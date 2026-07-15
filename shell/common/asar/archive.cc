// Copyright (c) 2014 GitHub, Inc.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#include "shell/common/asar/archive.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>
#if BUILDFLAG(ENABLE_EASR_V2)
#include <atomic>
#include <map>
#include <tuple>
#endif

#include "base/check.h"
#include "base/containers/span.h"
#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/json/json_reader.h"
#include "base/logging.h"
#include "base/notreached.h"
#include "base/pickle.h"
#include "base/strings/string_number_conversions.h"
#include "base/threading/thread_restrictions.h"
#include "base/values.h"
#include "electron/fuses.h"
#include "shell/common/asar/asar_util.h"
#if BUILDFLAG(ENABLE_EASR_V2)
#include "base/at_exit.h"
#include "base/no_destructor.h"
#include "base/synchronization/waitable_event.h"
#include "electron/easr_v2_key_material.h"
#include "shell/common/asar/easar_v2.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#endif
#include "shell/common/asar/scoped_temporary_file.h"

#if BUILDFLAG(IS_WIN)
#include <io.h>
#endif

namespace asar {

namespace {

#if BUILDFLAG(IS_WIN)
const char kSeparators[] = "\\/";
#else
const char kSeparators[] = "/";
#endif

#if BUILDFLAG(ENABLE_EASR_V2)
constexpr char kEncryptedAsarMagic[] = {'E', 'A', 'S', 'R'};
constexpr uint32_t kEncryptedAsarV1 = 1;
constexpr uint32_t kEncryptedAsarV2 = 2;
constexpr size_t kEncryptedAsarSuperblockSize = 200;

std::atomic<const EasrKeyProvider*> g_easr_key_provider{nullptr};
std::atomic<bool> g_require_encrypted_asar{false};
#endif

#if BUILDFLAG(ENABLE_EASR_V2)
constexpr size_t kMaxRetainedExternalFiles = 128;
constexpr uint64_t kMaxRetainedExternalBytes = 512ull * 1024 * 1024;
constexpr uint64_t kDefaultMaxSingleExternalFileBytes = 256ull * 1024 * 1024;

std::atomic<uint64_t> g_max_single_external_file_bytes{
    kDefaultMaxSingleExternalFileBytes};
std::atomic<bool> g_force_external_file_delete_failure_for_testing{false};

struct ExternalFileReservation {
  uint64_t bytes = 0;
  bool active = false;
};

struct ExternalFileKey {
  std::array<uint8_t, 32> easr_header_digest{};
  uint32_t easr_entry = 0;
  base::FilePath::StringType entry_extension;
  bool executable = false;
  uint64_t entry_size = 0;
  uint64_t packed_size = 0;

  bool operator<(const ExternalFileKey& other) const {
    return std::tie(easr_header_digest, easr_entry, entry_extension, executable,
                    entry_size, packed_size) <
           std::tie(other.easr_header_digest, other.easr_entry,
                    other.entry_extension, other.executable, other.entry_size,
                    other.packed_size);
  }
};

struct RetainedExternalFile {
  base::FilePath path;
  std::unique_ptr<ScopedTemporaryFile> file;
};

struct PendingRetainedExternalFile {
  PendingRetainedExternalFile()
      : ready(base::WaitableEvent::ResetPolicy::MANUAL,
              base::WaitableEvent::InitialState::NOT_SIGNALED) {}

  base::WaitableEvent ready;
  base::FilePath path;
  Archive::Error error = Archive::Error::kIo;
};

struct ExternalFileRegistry {
  base::Lock lock;
  bool accepting = true;
  size_t count = 0;
  uint64_t bytes = 0;
  std::map<ExternalFileKey, RetainedExternalFile> files;
  std::map<ExternalFileKey, std::shared_ptr<PendingRetainedExternalFile>>
      pending;
  std::map<ExternalFileKey, std::shared_ptr<PendingRetainedExternalFile>>
      failed;
  std::vector<std::unique_ptr<ScopedTemporaryFile>> quarantine;
};

void DrainExternalFiles(ExternalFileRegistry* registry, bool permanent) {
  std::vector<std::shared_ptr<PendingRetainedExternalFile>> pending;
  {
    base::AutoLock auto_lock(registry->lock);
    registry->accepting = false;
    pending.reserve(registry->pending.size());
    for (const auto& item : registry->pending)
      pending.push_back(item.second);
  }
  for (const auto& item : pending)
    item->ready.Wait();

  std::map<ExternalFileKey, RetainedExternalFile> files;
  std::map<ExternalFileKey, std::shared_ptr<PendingRetainedExternalFile>>
      failed;
  std::vector<std::unique_ptr<ScopedTemporaryFile>> quarantine;
  {
    base::AutoLock auto_lock(registry->lock);
    CHECK(registry->pending.empty());
    files.swap(registry->files);
    failed.swap(registry->failed);
    quarantine.swap(registry->quarantine);
    registry->count = 0;
    registry->bytes = 0;
    if (!permanent)
      registry->accepting = true;
  }
}

void CleanupExternalFiles(void* opaque) {
  DrainExternalFiles(static_cast<ExternalFileRegistry*>(opaque), true);
}

ExternalFileRegistry& GetExternalFileRegistry() {
  static base::NoDestructor<ExternalFileRegistry> registry;
  static const bool registered = [] {
    base::AtExitManager::RegisterCallback(&CleanupExternalFiles, &*registry);
    return true;
  }();
  (void)registered;
  return *registry;
}

enum class ExternalFileAcquireResult { kRejected, kRetained, kWait, kLoad };

ExternalFileAcquireResult AcquireExternalFile(
    const ExternalFileKey& key,
    uint64_t bytes,
    ExternalFileReservation* reservation,
    std::shared_ptr<PendingRetainedExternalFile>* pending,
    base::FilePath* retained_path) {
  const uint64_t max_single_file_bytes =
      g_max_single_external_file_bytes.load(std::memory_order_relaxed);
  if (!reservation || !pending || !retained_path ||
      bytes > max_single_file_bytes) {
    return ExternalFileAcquireResult::kRejected;
  }
  ExternalFileRegistry& registry = GetExternalFileRegistry();
  base::AutoLock auto_lock(registry.lock);
  if (!registry.accepting)
    return ExternalFileAcquireResult::kRejected;
  auto retained = registry.files.find(key);
  if (retained != registry.files.end()) {
    *retained_path = retained->second.path;
    return ExternalFileAcquireResult::kRetained;
  }
  auto loading = registry.pending.find(key);
  if (loading != registry.pending.end()) {
    *pending = loading->second;
    return ExternalFileAcquireResult::kWait;
  }
  auto failed = registry.failed.find(key);
  if (failed != registry.failed.end()) {
    *pending = failed->second;
    return ExternalFileAcquireResult::kWait;
  }
  if (registry.count >= kMaxRetainedExternalFiles ||
      bytes > kMaxRetainedExternalBytes ||
      registry.bytes > kMaxRetainedExternalBytes - bytes) {
    return ExternalFileAcquireResult::kRejected;
  }
  ++registry.count;
  registry.bytes += bytes;
  reservation->bytes = bytes;
  reservation->active = true;
  *pending = std::make_shared<PendingRetainedExternalFile>();
  registry.pending.emplace(key, *pending);
  return ExternalFileAcquireResult::kLoad;
}

void CompleteExternalFile(
    const ExternalFileKey& key,
    const std::shared_ptr<PendingRetainedExternalFile>& pending,
    ExternalFileReservation* reservation,
    std::unique_ptr<ScopedTemporaryFile> file,
    bool materialized,
    bool deleted,
    Archive::Error error) {
  CHECK(pending && reservation && reservation->active && file);
  ExternalFileRegistry& registry = GetExternalFileRegistry();
  {
    base::AutoLock auto_lock(registry.lock);
    auto found = registry.pending.find(key);
    CHECK(found != registry.pending.end());
    CHECK(found->second == pending);
    if (materialized) {
      pending->path = file->path();
      pending->error = Archive::Error::kNone;
      registry.files.emplace(
          key, RetainedExternalFile{pending->path, std::move(file)});
    } else if (deleted) {
      CHECK_GT(registry.count, 0u);
      CHECK_GE(registry.bytes, reservation->bytes);
      --registry.count;
      registry.bytes -= reservation->bytes;
      pending->error = error;
    } else {
      pending->error = error;
      const bool inserted = registry.failed.emplace(key, pending).second;
      CHECK(inserted);
      registry.quarantine.push_back(std::move(file));
    }
    reservation->active = false;
    registry.pending.erase(found);
  }
  pending->ready.Signal();
}
#endif  // BUILDFLAG(ENABLE_EASR_V2)

const base::Value::Dict* GetNodeFromPath(std::string path,
                                         const base::Value::Dict& root);

#if BUILDFLAG(ENABLE_EASR_V2)
uint32_t ReadUInt32LE(const char* data) {
  return static_cast<uint32_t>(static_cast<uint8_t>(data[0])) |
         (static_cast<uint32_t>(static_cast<uint8_t>(data[1])) << 8) |
         (static_cast<uint32_t>(static_cast<uint8_t>(data[2])) << 16) |
         (static_cast<uint32_t>(static_cast<uint8_t>(data[3])) << 24);
}
#endif

size_t ReadUpTo(base::File* file, uint64_t offset, base::span<char> buffer) {
  constexpr uint64_t kMaxFileOffset =
      static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
  if (buffer.size() > static_cast<size_t>(std::numeric_limits<int>::max()) ||
      offset > kMaxFileOffset || buffer.size() > kMaxFileOffset - offset) {
    return 0;
  }
  base::ThreadRestrictions::ScopedAllowIO allow_io;
  size_t read = 0;
  while (read < buffer.size()) {
    const int result =
        file->Read(static_cast<int64_t>(offset + read), buffer.data() + read,
                   static_cast<int>(buffer.size() - read));
    if (result <= 0)
      return read;
    read += static_cast<size_t>(result);
  }
  return read;
}

bool ReadExact(base::File* file, uint64_t offset, base::span<char> buffer) {
  return ReadUpTo(file, offset, buffer) == buffer.size();
}

#if BUILDFLAG(ENABLE_EASR_V2)
void CleanseBytes(base::span<char> bytes) {
  if (bytes.empty())
    return;
  OPENSSL_cleanse(bytes.data(), bytes.size());
}

void CleanseAndClear(std::string* value) {
  if (!value)
    return;
  CleanseBytes(base::make_span(*value));
  value->clear();
}
#endif  // BUILDFLAG(ENABLE_EASR_V2)

void ResetFileInfo(Archive::FileInfo* info) {
  info->unpacked = false;
  info->executable = false;
  info->size = 0;
#if BUILDFLAG(ENABLE_EASR_V2)
  info->packed_size = 0;
#endif
  info->offset = 0;
#if BUILDFLAG(ENABLE_EASR_V2)
  info->easr_entry = std::numeric_limits<uint32_t>::max();
#endif
  info->integrity.reset();
}

// Gets the "files" from "dir".
const base::Value::Dict* GetFilesNode(const base::Value::Dict& root,
                                      const base::Value::Dict& dir) {
  // Test for symbol linked directory.
  const std::string* link = dir.FindString("link");
  if (link != nullptr) {
    const base::Value::Dict* linked_node = GetNodeFromPath(*link, root);
    if (!linked_node)
      return nullptr;
    return linked_node->FindDict("files");
  }

  return dir.FindDict("files");
}

// Gets sub-file "name" from "dir".
const base::Value::Dict* GetChildNode(const base::Value::Dict& root,
                                      const std::string& name,
                                      const base::Value::Dict& dir) {
  if (name.empty())
    return &root;

  const base::Value::Dict* files = GetFilesNode(root, dir);
  return files ? files->FindDict(name) : nullptr;
}

// Gets the node of "path" from "root".
const base::Value::Dict* GetNodeFromPath(std::string path,
                                         const base::Value::Dict& root) {
  if (path.empty())
    return &root;

  const base::Value::Dict* dir = &root;
  for (size_t delimiter_position = path.find_first_of(kSeparators);
       delimiter_position != std::string::npos;
       delimiter_position = path.find_first_of(kSeparators)) {
    const base::Value::Dict* child =
        GetChildNode(root, path.substr(0, delimiter_position), *dir);
    if (!child)
      return nullptr;

    dir = child;
    path.erase(0, delimiter_position + 1);
  }

  return GetChildNode(root, path, *dir);
}

bool FillFileInfoWithNode(Archive::FileInfo* info,
                          uint32_t header_size,
                          bool load_integrity,
                          const base::Value::Dict* node) {
  ResetFileInfo(info);

  if (absl::optional<int> size = node->FindInt("size")) {
    if (*size < 0)
      return false;
    info->size = static_cast<uint32_t>(*size);
  } else {
    return false;
  }

  if (absl::optional<bool> unpacked = node->FindBool("unpacked")) {
    info->unpacked = *unpacked;
    if (info->unpacked) {
      return true;
    }
  }

  const std::string* offset = node->FindString("offset");
  if (offset &&
      base::StringToUint64(base::StringPiece(*offset), &info->offset)) {
    info->offset += header_size;
  } else {
    return false;
  }

  if (absl::optional<bool> executable = node->FindBool("executable")) {
    info->executable = *executable;
  }

#if BUILDFLAG(IS_MAC)
  if (load_integrity &&
      electron::fuses::IsEmbeddedAsarIntegrityValidationEnabled()) {
    if (const base::Value::Dict* integrity = node->FindDict("integrity")) {
      const std::string* algorithm = integrity->FindString("algorithm");
      const std::string* hash = integrity->FindString("hash");
      absl::optional<int> block_size = integrity->FindInt("blockSize");
      const base::Value::List* blocks = integrity->FindList("blocks");

      if (algorithm && hash && block_size && block_size > 0 && blocks) {
        IntegrityPayload integrity_payload;
        integrity_payload.hash = *hash;
        integrity_payload.block_size =
            static_cast<uint32_t>(block_size.value());
        for (auto& value : *blocks) {
          if (const std::string* block = value.GetIfString()) {
            integrity_payload.blocks.push_back(*block);
          } else {
            LOG(FATAL)
                << "Invalid block integrity value for file in ASAR archive";
          }
        }
        if (*algorithm == "SHA256") {
          integrity_payload.algorithm = HashAlgorithm::SHA256;
          info->integrity = std::move(integrity_payload);
        }
      }
    }

    if (!info->integrity.has_value()) {
      LOG(FATAL) << "Failed to read integrity for file in ASAR archive";
      return false;
    }
  }
#endif

  return true;
}

}  // namespace

#if BUILDFLAG(ENABLE_EASR_V2)
struct Archive::PendingExternalFile {
  PendingExternalFile()
      : ready(base::WaitableEvent::ResetPolicy::MANUAL,
              base::WaitableEvent::InitialState::NOT_SIGNALED) {}

  base::WaitableEvent ready;
  base::FilePath path;
  Error error = Error::kIo;
};

uint64_t EasrKeyProvider::GetMinimumEpoch(
    const EasrKeyId& data_key_id,
    const EasrKeyId& signing_key_id) const {
  return 0;
}

void SetEasrKeyProviderForProcess(const EasrKeyProvider* provider) {
  g_easr_key_provider.store(provider, std::memory_order_release);
}

void SetRequireEncryptedAsarForProcess(bool require_encrypted) {
  g_require_encrypted_asar.store(require_encrypted, std::memory_order_release);
}

void InstallEasrBuildPolicy() {
  SetEasrKeyProviderForProcess(electron::easr_v2_build::GetKeyProvider());
  SetRequireEncryptedAsarForProcess(BUILDFLAG(REQUIRE_ENCRYPTED_ASAR));
}
#endif

#if BUILDFLAG(ENABLE_EASR_V2)
size_t GetRetainedExternalFileCountForTesting() {
  ExternalFileRegistry& registry = GetExternalFileRegistry();
  base::AutoLock auto_lock(registry.lock);
  return registry.count;
}

uint64_t GetRetainedExternalFileBytesForTesting() {
  ExternalFileRegistry& registry = GetExternalFileRegistry();
  base::AutoLock auto_lock(registry.lock);
  return registry.bytes;
}

void ClearRetainedExternalFilesForTesting() {
  DrainExternalFiles(&GetExternalFileRegistry(), false);
}

void SetEasrSingleFileMaterializationLimitForTesting(uint64_t byte_limit) {
  g_max_single_external_file_bytes.store(byte_limit, std::memory_order_relaxed);
}

void ResetEasrSingleFileMaterializationLimitForTesting() {
  SetEasrSingleFileMaterializationLimitForTesting(
      kDefaultMaxSingleExternalFileBytes);
}

void SetEasrExternalFileDeleteFailureForTesting(bool fail) {
  g_force_external_file_delete_failure_for_testing.store(
      fail, std::memory_order_relaxed);
}
#endif  // BUILDFLAG(ENABLE_EASR_V2)

IntegrityPayload::IntegrityPayload()
    : algorithm(HashAlgorithm::NONE), block_size(0) {}
IntegrityPayload::~IntegrityPayload() = default;
IntegrityPayload::IntegrityPayload(const IntegrityPayload& other) = default;

Archive::FileInfo::FileInfo()
    : unpacked(false),
      executable(false),
      size(0),
#if BUILDFLAG(ENABLE_EASR_V2)
      packed_size(0),
#endif
      offset(0)
#if BUILDFLAG(ENABLE_EASR_V2)
      ,
      easr_entry(std::numeric_limits<uint32_t>::max())
#endif
{
}
Archive::FileInfo::~FileInfo() = default;
Archive::FileInfo::FileInfo(const FileInfo& other) = default;
Archive::FileInfo& Archive::FileInfo::operator=(const FileInfo& other) =
    default;

Archive::Archive(const base::FilePath& path)
    : initialized_(false), path_(path), file_(base::File::FILE_OK) {
  base::ThreadRestrictions::ScopedAllowIO allow_io;
  file_.Initialize(path_, base::File::FLAG_OPEN | base::File::FLAG_READ);
#if BUILDFLAG(IS_WIN)
  fd_ = _open_osfhandle(reinterpret_cast<intptr_t>(file_.GetPlatformFile()), 0);
#elif BUILDFLAG(IS_POSIX)
  fd_ = file_.GetPlatformFile();
#endif
}

Archive::~Archive() {
#if BUILDFLAG(IS_WIN)
  if (fd_ != -1) {
    _close(fd_);
    // Don't close the handle since we already closed the fd.
    file_.TakePlatformFile();
  }
#endif
  base::ThreadRestrictions::ScopedAllowIO allow_io;
  file_.Close();
}

bool Archive::Init() {
  // Should only be initialized once
  CHECK(!initialized_);
  initialized_ = true;

  if (!file_.IsValid()) {
    init_error_ = file_.error_details() == base::File::FILE_ERROR_NOT_FOUND
                      ? Error::kNotFound
                      : Error::kIo;
    if (file_.error_details() != base::File::FILE_ERROR_NOT_FOUND) {
      LOG(WARNING) << "Opening " << path_.value() << ": "
                   << base::File::ErrorToString(file_.error_details());
    }
    return false;
  }

#if BUILDFLAG(ENABLE_EASR_V2)
  std::array<char, kEncryptedAsarSuperblockSize> prefix{};
  const size_t prefix_size = ReadUpTo(&file_, 0, base::make_span(prefix));
  if (prefix_size >= sizeof(kEncryptedAsarMagic) &&
      memcmp(prefix.data(), kEncryptedAsarMagic, sizeof(kEncryptedAsarMagic)) ==
          0) {
    if (prefix_size < 8) {
      init_error_ = Error::kMalformedSuperblock;
      return false;
    }
    const uint32_t version = ReadUInt32LE(prefix.data() + 4);
    if (version == kEncryptedAsarV1) {
      init_error_ = Error::kLegacyVersion;
      LOG(ERROR) << "Legacy EASR v1 is disabled: " << path_.value();
      return false;
    }
    if (version == kEncryptedAsarV2) {
      return InitEncryptedV2(
          base::as_bytes(base::make_span(prefix).first(prefix_size)));
    }
    init_error_ = Error::kUnsupportedVersion;
    LOG(ERROR) << "Unsupported EASR version in " << path_.value();
    return false;
  }

  if (g_require_encrypted_asar.load(std::memory_order_acquire)) {
    init_error_ = Error::kEncryptedArchiveRequired;
    return false;
  }

  if (prefix_size < 8) {
    init_error_ = Error::kInvalidArchive;
    PLOG(ERROR) << "Failed to read header size from " << path_.value();
    return false;
  }
  std::array<char, 8> standard_prefix{};
  std::copy_n(prefix.begin(), standard_prefix.size(), standard_prefix.begin());
  return InitStandard(&standard_prefix);
#else
  return InitStandard();
#endif  // BUILDFLAG(ENABLE_EASR_V2)
}

bool Archive::InitStandard(const std::array<char, 8>* prefix) {
  std::vector<char> buf;

  if (prefix) {
    buf.assign(prefix->begin(), prefix->end());
  } else {
    buf.resize(8);
    if (!ReadExact(&file_, 0, base::make_span(buf))) {
      init_error_ = Error::kInvalidArchive;
      PLOG(ERROR) << "Failed to read header size from " << path_.value();
      return false;
    }
  }

  uint32_t size;
  if (!base::PickleIterator(base::Pickle(buf.data(), buf.size()))
           .ReadUInt32(&size)) {
    init_error_ = Error::kInvalidArchive;
    LOG(ERROR) << "Failed to parse header size from " << path_.value();
    return false;
  }

  if (size > static_cast<uint32_t>(std::numeric_limits<int>::max())) {
    init_error_ = Error::kInvalidArchive;
    LOG(ERROR) << "ASAR header is too large in " << path_.value();
    return false;
  }

  buf.resize(size);
  if (!ReadExact(&file_, 8, base::make_span(buf))) {
    init_error_ = Error::kInvalidArchive;
    PLOG(ERROR) << "Failed to read header from " << path_.value();
    return false;
  }

  std::string header;
  if (!base::PickleIterator(base::Pickle(buf.data(), buf.size()))
           .ReadString(&header)) {
    init_error_ = Error::kInvalidArchive;
    LOG(ERROR) << "Failed to parse header from " << path_.value();
    return false;
  }

#if BUILDFLAG(IS_MAC)
  // Validate header signature if required and possible
  if (electron::fuses::IsEmbeddedAsarIntegrityValidationEnabled() &&
      RelativePath().has_value()) {
    absl::optional<IntegrityPayload> integrity = HeaderIntegrity();
    if (!integrity.has_value()) {
      LOG(FATAL) << "Failed to get integrity for validatable asar archive: "
                 << RelativePath().value();
      return false;
    }

    // Currently we only support the sha256 algorithm, we can add support for
    // more below ensure we read them in preference order from most secure to
    // least
    if (integrity.value().algorithm != HashAlgorithm::NONE) {
      ValidateIntegrityOrDie(header.c_str(), header.length(),
                             integrity.value());
    } else {
      LOG(FATAL) << "No eligible hash for validatable asar archive: "
                 << RelativePath().value();
    }

    header_validated_ = true;
  }
#endif

  absl::optional<base::Value> value = base::JSONReader::Read(header);
  if (!value || !value->is_dict()) {
    init_error_ = Error::kInvalidArchive;
    LOG(ERROR) << "Failed to parse header";
    return false;
  }

  header_size_ = 8 + size;
  header_ = std::move(value->GetDict());
  init_error_ = Error::kNone;
  return true;
}

#if BUILDFLAG(ENABLE_EASR_V2)
bool Archive::InitEncryptedV2(base::span<const uint8_t> superblock) {
  const EasrKeyProvider* provider =
      g_easr_key_provider.load(std::memory_order_acquire);
  easr_v2_ =
      EasrV2Reader::Create(&file_, path_, provider, superblock, &init_error_);
  encrypted_ = easr_v2_ != nullptr;
#if BUILDFLAG(IS_MAC)
  if (encrypted_ &&
      electron::fuses::IsEmbeddedAsarIntegrityValidationEnabled() &&
      RelativePath().has_value()) {
    absl::optional<IntegrityPayload> integrity = HeaderIntegrity();
    if (!integrity.has_value()) {
      LOG(FATAL) << "Failed to get integrity for validatable EASR archive: "
                 << RelativePath().value();
      return false;
    }
    ValidateIntegrityDigestOrDie(easr_v2_->header_digest(), *integrity);
    header_validated_ = true;
  }
#endif
  return encrypted_;
}
#endif  // BUILDFLAG(ENABLE_EASR_V2)

#if !BUILDFLAG(IS_MAC)
absl::optional<IntegrityPayload> Archive::HeaderIntegrity() const {
  return absl::nullopt;
}

absl::optional<base::FilePath> Archive::RelativePath() const {
  return absl::nullopt;
}
#endif

bool Archive::GetFileInfo(const base::FilePath& path, FileInfo* info) const {
#if BUILDFLAG(ENABLE_EASR_V2)
  if (easr_v2_)
    return easr_v2_->GetFileInfo(path, info);
#endif
  if (!header_)
    return false;

  const base::Value::Dict* node =
      GetNodeFromPath(path.AsUTF8Unsafe(), *header_);
  if (!node)
    return false;

  const std::string* link = node->FindString("link");
  if (link)
    return GetFileInfo(base::FilePath::FromUTF8Unsafe(*link), info);

  return FillFileInfoWithNode(info, header_size_, header_validated_, node);
}

bool Archive::Stat(const base::FilePath& path, Stats* stats) const {
#if BUILDFLAG(ENABLE_EASR_V2)
  if (easr_v2_)
    return easr_v2_->Stat(path, stats);
#endif
  if (!header_)
    return false;

  const base::Value::Dict* node =
      GetNodeFromPath(path.AsUTF8Unsafe(), *header_);
  if (!node)
    return false;

  if (node->Find("link")) {
    stats->is_file = false;
    stats->is_link = true;
    return true;
  }

  if (node->Find("files")) {
    stats->is_file = false;
    stats->is_directory = true;
    return true;
  }

  return FillFileInfoWithNode(stats, header_size_, header_validated_, node);
}

bool Archive::Readdir(const base::FilePath& path,
                      std::vector<base::FilePath>* files) const {
#if BUILDFLAG(ENABLE_EASR_V2)
  if (easr_v2_)
    return easr_v2_->Readdir(path, files);
#endif
  if (!header_)
    return false;

  const base::Value::Dict* node =
      GetNodeFromPath(path.AsUTF8Unsafe(), *header_);
  if (!node)
    return false;

  const base::Value::Dict* files_node = GetFilesNode(*header_, *node);
  if (!files_node)
    return false;

  for (const auto iter : *files_node)
    files->push_back(base::FilePath::FromUTF8Unsafe(iter.first));
  return true;
}

bool Archive::Realpath(const base::FilePath& path,
                       base::FilePath* realpath) const {
#if BUILDFLAG(ENABLE_EASR_V2)
  if (easr_v2_)
    return easr_v2_->Realpath(path, realpath);
#endif
  if (!header_)
    return false;

  const base::Value::Dict* node =
      GetNodeFromPath(path.AsUTF8Unsafe(), *header_);
  if (!node)
    return false;

  const std::string* link = node->FindString("link");
  if (link) {
    *realpath = base::FilePath::FromUTF8Unsafe(*link);
    return true;
  }

  *realpath = path;
  return true;
}

bool Archive::ReadFile(const base::FilePath& path,
                       std::string* contents,
                       Error* error) {
  return ReadFile(path, contents, std::numeric_limits<uint64_t>::max(), error);
}

bool Archive::ReadFile(const base::FilePath& path,
                       std::string* contents,
                       uint64_t max_size,
                       Error* error) {
  if (!contents) {
    if (error)
      *error = Error::kInvalidRange;
    return false;
  }
#if BUILDFLAG(ENABLE_EASR_V2)
  if (easr_v2_)
    CleanseAndClear(contents);
  else
#endif
    contents->clear();

  FileInfo info;
  if (!GetFileInfo(path, &info)) {
    if (error)
      *error = Error::kNotFound;
    return false;
  }
  if (info.size > max_size) {
    if (error)
      *error = Error::kResourceExhausted;
    return false;
  }

#if BUILDFLAG(ENABLE_EASR_V2)
  if (easr_v2_) {
    if (info.unpacked) {
      return easr_v2_->ReadFile(&file_, path, contents, error);
    }
    if (info.size > std::numeric_limits<size_t>::max()) {
      if (error)
        *error = Error::kInvalidRange;
      return false;
    }
    return ReadRange(info, 0, static_cast<size_t>(info.size), contents, error);
  }
#endif

  if (info.unpacked) {
    base::FilePath real_path;
    Error copy_error = Error::kNone;
    if (!CopyFileOut(path, &real_path, &copy_error)) {
      if (error)
        *error = copy_error;
      return false;
    }
    const bool result = base::ReadFileToString(real_path, contents);
    if (!result)
      contents->clear();
    if (error)
      *error = result ? Error::kNone : Error::kIo;
    return result;
  }

  if (info.size > std::numeric_limits<size_t>::max()) {
    if (error)
      *error = Error::kInvalidRange;
    return false;
  }
  return ReadRange(info, 0, static_cast<size_t>(info.size), contents, error);
}

bool Archive::ReadRange(const FileInfo& info,
                        uint64_t offset,
                        size_t size,
                        std::string* contents,
                        Error* error) {
  if (!contents) {
    if (error)
      *error = Error::kInvalidRange;
    return false;
  }
#if BUILDFLAG(ENABLE_EASR_V2)
  if (easr_v2_)
    CleanseAndClear(contents);
  else
#endif
    contents->clear();
  bool exceeds_standard_read_limit =
      size > static_cast<size_t>(std::numeric_limits<int>::max());
#if BUILDFLAG(ENABLE_EASR_V2)
  exceeds_standard_read_limit &= !easr_v2_;
#endif
  if (offset > info.size || size > info.size - offset ||
      size > contents->max_size() || exceeds_standard_read_limit) {
    if (error)
      *error = Error::kInvalidRange;
    return false;
  }
  contents->resize(size);
  if (!ReadRange(info, offset, base::make_span(*contents), error)) {
#if BUILDFLAG(ENABLE_EASR_V2)
    if (easr_v2_)
      CleanseAndClear(contents);
    else
#endif
      contents->clear();
    return false;
  }
  return true;
}

bool Archive::ReadRange(const FileInfo& info,
                        uint64_t offset,
                        base::span<char> contents,
                        Error* error) {
#if BUILDFLAG(ENABLE_EASR_V2)
  if (easr_v2_)
    return easr_v2_->ReadRange(&file_, info, offset, contents, error);
#endif

  constexpr uint64_t kMaxFileOffset =
      static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
  if (offset > info.size || contents.size() > info.size - offset ||
      contents.size() > static_cast<size_t>(std::numeric_limits<int>::max()) ||
      info.offset > kMaxFileOffset || offset > kMaxFileOffset - info.offset) {
    if (error)
      *error = Error::kInvalidRange;
    return false;
  }

  if (contents.empty()) {
    if (error)
      *error = Error::kNone;
    return true;
  }

  if (!ReadExact(&file_, info.offset + offset, contents)) {
    if (error)
      *error = Error::kIo;
    return false;
  }
  if (info.integrity.has_value() && offset == 0 &&
      contents.size() == info.size) {
    ValidateIntegrityOrDie(contents.data(), contents.size(),
                           info.integrity.value());
  }
  if (error)
    *error = Error::kNone;
  return true;
}

bool Archive::CopyFileOut(const base::FilePath& path,
                          base::FilePath* out,
                          Error* error) {
#if BUILDFLAG(ENABLE_EASR_V2)
  if (!out || (!header_ && !easr_v2_)) {
#else
  if (!out || !header_) {
#endif
    if (error)
      *error = Error::kInvalidArchive;
    return false;
  }

#if BUILDFLAG(ENABLE_EASR_V2)
  if (!easr_v2_) {
#endif
    // Keep ordinary ASAR on its historical materialization path. It must not
    // inherit EASR's cross-Archive deduplication or admission limits; only the
    // ownership of each returned bare path is extended to process lifetime.
    base::AutoLock auto_lock(external_files_lock_);
    auto cached = external_files_.find(path.value());
    if (cached != external_files_.end()) {
      *out = cached->second;
      if (error)
        *error = Error::kNone;
      return true;
    }

    FileInfo info;
    if (!GetFileInfo(path, &info)) {
      if (error)
        *error = Error::kNotFound;
      return false;
    }

    if (info.unpacked) {
      *out = path_.AddExtension(FILE_PATH_LITERAL("unpacked")).Append(path);
      if (error)
        *error = Error::kNone;
      return true;
    }

    auto temp_file = std::make_unique<ScopedTemporaryFile>();
    const base::FilePath::StringType ext = path.Extension();
    if (!temp_file->InitFromFile(&file_, ext, info.offset, info.size,
                                 info.integrity)) {
      if (error)
        *error = Error::kIo;
      return false;
    }

#if BUILDFLAG(IS_POSIX)
    if (info.executable)
      base::SetPosixFilePermissions(temp_file->path(), 0755);
#endif

    *out = temp_file->path();
    external_files_[path.value()] = *out;
    RetainOrdinaryAsarTemporaryFile(std::move(temp_file));
    if (error)
      *error = Error::kNone;
    return true;
#if BUILDFLAG(ENABLE_EASR_V2)
  }

  FileInfo info;
  if (!GetFileInfo(path, &info)) {
    if (error)
      *error = Error::kNotFound;
    return false;
  }
  const EasrExternalFileKey local_key{info.easr_entry, path.Extension()};

  std::shared_ptr<PendingExternalFile> pending;
  bool is_loader = false;
  {
    base::AutoLock auto_lock(external_files_lock_);
    auto cached = easr_external_files_.find(local_key);
    if (cached != easr_external_files_.end()) {
      *out = cached->second;
      if (error)
        *error = Error::kNone;
      return true;
    }
    auto loading = pending_external_files_.find(local_key);
    if (loading != pending_external_files_.end()) {
      pending = loading->second;
    } else {
      // A returned path may be retained indefinitely by dlopen or a child
      // process. Without a lease token, evicting it would be a use-after-
      // delete. Refuse new materializations at the hard cap instead.
      if (easr_external_files_.size() + pending_external_files_.size() >=
          kMaxEasrExternalFiles) {
        if (error)
          *error = Error::kResourceExhausted;
        return false;
      }
      pending = std::make_shared<PendingExternalFile>();
      pending_external_files_.emplace(local_key, pending);
      is_loader = true;
    }
  }

  if (!is_loader) {
    pending->ready.Wait();
    if (error)
      *error = pending->error;
    if (pending->error == Error::kNone)
      *out = pending->path;
    return pending->error == Error::kNone;
  }

  auto publish_local_result = [&](Error result_error,
                                  const base::FilePath& result_path) {
    {
      base::AutoLock auto_lock(external_files_lock_);
      pending->error = result_error;
      pending->path = result_path;
      if (result_error == Error::kNone)
        easr_external_files_[local_key] = result_path;
      pending_external_files_.erase(local_key);
    }
    pending->ready.Signal();
    if (error)
      *error = result_error;
    if (result_error == Error::kNone)
      *out = result_path;
    return result_error == Error::kNone;
  };

  ExternalFileKey external_key;
  external_key.easr_header_digest = easr_v2_->header_digest();
  external_key.easr_entry = info.easr_entry;
  external_key.entry_extension = local_key.entry_extension;
  external_key.executable = info.executable;
  external_key.entry_size = info.size;
  external_key.packed_size = info.packed_size;

  if (!PrepareTemporaryFileDirectory())
    return publish_local_result(Error::kIo, base::FilePath());

  ExternalFileReservation reservation;
  std::shared_ptr<PendingRetainedExternalFile> global_pending;
  base::FilePath retained_path;
  const ExternalFileAcquireResult acquire = AcquireExternalFile(
      external_key, info.size, &reservation, &global_pending, &retained_path);
  if (acquire == ExternalFileAcquireResult::kRejected) {
    return publish_local_result(Error::kResourceExhausted, base::FilePath());
  }
  if (acquire == ExternalFileAcquireResult::kRetained)
    return publish_local_result(Error::kNone, retained_path);
  if (acquire == ExternalFileAcquireResult::kWait) {
    global_pending->ready.Wait();
    return publish_local_result(global_pending->error, global_pending->path);
  }

  auto temp_file = std::make_unique<ScopedTemporaryFile>();
  Error materialize_error = Error::kIo;
  bool materialized = false;
  base::File destination;
  if (temp_file->InitForWrite(local_key.entry_extension, &destination)) {
    materialized =
        easr_v2_->CopyFileTo(&file_, info, &destination, &materialize_error);
#if BUILDFLAG(IS_POSIX)
    if (materialized && info.executable &&
        !base::SetPosixFilePermissions(temp_file->path(), 0700)) {
      materialized = false;
      materialize_error = Error::kIo;
    }
#endif
    if (!materialized) {
      destination.SetLength(0);
#if BUILDFLAG(IS_WIN)
      destination.DeleteOnClose(true);
#endif
    }
    destination.Close();
  }

  const bool deleted = !materialized &&
                       !g_force_external_file_delete_failure_for_testing.load(
                           std::memory_order_relaxed) &&
                       temp_file->DeleteNow();
  CompleteExternalFile(external_key, global_pending, &reservation,
                       std::move(temp_file), materialized, deleted,
                       materialize_error);
  return publish_local_result(global_pending->error, global_pending->path);
#endif  // BUILDFLAG(ENABLE_EASR_V2)
}

int Archive::GetUnsafeFD() const {
#if BUILDFLAG(ENABLE_EASR_V2)
  if (encrypted_)
    return -1;
#endif
  return fd_;
}

#if BUILDFLAG(ENABLE_EASR_V2)
void Archive::SetEasrChunkCacheLimitsForTesting(size_t byte_limit,
                                                size_t chunk_limit) {
  if (easr_v2_)
    easr_v2_->SetChunkCacheLimitsForTesting(byte_limit, chunk_limit);
}

Archive::EasrChunkCacheStats Archive::GetEasrChunkCacheStatsForTesting() const {
  return easr_v2_ ? easr_v2_->GetChunkCacheStatsForTesting()
                  : EasrChunkCacheStats{};
}

void Archive::ClearEasrChunkCacheForTesting() {
  if (easr_v2_)
    easr_v2_->ClearChunkCacheForTesting();
}

size_t Archive::GetEasrExternalFileSlotCountForTesting() {
  base::AutoLock auto_lock(external_files_lock_);
  return easr_external_files_.size() + pending_external_files_.size();
}
#endif  // BUILDFLAG(ENABLE_EASR_V2)

const char* ArchiveErrorName(Archive::Error error) {
  switch (error) {
    case Archive::Error::kNone:
      return "";
    case Archive::Error::kNotFound:
      return "ERR_ASAR_NOT_FOUND";
    case Archive::Error::kIo:
      return "ERR_ASAR_IO";
    case Archive::Error::kInvalidArchive:
      return "ERR_ASAR_INVALID_ARCHIVE";
#if BUILDFLAG(ENABLE_EASR_V2)
    case Archive::Error::kEncryptedArchiveRequired:
      return "ERR_EASR_REQUIRED";
    case Archive::Error::kLegacyVersion:
      return "ERR_EASR_LEGACY_VERSION";
    case Archive::Error::kUnsupportedVersion:
      return "ERR_EASR_UNSUPPORTED_VERSION";
    case Archive::Error::kMalformedSuperblock:
      return "ERR_EASR_MALFORMED_SUPERBLOCK";
    case Archive::Error::kUnknownSigningKey:
      return "ERR_EASR_UNKNOWN_SIGNING_KEY";
    case Archive::Error::kSigningKeyIdMismatch:
      return "ERR_EASR_SIGNING_KEY_ID_MISMATCH";
    case Archive::Error::kInvalidSignature:
      return "ERR_EASR_INVALID_SIGNATURE";
    case Archive::Error::kRollback:
      return "ERR_EASR_ROLLBACK";
    case Archive::Error::kArchiveSize:
      return "ERR_EASR_ARCHIVE_SIZE";
    case Archive::Error::kIndexHash:
      return "ERR_EASR_INDEX_HASH";
    case Archive::Error::kMalformedIndex:
      return "ERR_EASR_MALFORMED_INDEX";
    case Archive::Error::kUnknownDataKey:
      return "ERR_EASR_UNKNOWN_DATA_KEY";
    case Archive::Error::kDataKeyIdMismatch:
      return "ERR_EASR_DATA_KEY_ID_MISMATCH";
    case Archive::Error::kAuthentication:
      return "ERR_EASR_AUTHENTICATION";
    case Archive::Error::kDecompression:
      return "ERR_EASR_DECOMPRESSION";
    case Archive::Error::kUnpackedAuthentication:
      return "ERR_EASR_UNPACKED_AUTHENTICATION";
#endif
    case Archive::Error::kInvalidRange:
      return "ERR_ASAR_INVALID_RANGE";
    case Archive::Error::kResourceExhausted:
      return "ERR_ASAR_RESOURCE_EXHAUSTED";
  }
  NOTREACHED();
  return "ERR_ASAR_UNKNOWN";
}

}  // namespace asar
