// Copyright (c) 2026 Electron authors.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#include "shell/common/asar/easar_v2.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <limits>
#include <list>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/containers/span.h"
#include "base/files/file.h"
#include "base/i18n/icu_string_conversions.h"
#include "base/strings/string_util.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread_restrictions.h"
#include "build/build_config.h"
#include "crypto/hkdf.h"
#include "crypto/secure_hash.h"
#include "crypto/sha2.h"
#include "third_party/boringssl/src/include/openssl/aead.h"
#include "third_party/boringssl/src/include/openssl/base.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/icu/source/common/unicode/locid.h"
#include "third_party/icu/source/common/unicode/normalizer2.h"
#include "third_party/icu/source/common/unicode/unistr.h"
#include "third_party/zlib/zlib.h"

#if BUILDFLAG(IS_POSIX)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#if BUILDFLAG(IS_WIN)
#include <windows.h>
#endif

namespace asar {

namespace {

constexpr size_t kSuperblockSize = 200;
constexpr size_t kSignatureOffset = 136;
constexpr size_t kKeyIdSize = 16;
constexpr size_t kArchiveIdSize = 32;
constexpr size_t kIndexHashSize = 32;
constexpr size_t kTagSize = 16;
constexpr size_t kDigestSize = 32;
constexpr size_t kIndexHeaderSize = 8;
constexpr size_t kMaxIndexSize = 16 * 1024 * 1024;
constexpr uint32_t kMaxEntryCount = 262144;
constexpr uint32_t kMaxChunkCount = 262144;
constexpr size_t kMaxPathBytes = 4096;
constexpr size_t kMaxPathSegmentBytes = 255;
constexpr size_t kMaxSymlinkDepth = 40;
// Prefix coding can otherwise expand a tiny authenticated index into an
// impractically large set of repeated paths. This bound is independent of the
// input allocation and comfortably exceeds normal desktop archives.
constexpr size_t kMaxExpandedPathBytes = 64 * 1024 * 1024;
constexpr uint64_t kMaxSafeInteger = 9007199254740991ULL;
constexpr size_t kDefaultChunkCacheBytes = 8 * 1024 * 1024;
constexpr size_t kDefaultChunkCacheEntries = 256;
constexpr size_t kGlobalChunkCacheBytes = 32 * 1024 * 1024;

std::atomic<size_t> g_global_chunk_cache_bytes{0};
std::atomic<size_t> g_global_chunk_cache_byte_limit{kGlobalChunkCacheBytes};

bool TryReserveGlobalChunkBytes(size_t bytes) {
  if (bytes == 0)
    return true;
  const size_t limit =
      g_global_chunk_cache_byte_limit.load(std::memory_order_acquire);
  size_t current = g_global_chunk_cache_bytes.load(std::memory_order_relaxed);
  while (current <= limit && bytes <= limit - current) {
    if (g_global_chunk_cache_bytes.compare_exchange_weak(
            current, current + bytes, std::memory_order_acq_rel,
            std::memory_order_relaxed)) {
      return true;
    }
  }
  return false;
}

void ReleaseGlobalChunkBytes(size_t bytes) {
  if (bytes)
    g_global_chunk_cache_bytes.fetch_sub(bytes, std::memory_order_acq_rel);
}

constexpr uint8_t kEntryDirectory = 0;
constexpr uint8_t kEntrySymlink = 2;
constexpr uint8_t kEntryKindMask = 3;
constexpr uint8_t kEntryExecutable = 4;
constexpr uint8_t kEntryUnpacked = 8;
constexpr uint8_t kEntryKnownFlags =
    kEntryKindMask | kEntryExecutable | kEntryUnpacked;
constexpr uint8_t kCodecRaw = 0;
constexpr uint8_t kCodecDeflateRaw = 1;

constexpr char kEasrMagic[] = "EASR";
constexpr char kIndexMagic[] = "EIDX";
constexpr char kSignatureDomain[] = "EASR-v2-superblock-signature\0";
constexpr char kDataKeyIdDomain[] = "EASR-v2-data-key-id\0";
constexpr char kSigningKeyIdDomain[] = "EASR-v2-signing-key-id\0";
constexpr char kDataKeyDomain[] = "EASR-v2-data-key\0";
constexpr char kAadDomain[] = "EASR2-DATA-AAD";
constexpr std::array<uint8_t, 12> kEd25519SpkiPrefix = {
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};

using Error = Archive::Error;

void SetError(Error* error, Error value) {
  if (error)
    *error = value;
}

class ScopedCleanse {
 public:
  explicit ScopedCleanse(base::span<uint8_t> bytes) : bytes_(bytes) {}
  ScopedCleanse(const ScopedCleanse&) = delete;
  ScopedCleanse& operator=(const ScopedCleanse&) = delete;
  ~ScopedCleanse() {
    if (!bytes_.empty())
      OPENSSL_cleanse(bytes_.data(), bytes_.size());
  }

 private:
  base::span<uint8_t> bytes_;
};

void CleanseAndClear(std::string* value) {
  if (value && !value->empty()) {
    OPENSSL_cleanse(value->data(), value->size());
    value->clear();
  }
}

void CleanseOutput(base::span<char> bytes) {
  if (!bytes.empty())
    OPENSSL_cleanse(bytes.data(), bytes.size());
}

bool IsAllZero(base::span<const uint8_t> bytes) {
  uint8_t value = 0;
  for (uint8_t byte : bytes)
    value |= byte;
  return value == 0;
}

uint16_t ReadUInt16LE(const uint8_t* data) {
  return static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
}

uint32_t ReadUInt32LE(const uint8_t* data) {
  return static_cast<uint32_t>(data[0]) |
         (static_cast<uint32_t>(data[1]) << 8) |
         (static_cast<uint32_t>(data[2]) << 16) |
         (static_cast<uint32_t>(data[3]) << 24);
}

uint64_t ReadUInt64LE(const uint8_t* data) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; ++i)
    value |= static_cast<uint64_t>(data[i]) << (i * 8);
  return value;
}

void WriteUInt32LE(uint32_t value, uint8_t* out) {
  for (size_t i = 0; i < 4; ++i)
    out[i] = static_cast<uint8_t>(value >> (i * 8));
}

void WriteUInt64LE(uint64_t value, uint8_t* out) {
  for (size_t i = 0; i < 8; ++i)
    out[i] = static_cast<uint8_t>(value >> (i * 8));
}

bool ReadExact(base::File* file, uint64_t offset, base::span<uint8_t> output) {
  if (output.size() > static_cast<size_t>(std::numeric_limits<int>::max()) ||
      offset > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
    return false;
  }
  base::ThreadRestrictions::ScopedAllowIO allow_io;
  size_t total = 0;
  while (total < output.size()) {
    const int count = file->Read(static_cast<int64_t>(offset + total),
                                 reinterpret_cast<char*>(output.data() + total),
                                 static_cast<int>(output.size() - total));
    if (count <= 0)
      return false;
    total += static_cast<size_t>(count);
  }
  return true;
}

bool WriteExact(base::File* file,
                uint64_t offset,
                base::span<const uint8_t> input) {
  if (!file || !file->IsValid() ||
      input.size() > static_cast<size_t>(std::numeric_limits<int>::max()) ||
      offset > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
    return false;
  }
  base::ThreadRestrictions::ScopedAllowIO allow_io;
  size_t total = 0;
  while (total < input.size()) {
    const int count =
        file->Write(static_cast<int64_t>(offset + total),
                    reinterpret_cast<const char*>(input.data() + total),
                    static_cast<int>(input.size() - total));
    if (count <= 0)
      return false;
    total += static_cast<size_t>(count);
  }
  return true;
}

std::array<uint8_t, 32> HashParts(
    std::initializer_list<base::span<const uint8_t>> parts) {
  std::array<uint8_t, 32> digest{};
  std::unique_ptr<crypto::SecureHash> hash =
      crypto::SecureHash::Create(crypto::SecureHash::SHA256);
  for (base::span<const uint8_t> part : parts)
    hash->Update(part.data(), part.size());
  hash->Finish(digest.data(), digest.size());
  return digest;
}

base::span<const uint8_t> ByteSpan(const char* data, size_t size) {
  return base::make_span(reinterpret_cast<const uint8_t*>(data), size);
}

template <size_t N>
base::span<const uint8_t> ByteSpan(const std::array<uint8_t, N>& value) {
  return base::make_span(value);
}

bool ConstantTimeEqual(base::span<const uint8_t> left,
                       base::span<const uint8_t> right) {
  return left.size() == right.size() &&
         CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

bool IsWindowsDeviceName(std::string_view segment) {
  const size_t dot = segment.find('.');
  const std::string_view basename = segment.substr(0, dot);
  const auto equals_ascii = [](std::string_view value,
                               std::string_view candidate) {
    if (value.size() != candidate.size())
      return false;
    for (size_t index = 0; index < value.size(); ++index) {
      char character = value[index];
      if (character >= 'a' && character <= 'z')
        character = static_cast<char>(character - ('a' - 'A'));
      if (character != candidate[index])
        return false;
    }
    return true;
  };
  if (equals_ascii(basename, "CON") || equals_ascii(basename, "PRN") ||
      equals_ascii(basename, "AUX") || equals_ascii(basename, "NUL")) {
    return true;
  }
  const std::string_view prefix = basename.substr(0, 3);
  if (basename.size() < 4 ||
      (!equals_ascii(prefix, "COM") && !equals_ascii(prefix, "LPT"))) {
    return false;
  }
  const std::string_view suffix(basename.data() + 3, basename.size() - 3);
  return (suffix.size() == 1 && suffix[0] >= '1' && suffix[0] <= '9') ||
         suffix == "\xC2\xB9" || suffix == "\xC2\xB2" || suffix == "\xC2\xB3";
}

bool ValidateCanonicalPath(const std::string& path) {
  if (path.empty() || path.size() > kMaxPathBytes || path.front() == '/' ||
      path.back() == '/' || path.find('\\') != std::string::npos ||
      path.find(':') != std::string::npos || !base::IsStringUTF8(path)) {
    return false;
  }

  if (!base::IsStringASCII(path)) {
    std::string normalized;
    if (!base::ConvertToUtf8AndNormalize(path, "UTF-8", &normalized) ||
        normalized != path) {
      return false;
    }
  }

  size_t segment_start = 0;
  while (segment_start < path.size()) {
    size_t separator = path.find('/', segment_start);
    size_t segment_end =
        separator == std::string::npos ? path.size() : separator;
    std::string_view segment(path.data() + segment_start,
                             segment_end - segment_start);
    if (segment.empty() || segment.size() > kMaxPathSegmentBytes ||
        segment == "." || segment == ".." || segment.back() == '.' ||
        segment.back() == ' ' || IsWindowsDeviceName(segment)) {
      return false;
    }
    for (unsigned char character : segment) {
      if (character == 0 || (character >= 1 && character <= 0x1f) ||
          character == '<' || character == '>' || character == '"' ||
          character == '|' || character == '?' || character == '*') {
        return false;
      }
    }
    if (separator == std::string::npos)
      break;
    segment_start = separator + 1;
  }
  return true;
}

std::string PortablePathKey(const std::string& path) {
  if (base::IsStringASCII(path)) {
    std::string uppercase = path;
    for (char& character : uppercase) {
      if (character >= 'a' && character <= 'z')
        character = static_cast<char>(character - ('a' - 'A'));
    }
    return uppercase;
  }
  icu::UnicodeString uppercase = icu::UnicodeString::fromUTF8(path);
  uppercase.toUpper(icu::Locale::getRoot());
  UErrorCode status = U_ZERO_ERROR;
  const icu::Normalizer2* normalizer = icu::Normalizer2::getNFCInstance(status);
  icu::UnicodeString normalized;
  if (U_FAILURE(status) || !normalizer)
    return std::string();
  normalizer->normalize(uppercase, normalized, status);
  if (U_FAILURE(status))
    return std::string();
  std::string result;
  normalized.toUTF8String(result);
  return result;
}

size_t CommonPrefixLength(std::string_view left, std::string_view right) {
  const size_t length = std::min(left.size(), right.size());
  size_t index = 0;
  while (index < length && left[index] == right[index])
    ++index;
  return index;
}

int CompareBytewise(std::string_view left, std::string_view right) {
  const size_t common_size = std::min(left.size(), right.size());
  const int common =
      common_size == 0 ? 0 : memcmp(left.data(), right.data(), common_size);
  if (common != 0)
    return common;
  if (left.size() == right.size())
    return 0;
  return left.size() < right.size() ? -1 : 1;
}

std::string ParentPath(const std::string& path) {
  const size_t separator = path.rfind('/');
  return separator == std::string::npos ? std::string()
                                        : path.substr(0, separator);
}

std::string Basename(const std::string& path) {
  const size_t separator = path.rfind('/');
  return separator == std::string::npos ? path : path.substr(separator + 1);
}

std::string LookupPath(const base::FilePath& path) {
  std::string value = path.AsUTF8Unsafe();
#if BUILDFLAG(IS_WIN)
  std::replace(value.begin(), value.end(), '\\', '/');
#endif
  while (!value.empty() && value.front() == '/')
    value.erase(value.begin());
  while (!value.empty() && value.back() == '/')
    value.pop_back();
  return value;
}

class IndexReader {
 public:
  explicit IndexReader(base::span<const uint8_t> bytes) : bytes_(bytes) {}

  bool ReadByte(uint8_t* value) {
    if (offset_ == bytes_.size())
      return false;
    *value = bytes_[offset_++];
    return true;
  }

  bool ReadBytes(size_t length, base::span<const uint8_t>* value) {
    if (length > bytes_.size() - offset_)
      return false;
    *value = bytes_.subspan(offset_, length);
    offset_ += length;
    return true;
  }

  bool ReadVarint(uint64_t maximum, uint64_t* value) {
    uint64_t result = 0;
    for (size_t index = 0; index < 10; ++index) {
      uint8_t byte = 0;
      if (!ReadByte(&byte) || (index == 9 && byte > 1))
        return false;
      result |= static_cast<uint64_t>(byte & 0x7f) << (index * 7);
      if ((byte & 0x80) == 0) {
        if ((index > 0 && (byte & 0x7f) == 0) || result > maximum)
          return false;
        *value = result;
        return true;
      }
    }
    return false;
  }

  size_t offset() const { return offset_; }
  size_t remaining() const { return bytes_.size() - offset_; }

 private:
  base::span<const uint8_t> bytes_;
  size_t offset_ = 0;
};

base::File OpenUnpackedNoFollow(const base::FilePath& path) {
#if BUILDFLAG(IS_POSIX)
  base::ThreadRestrictions::ScopedAllowIO allow_io;
  const int descriptor = open(path.value().c_str(),
                              O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  struct stat info = {};
  if (descriptor < 0 || fstat(descriptor, &info) != 0 ||
      !S_ISREG(info.st_mode)) {
    if (descriptor >= 0)
      close(descriptor);
    return base::File(base::File::FILE_ERROR_SECURITY);
  }
  return base::File(descriptor);
#elif BUILDFLAG(IS_WIN)
  base::ThreadRestrictions::ScopedAllowIO allow_io;
  HANDLE handle =
      CreateFileW(path.value().c_str(), GENERIC_READ,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr, OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
                      FILE_FLAG_SEQUENTIAL_SCAN,
                  nullptr);
  if (handle == INVALID_HANDLE_VALUE)
    return base::File(base::File::FILE_ERROR_FAILED);
  FILE_ATTRIBUTE_TAG_INFO attributes{};
  if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes,
                                    sizeof(attributes)) ||
      (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
    CloseHandle(handle);
    return base::File(base::File::FILE_ERROR_SECURITY);
  }
  return base::File(handle);
#else
  return base::File(path, base::File::FLAG_OPEN | base::File::FLAG_READ);
#endif
}

class ReusableRawInflater {
 public:
  ReusableRawInflater() = default;
  ReusableRawInflater(const ReusableRawInflater&) = delete;
  ReusableRawInflater& operator=(const ReusableRawInflater&) = delete;
  ~ReusableRawInflater() {
    if (initialized_)
      inflateEnd(&stream_);
  }

  bool InflateExact(base::span<const uint8_t> compressed,
                    base::span<uint8_t> output,
                    size_t expected_size) {
    if (compressed.size() > std::numeric_limits<uInt>::max() ||
        output.size() > std::numeric_limits<uInt>::max() ||
        output.size() != expected_size + 1) {
      return false;
    }

    if (!initialized_) {
      if (inflateInit2(&stream_, -MAX_WBITS) != Z_OK)
        return false;
      initialized_ = true;
    } else if (inflateReset(&stream_) != Z_OK) {
      return false;
    }

    stream_.next_in = const_cast<Bytef*>(compressed.data());
    stream_.avail_in = static_cast<uInt>(compressed.size());
    stream_.next_out = output.data();
    stream_.avail_out = static_cast<uInt>(output.size());
    const int result = inflate(&stream_, Z_FINISH);
    return result == Z_STREAM_END && stream_.avail_in == 0 &&
           stream_.total_out == expected_size;
  }

 private:
  z_stream stream_{};
  bool initialized_ = false;
};

}  // namespace

class EasrV2Reader::State {
 public:
  enum class Kind : uint8_t { kDirectory, kFile, kSymlink };

  struct Chunk {
    uint64_t payload_offset = 0;
    std::array<uint8_t, kTagSize> tag{};
    uint32_t ordinal = 0;
    uint32_t file_ordinal = 0;
    uint32_t chunk_in_file = 0;
    uint32_t plain_size = 0;
    uint32_t stored_size = 0;
    uint8_t codec = 0;
    uint8_t entry_flags = 0;
  };

  struct Entry {
    std::string path;
    Kind kind = Kind::kDirectory;
    bool executable = false;
    bool unpacked = false;
    uint64_t size = 0;
    uint64_t packed_size = 0;
    uint32_t first_chunk = 0;
    uint32_t chunk_count = 0;
    std::string target;
    uint32_t resolved_entry = std::numeric_limits<uint32_t>::max();
    std::array<uint8_t, kDigestSize> digest{};
    std::vector<uint32_t> children;
  };

  struct CacheCounters {
    std::atomic<uint64_t> hits{0};
    std::atomic<uint64_t> misses{0};
    std::atomic<uint64_t> coalesced{0};
    std::atomic<uint64_t> evictions{0};
    std::atomic<uint64_t> cleansed_bytes{0};
  };

  struct SecureChunk {
    SecureChunk(size_t size, std::shared_ptr<CacheCounters> counters)
        : bytes(size), counters(std::move(counters)) {}
    ~SecureChunk() {
      if (!bytes.empty())
        OPENSSL_cleanse(bytes.data(), bytes.size());
      if (evicted.load(std::memory_order_relaxed))
        counters->cleansed_bytes.fetch_add(bytes.size(),
                                           std::memory_order_relaxed);
    }

    void MarkEvicted() { evicted.store(true, std::memory_order_relaxed); }

    std::vector<uint8_t> bytes;
    std::shared_ptr<CacheCounters> counters;
    std::atomic<bool> evicted{false};
  };

  struct CacheEntry {
    std::shared_ptr<SecureChunk> chunk;
    std::list<uint32_t>::iterator lru;
  };

  struct PendingChunk {
    PendingChunk()
        : ready(base::WaitableEvent::ResetPolicy::MANUAL,
                base::WaitableEvent::InitialState::NOT_SIGNALED) {}

    base::WaitableEvent ready;
    std::shared_ptr<SecureChunk> chunk;
    Error error = Error::kIo;
  };

  State() {
    chunk_cache.reserve(kDefaultChunkCacheEntries);
    pending_chunks.reserve(16);
  }
  ~State() {
    const size_t cached_bytes = chunk_cache_bytes;
    chunk_cache.clear();
    chunk_cache_lru.clear();
    chunk_cache_bytes = 0;
    ReleaseGlobalChunkBytes(cached_bytes);
    OPENSSL_cleanse(data_key.data(), data_key.size());
  }

  base::FilePath archive_path;
  std::array<uint8_t, kKeyIdSize> data_key_id{};
  std::array<uint8_t, kArchiveIdSize> archive_id{};
  std::array<uint8_t, 32> data_key{};
  std::array<uint8_t, kDigestSize> header_digest{};
  uint64_t epoch = 0;
  uint64_t payload_offset = 0;
  uint64_t payload_size = 0;
  uint32_t block_size = 0;
  std::vector<Entry> entries;
  std::vector<Chunk> chunks;
  std::unordered_map<std::string_view, uint32_t> by_path;
  std::vector<uint32_t> root_children;
  bssl::ScopedEVP_AEAD_CTX aead;

  mutable base::Lock chunk_cache_lock;
  size_t chunk_cache_byte_limit = kDefaultChunkCacheBytes;
  size_t chunk_cache_entry_limit = kDefaultChunkCacheEntries;
  size_t chunk_cache_bytes = 0;
  std::list<uint32_t> chunk_cache_lru;
  std::unordered_map<uint32_t, CacheEntry> chunk_cache;
  std::unordered_map<uint32_t, std::shared_ptr<PendingChunk>> pending_chunks;
  std::shared_ptr<CacheCounters> cache_counters =
      std::make_shared<CacheCounters>();
};

static_assert(sizeof(EasrV2Reader::State::Chunk) <= 48);

namespace {

using State = EasrV2Reader::State;

struct ChunkScratch {
  ~ChunkScratch() {
    if (!stored_plaintext.empty()) {
      OPENSSL_cleanse(stored_plaintext.data(), stored_plaintext.size());
    }
  }

  std::vector<uint8_t> ciphertext;
  std::vector<uint8_t> stored_plaintext;
  // Scratch is owned by one read/copy operation, so resetting the inflater
  // reuses zlib allocations without introducing shared mutable state.
  ReusableRawInflater inflater;
};

void BuildChunkNonceAndAad(const State& state,
                           const State::Chunk& chunk,
                           std::array<uint8_t, 12>* nonce,
                           std::array<uint8_t, 108>* aad) {
  memcpy(nonce->data(), "EA2D", 4);
  WriteUInt64LE(chunk.ordinal, nonce->data() + 4);
  memcpy(aad->data(), kAadDomain, sizeof(kAadDomain) - 1);
  memcpy(aad->data() + 16, state.archive_id.data(), state.archive_id.size());
  memcpy(aad->data() + 48, state.data_key_id.data(), state.data_key_id.size());
  WriteUInt64LE(state.epoch, aad->data() + 64);
  WriteUInt32LE(chunk.file_ordinal, aad->data() + 72);
  WriteUInt32LE(chunk.chunk_in_file, aad->data() + 76);
  WriteUInt64LE(chunk.ordinal, aad->data() + 80);
  WriteUInt64LE(static_cast<uint64_t>(chunk.chunk_in_file) * state.block_size,
                aad->data() + 88);
  WriteUInt32LE(chunk.plain_size, aad->data() + 96);
  WriteUInt32LE(chunk.stored_size, aad->data() + 100);
  (*aad)[104] = chunk.codec;
  (*aad)[105] = chunk.entry_flags;
}

std::shared_ptr<State::SecureChunk> LoadAuthenticatedChunk(
    const State& state,
    base::File* file,
    const State::Chunk& chunk,
    ChunkScratch* scratch,
    Error* error) {
  scratch->ciphertext.resize(chunk.stored_size);
  if (!ReadExact(file, state.payload_offset + chunk.payload_offset,
                 base::make_span(scratch->ciphertext))) {
    SetError(error, Error::kIo);
    return nullptr;
  }

  std::array<uint8_t, 12> nonce{};
  std::array<uint8_t, 108> aad{};
  BuildChunkNonceAndAad(state, chunk, &nonce, &aad);

  auto plaintext = std::make_shared<State::SecureChunk>(
      chunk.codec == kCodecRaw ? chunk.plain_size : chunk.plain_size + 1,
      state.cache_counters);
  scratch->stored_plaintext.resize(
      chunk.codec == kCodecRaw ? 0 : chunk.stored_size);
  ScopedCleanse cleanse_stored_plaintext(
      base::make_span(scratch->stored_plaintext));
  uint8_t* decrypted = nullptr;
  if (chunk.codec == kCodecRaw) {
    if (chunk.stored_size != chunk.plain_size) {
      SetError(error, Error::kDecompression);
      return nullptr;
    }
    decrypted = plaintext->bytes.data();
  } else {
    decrypted = scratch->stored_plaintext.data();
  }

  // BoringSSL explicitly permits concurrent open operations on one immutable
  // EVP_AEAD_CTX, so no crypto-wide lock serializes independent chunks.
  if (!EVP_AEAD_CTX_open_gather(state.aead.get(), decrypted, nonce.data(),
                                nonce.size(), scratch->ciphertext.data(),
                                scratch->ciphertext.size(), chunk.tag.data(),
                                chunk.tag.size(), aad.data(), aad.size())) {
    SetError(error, Error::kAuthentication);
    return nullptr;
  }

  if (chunk.codec == kCodecDeflateRaw) {
    if (!scratch->inflater.InflateExact(
            base::make_span(scratch->stored_plaintext),
            base::make_span(plaintext->bytes), chunk.plain_size)) {
      SetError(error, Error::kDecompression);
      return nullptr;
    }
    plaintext->bytes.resize(chunk.plain_size);
  } else if (chunk.codec != kCodecRaw) {
    SetError(error, Error::kDecompression);
    return nullptr;
  }

  SetError(error, Error::kNone);
  return plaintext;
}

void EvictChunkLocked(State* state,
                      uint32_t ordinal,
                      bool release_global_bytes = true)
    EXCLUSIVE_LOCKS_REQUIRED(state->chunk_cache_lock) {
  auto found = state->chunk_cache.find(ordinal);
  if (found == state->chunk_cache.end())
    return;
  state->chunk_cache_bytes -= found->second.chunk->bytes.size();
  if (release_global_bytes)
    ReleaseGlobalChunkBytes(found->second.chunk->bytes.size());
  state->chunk_cache_lru.erase(found->second.lru);
  found->second.chunk->MarkEvicted();
  state->chunk_cache.erase(found);
  state->cache_counters->evictions.fetch_add(1, std::memory_order_relaxed);
}

std::shared_ptr<State::SecureChunk> GetAuthenticatedChunk(
    State* state,
    base::File* file,
    const State::Chunk& chunk,
    ChunkScratch* scratch,
    Error* error) {
  std::shared_ptr<State::PendingChunk> pending;
  bool is_loader = false;
  {
    base::AutoLock auto_lock(state->chunk_cache_lock);
    auto cached = state->chunk_cache.find(chunk.ordinal);
    if (cached != state->chunk_cache.end()) {
      state->chunk_cache_lru.splice(state->chunk_cache_lru.end(),
                                    state->chunk_cache_lru, cached->second.lru);
      state->cache_counters->hits.fetch_add(1, std::memory_order_relaxed);
      SetError(error, Error::kNone);
      return cached->second.chunk;
    }

    auto loading = state->pending_chunks.find(chunk.ordinal);
    if (loading != state->pending_chunks.end()) {
      pending = loading->second;
      state->cache_counters->coalesced.fetch_add(1, std::memory_order_relaxed);
    } else {
      pending = std::make_shared<State::PendingChunk>();
      state->pending_chunks.emplace(chunk.ordinal, pending);
      state->cache_counters->misses.fetch_add(1, std::memory_order_relaxed);
      is_loader = true;
    }
  }

  if (!is_loader) {
    pending->ready.Wait();
    SetError(error, pending->error);
    return pending->chunk;
  }

  Error load_error = Error::kIo;
  std::shared_ptr<State::SecureChunk> loaded =
      LoadAuthenticatedChunk(*state, file, chunk, scratch, &load_error);
  {
    base::AutoLock auto_lock(state->chunk_cache_lock);
    state->pending_chunks.erase(chunk.ordinal);
    if (loaded && state->chunk_cache_byte_limit != 0 &&
        state->chunk_cache_entry_limit != 0 &&
        loaded->bytes.size() <= state->chunk_cache_byte_limit) {
      size_t eviction_count = 0;
      size_t eviction_bytes = 0;
      size_t remaining_entries = state->chunk_cache.size();
      size_t remaining_bytes = state->chunk_cache_bytes;
      auto candidate = state->chunk_cache_lru.begin();
      while (candidate != state->chunk_cache_lru.end() &&
             (remaining_entries >= state->chunk_cache_entry_limit ||
              remaining_bytes >
                  state->chunk_cache_byte_limit - loaded->bytes.size())) {
        const auto found = state->chunk_cache.find(*candidate++);
        DCHECK(found != state->chunk_cache.end());
        const size_t candidate_bytes = found->second.chunk->bytes.size();
        ++eviction_count;
        eviction_bytes += candidate_bytes;
        --remaining_entries;
        remaining_bytes -= candidate_bytes;
      }

      const size_t loaded_bytes = loaded->bytes.size();
      const size_t additional_global_bytes =
          loaded_bytes > eviction_bytes ? loaded_bytes - eviction_bytes : 0;
      if (TryReserveGlobalChunkBytes(additional_global_bytes)) {
        for (size_t index = 0; index < eviction_count; ++index) {
          EvictChunkLocked(state, state->chunk_cache_lru.front(),
                           /*release_global_bytes=*/false);
        }
        if (eviction_bytes > loaded_bytes)
          ReleaseGlobalChunkBytes(eviction_bytes - loaded_bytes);
        state->chunk_cache_lru.push_back(chunk.ordinal);
        auto lru = std::prev(state->chunk_cache_lru.end());
        state->chunk_cache.emplace(chunk.ordinal,
                                   State::CacheEntry{loaded, lru});
        state->chunk_cache_bytes += loaded_bytes;
      }
    }
    pending->chunk = loaded;
    pending->error = load_error;
  }
  pending->ready.Signal();
  SetError(error, load_error);
  return loaded;
}

bool FillFileInfo(const EasrV2Reader::State& state,
                  uint32_t index,
                  Archive::FileInfo* info) {
  if (index >= state.entries.size())
    return false;
  const auto& source = state.entries[index];
  if (source.kind != EasrV2Reader::State::Kind::kFile)
    return false;

  info->unpacked = source.unpacked;
  info->executable = source.executable;
  info->size = source.size;
  info->packed_size = source.packed_size;
  info->easr_entry = index;
  info->integrity.reset();
  if (!source.unpacked && source.chunk_count != 0) {
    const auto& first = state.chunks[source.first_chunk];
    info->offset = state.payload_offset + first.payload_offset;
  } else {
    info->offset = 0;
  }
  return true;
}

uint32_t FindEntry(const EasrV2Reader::State& state,
                   const base::FilePath& path) {
  const std::string key = LookupPath(path);
  auto found = state.by_path.find(key);
  return found == state.by_path.end() ? std::numeric_limits<uint32_t>::max()
                                      : found->second;
}

uint32_t ResolveEntry(const EasrV2Reader::State& state, uint32_t index) {
  if (index >= state.entries.size())
    return std::numeric_limits<uint32_t>::max();
  const auto& entry = state.entries[index];
  return entry.kind == EasrV2Reader::State::Kind::kSymlink
             ? entry.resolved_entry
             : index;
}

bool ParseIndex(base::span<const uint8_t> index,
                uint64_t expected_payload_size,
                EasrV2Reader::State* state) {
  if (index.size() < kIndexHeaderSize || index.size() > kMaxIndexSize ||
      memcmp(index.data(), kIndexMagic, 4) != 0 || index[4] != 1 ||
      index[5] != 0 || index[7] < 12 || index[7] > 20) {
    return false;
  }

  state->block_size = 1U << index[7];
  IndexReader reader(index);
  base::span<const uint8_t> ignored;
  if (!reader.ReadBytes(kIndexHeaderSize, &ignored))
    return false;

  uint64_t entry_count64 = 0;
  uint64_t declared_chunk_count64 = 0;
  if (!reader.ReadVarint(kMaxEntryCount, &entry_count64) ||
      !reader.ReadVarint(kMaxChunkCount, &declared_chunk_count64)) {
    return false;
  }
  const uint32_t entry_count = static_cast<uint32_t>(entry_count64);
  const uint32_t declared_chunk_count =
      static_cast<uint32_t>(declared_chunk_count64);
  state->entries.reserve(entry_count);
  state->chunks.reserve(declared_chunk_count);
  state->by_path.reserve(entry_count);

  std::string_view previous_path;
  size_t expanded_path_bytes = 0;
  uint64_t payload_size = 0;
  std::unordered_set<std::string> portable_paths;
  portable_paths.reserve(entry_count);

  for (uint32_t file_ordinal = 0; file_ordinal < entry_count; ++file_ordinal) {
    uint64_t prefix_length = 0;
    uint64_t suffix_length = 0;
    if (!reader.ReadVarint(kMaxPathBytes, &prefix_length) ||
        !reader.ReadVarint(kMaxPathBytes, &suffix_length) ||
        prefix_length > previous_path.size() ||
        prefix_length + suffix_length > kMaxPathBytes) {
      return false;
    }
    const size_t path_length =
        static_cast<size_t>(prefix_length + suffix_length);
    if (expanded_path_bytes > kMaxExpandedPathBytes - path_length)
      return false;
    base::span<const uint8_t> suffix;
    if (!reader.ReadBytes(static_cast<size_t>(suffix_length), &suffix))
      return false;
    std::string path;
    path.reserve(path_length);
    if (prefix_length != 0)
      path.append(previous_path.data(), static_cast<size_t>(prefix_length));
    path.append(reinterpret_cast<const char*>(suffix.data()), suffix.size());
    if (!ValidateCanonicalPath(path) ||
        (file_ordinal > 0 && CompareBytewise(path, previous_path) <= 0) ||
        prefix_length !=
            (file_ordinal == 0 ? 0 : CommonPrefixLength(previous_path, path))) {
      return false;
    }
    expanded_path_bytes += path_length;

    std::string portable = PortablePathKey(path);
    if (portable.empty() || !portable_paths.insert(std::move(portable)).second)
      return false;

    uint8_t flags = 0;
    if (!reader.ReadByte(&flags) || (flags & ~kEntryKnownFlags) != 0)
      return false;
    const uint8_t kind = flags & kEntryKindMask;
    if (kind == 3 || (kind == kEntryDirectory && flags != kEntryDirectory) ||
        (kind == kEntrySymlink && flags != kEntrySymlink)) {
      return false;
    }

    State::Entry entry;
    entry.path = std::move(path);
    entry.executable = (flags & kEntryExecutable) != 0;
    entry.unpacked = (flags & kEntryUnpacked) != 0;
    entry.kind = kind == kEntryDirectory
                     ? State::Kind::kDirectory
                     : (kind == kEntrySymlink ? State::Kind::kSymlink
                                              : State::Kind::kFile);

    const std::string parent = ParentPath(entry.path);
    uint32_t parent_index = std::numeric_limits<uint32_t>::max();
    if (!parent.empty()) {
      auto found = state->by_path.find(parent);
      if (found == state->by_path.end() ||
          state->entries[found->second].kind != State::Kind::kDirectory) {
        return false;
      }
      parent_index = found->second;
    }

    if (entry.kind == State::Kind::kSymlink) {
      uint64_t target_length = 0;
      base::span<const uint8_t> target;
      if (!reader.ReadVarint(kMaxPathBytes, &target_length) ||
          !reader.ReadBytes(static_cast<size_t>(target_length), &target)) {
        return false;
      }
      entry.target.assign(reinterpret_cast<const char*>(target.data()),
                          target.size());
      if (!ValidateCanonicalPath(entry.target))
        return false;
    } else if (entry.kind == State::Kind::kFile) {
      uint64_t size = 0;
      if (!reader.ReadVarint(kMaxSafeInteger, &size))
        return false;
      entry.size = size;
      if (entry.unpacked) {
        base::span<const uint8_t> digest;
        if (!reader.ReadBytes(kDigestSize, &digest))
          return false;
        std::copy(digest.begin(), digest.end(), entry.digest.begin());
        entry.packed_size = size;
      } else {
        const uint64_t chunk_count =
            size == 0 ? 0 : ((size - 1) / state->block_size) + 1;
        if (chunk_count > kMaxChunkCount ||
            state->chunks.size() + chunk_count > declared_chunk_count) {
          return false;
        }
        entry.first_chunk = static_cast<uint32_t>(state->chunks.size());
        entry.chunk_count = static_cast<uint32_t>(chunk_count);
        for (uint32_t chunk_in_file = 0; chunk_in_file < entry.chunk_count;
             ++chunk_in_file) {
          const uint64_t logical_offset =
              static_cast<uint64_t>(chunk_in_file) * state->block_size;
          const uint32_t plain_size = static_cast<uint32_t>(
              std::min<uint64_t>(state->block_size, size - logical_offset));
          uint64_t descriptor = 0;
          if (!reader.ReadVarint(state->block_size, &descriptor))
            return false;
          const uint8_t codec = descriptor == 0 ? kCodecRaw : kCodecDeflateRaw;
          const uint32_t stored_size =
              descriptor == 0 ? plain_size : static_cast<uint32_t>(descriptor);
          if ((codec == kCodecDeflateRaw &&
               (stored_size == 0 || stored_size >= plain_size)) ||
              payload_size > kMaxSafeInteger - stored_size) {
            return false;
          }
          State::Chunk chunk;
          chunk.ordinal = static_cast<uint32_t>(state->chunks.size());
          chunk.file_ordinal = file_ordinal;
          chunk.chunk_in_file = chunk_in_file;
          chunk.plain_size = plain_size;
          chunk.stored_size = stored_size;
          chunk.payload_offset = payload_size;
          chunk.codec = codec;
          chunk.entry_flags = flags;
          state->chunks.push_back(chunk);
          entry.packed_size += stored_size;
          payload_size += stored_size;
        }
      }
    }

    const uint32_t entry_index = static_cast<uint32_t>(state->entries.size());
    state->entries.push_back(std::move(entry));
    const auto inserted = state->by_path.emplace(
        std::string_view(state->entries.back().path), entry_index);
    if (!inserted.second)
      return false;
    if (parent_index == std::numeric_limits<uint32_t>::max())
      state->root_children.push_back(entry_index);
    else
      state->entries[parent_index].children.push_back(entry_index);
    previous_path = state->entries.back().path;
  }

  if (state->chunks.size() != declared_chunk_count ||
      payload_size != expected_payload_size ||
      reader.remaining() !=
          static_cast<size_t>(declared_chunk_count) * kTagSize) {
    return false;
  }
  for (State::Chunk& chunk : state->chunks) {
    base::span<const uint8_t> tag;
    if (!reader.ReadBytes(kTagSize, &tag))
      return false;
    std::copy(tag.begin(), tag.end(), chunk.tag.begin());
  }
  if (reader.remaining() != 0)
    return false;
  state->payload_size = payload_size;

  for (uint32_t index_value = 0; index_value < state->entries.size();
       ++index_value) {
    State::Entry& entry = state->entries[index_value];
    if (entry.kind != State::Kind::kSymlink)
      continue;
    auto found = state->by_path.find(entry.target);
    if (found == state->by_path.end())
      return false;

    std::unordered_set<uint32_t> visited;
    visited.insert(index_value);
    uint32_t current = found->second;
    size_t depth = 1;
    while (state->entries[current].kind == State::Kind::kSymlink) {
      if (depth++ >= kMaxSymlinkDepth || !visited.insert(current).second)
        return false;
      auto target = state->by_path.find(state->entries[current].target);
      if (target == state->by_path.end())
        return false;
      current = target->second;
    }
    entry.resolved_entry = current;
  }
  return true;
}

bool VerifyUnpackedFile(const EasrV2Reader::State& state,
                        uint32_t entry_index,
                        std::string* contents,
                        base::File* destination) {
  if (entry_index >= state.entries.size())
    return false;
  const auto& entry = state.entries[entry_index];
  if (entry.kind != State::Kind::kFile || !entry.unpacked ||
      entry.size > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
    return false;
  }
  const base::FilePath path =
      state.archive_path.AddExtension(FILE_PATH_LITERAL("unpacked"))
          .Append(base::FilePath::FromUTF8Unsafe(entry.path));
  base::File file = OpenUnpackedNoFollow(path);
  if (!file.IsValid())
    return false;
  base::File::Info before;
  if (!file.GetInfo(&before) || before.is_directory ||
      before.size != static_cast<int64_t>(entry.size)) {
    return false;
  }

  std::unique_ptr<crypto::SecureHash> hash =
      crypto::SecureHash::Create(crypto::SecureHash::SHA256);
  constexpr size_t kBufferSize = 64 * 1024;
  std::array<uint8_t, kBufferSize> buffer{};
  ScopedCleanse cleanse_buffer(base::make_span(buffer));
  uint64_t offset = 0;
  if (contents) {
    if (entry.size > contents->max_size())
      return false;
    CleanseAndClear(contents);
    contents->reserve(static_cast<size_t>(entry.size));
  }
  while (offset < entry.size) {
    const size_t request = static_cast<size_t>(
        std::min<uint64_t>(buffer.size(), entry.size - offset));
    if (!ReadExact(&file, offset, base::make_span(buffer).first(request))) {
      CleanseAndClear(contents);
      return false;
    }
    hash->Update(buffer.data(), request);
    if (contents)
      contents->append(reinterpret_cast<const char*>(buffer.data()), request);
    if (destination) {
      if (!WriteExact(destination, offset,
                      base::make_span(buffer).first(request))) {
        CleanseAndClear(contents);
        return false;
      }
    }
    offset += request;
  }
  std::array<uint8_t, kDigestSize> digest{};
  hash->Finish(digest.data(), digest.size());
  base::File::Info after;
  const bool valid =
      file.GetInfo(&after) && after.size == before.size &&
      after.last_modified == before.last_modified &&
      ConstantTimeEqual(ByteSpan(digest), ByteSpan(entry.digest));
  OPENSSL_cleanse(buffer.data(), buffer.size());
  if (!valid) {
    CleanseAndClear(contents);
    return false;
  }
  return true;
}

}  // namespace

std::unique_ptr<EasrV2Reader> EasrV2Reader::Create(
    base::File* file,
    const base::FilePath& archive_path,
    const EasrKeyProvider* key_provider,
    base::span<const uint8_t> superblock_bytes,
    Error* error) {
  SetError(error, Error::kMalformedSuperblock);
  if (!file || !file->IsValid()) {
    SetError(error, Error::kIo);
    return nullptr;
  }

  int64_t file_length;
  {
    base::ThreadRestrictions::ScopedAllowIO allow_io;
    file_length = file->GetLength();
  }
  if (file_length < static_cast<int64_t>(kSuperblockSize))
    return nullptr;

  if (superblock_bytes.size() != kSuperblockSize)
    return nullptr;
  std::array<uint8_t, kSuperblockSize> superblock{};
  std::copy(superblock_bytes.begin(), superblock_bytes.end(),
            superblock.begin());
  if (memcmp(superblock.data(), kEasrMagic, 4) != 0 ||
      ReadUInt32LE(superblock.data() + 4) != 2 ||
      ReadUInt16LE(superblock.data() + 8) != kSuperblockSize ||
      superblock[10] != 1 || superblock[11] != 1 ||
      (ReadUInt32LE(superblock.data() + 12) & 0xffff0000U) != 0 ||
      ReadUInt32LE(superblock.data() + 20) != 0) {
    return nullptr;
  }

  const uint32_t index_size = ReadUInt32LE(superblock.data() + 16);
  const uint64_t payload_size = ReadUInt64LE(superblock.data() + 24);
  const uint64_t epoch = ReadUInt64LE(superblock.data() + 32);
  if (index_size < kIndexHeaderSize || index_size > kMaxIndexSize ||
      payload_size > kMaxSafeInteger ||
      payload_size > kMaxSafeInteger - kSuperblockSize - index_size) {
    return nullptr;
  }

  EasrKeyId data_key_id{};
  EasrKeyId signing_key_id{};
  std::array<uint8_t, kArchiveIdSize> archive_id{};
  std::array<uint8_t, kIndexHashSize> index_hash{};
  std::copy_n(superblock.begin() + 40, kKeyIdSize, data_key_id.begin());
  std::copy_n(superblock.begin() + 56, kKeyIdSize, signing_key_id.begin());
  std::copy_n(superblock.begin() + 72, kArchiveIdSize, archive_id.begin());
  std::copy_n(superblock.begin() + 104, kIndexHashSize, index_hash.begin());
  if (IsAllZero(ByteSpan(data_key_id)) || IsAllZero(ByteSpan(signing_key_id)) ||
      IsAllZero(ByteSpan(archive_id))) {
    return nullptr;
  }

  const uint64_t expected_length =
      kSuperblockSize + static_cast<uint64_t>(index_size) + payload_size;
  if (file_length < 0 ||
      static_cast<uint64_t>(file_length) != expected_length) {
    SetError(error, Error::kArchiveSize);
    return nullptr;
  }

  if (!key_provider) {
    SetError(error, Error::kUnknownSigningKey);
    return nullptr;
  }
  int signature_valid = 0;
  {
    std::array<uint8_t, 32> public_key{};
    ScopedCleanse cleanse_public_key(base::make_span(public_key));
    if (!key_provider->GetSigningPublicKey(signing_key_id, &public_key)) {
      SetError(error, Error::kUnknownSigningKey);
      return nullptr;
    }
    const auto derived_signing_id = HashParts(
        {ByteSpan(kSigningKeyIdDomain, sizeof(kSigningKeyIdDomain) - 1),
         ByteSpan(kEd25519SpkiPrefix), ByteSpan(public_key)});
    if (!ConstantTimeEqual(
            base::make_span(derived_signing_id).first(kKeyIdSize),
            ByteSpan(signing_key_id))) {
      SetError(error, Error::kSigningKeyIdMismatch);
      return nullptr;
    }

    std::array<uint8_t, sizeof(kSignatureDomain) - 1 + kSignatureOffset>
        signature_message{};
    memcpy(signature_message.data(), kSignatureDomain,
           sizeof(kSignatureDomain) - 1);
    memcpy(signature_message.data() + sizeof(kSignatureDomain) - 1,
           superblock.data(), kSignatureOffset);
    signature_valid =
        ED25519_verify(signature_message.data(), signature_message.size(),
                       superblock.data() + kSignatureOffset, public_key.data());
  }
  if (signature_valid != 1) {
    SetError(error, Error::kInvalidSignature);
    return nullptr;
  }

  if (epoch < key_provider->GetMinimumEpoch(data_key_id, signing_key_id)) {
    SetError(error, Error::kRollback);
    return nullptr;
  }

  std::vector<uint8_t> index(index_size);
  if (!ReadExact(file, kSuperblockSize, base::make_span(index))) {
    SetError(error, Error::kIo);
    return nullptr;
  }
  const auto actual_index_hash = crypto::SHA256Hash(base::make_span(index));
  if (!ConstantTimeEqual(ByteSpan(actual_index_hash), ByteSpan(index_hash))) {
    SetError(error, Error::kIndexHash);
    return nullptr;
  }

  auto state = std::make_unique<State>();
  state->archive_path = archive_path;
  state->header_digest = crypto::SHA256Hash(base::make_span(superblock));
  state->data_key_id = data_key_id;
  state->archive_id = archive_id;
  state->epoch = epoch;
  state->payload_offset = kSuperblockSize + index_size;
  if (!ParseIndex(base::make_span(index), payload_size, state.get())) {
    SetError(error, Error::kMalformedIndex);
    return nullptr;
  }

  std::array<uint8_t, sizeof(kDataKeyDomain) - 1 + kKeyIdSize + 8> info{};
  memcpy(info.data(), kDataKeyDomain, sizeof(kDataKeyDomain) - 1);
  memcpy(info.data() + sizeof(kDataKeyDomain) - 1, data_key_id.data(),
         data_key_id.size());
  WriteUInt64LE(epoch, info.data() + sizeof(kDataKeyDomain) - 1 + kKeyIdSize);
  {
    std::array<uint8_t, 32> master_key{};
    ScopedCleanse cleanse_master_key(base::make_span(master_key));
    if (!key_provider->GetDataKey(data_key_id, &master_key)) {
      SetError(error, Error::kUnknownDataKey);
      return nullptr;
    }
    const auto derived_data_id =
        HashParts({ByteSpan(kDataKeyIdDomain, sizeof(kDataKeyIdDomain) - 1),
                   ByteSpan(master_key)});
    if (IsAllZero(ByteSpan(master_key)) ||
        !ConstantTimeEqual(base::make_span(derived_data_id).first(kKeyIdSize),
                           ByteSpan(data_key_id))) {
      SetError(error, Error::kDataKeyIdMismatch);
      return nullptr;
    }

    std::vector<uint8_t> derived_key = crypto::HkdfSha256(
        base::make_span(master_key), base::make_span(archive_id),
        base::make_span(info), state->data_key.size());
    ScopedCleanse cleanse_derived_key(base::make_span(derived_key));
    if (derived_key.size() != state->data_key.size()) {
      SetError(error, Error::kDataKeyIdMismatch);
      return nullptr;
    }
    std::copy(derived_key.begin(), derived_key.end(), state->data_key.begin());
  }

  if (!EVP_AEAD_CTX_init(state->aead.get(), EVP_aead_aes_256_gcm(),
                         state->data_key.data(), state->data_key.size(),
                         kTagSize, nullptr)) {
    SetError(error, Error::kDataKeyIdMismatch);
    return nullptr;
  }
  SetError(error, Error::kNone);
  return std::unique_ptr<EasrV2Reader>(new EasrV2Reader(std::move(state)));
}

EasrV2Reader::EasrV2Reader(std::unique_ptr<State> state)
    : state_(std::move(state)) {}

EasrV2Reader::~EasrV2Reader() = default;

size_t GetEasrGlobalChunkCacheBytesForTesting() {
  return g_global_chunk_cache_bytes.load(std::memory_order_acquire);
}

void SetEasrGlobalChunkCacheByteLimitForTesting(size_t byte_limit) {
  CHECK_EQ(GetEasrGlobalChunkCacheBytesForTesting(), 0u);
  g_global_chunk_cache_byte_limit.store(byte_limit, std::memory_order_release);
}

void ResetEasrGlobalChunkCacheByteLimitForTesting() {
  SetEasrGlobalChunkCacheByteLimitForTesting(kGlobalChunkCacheBytes);
}

const std::array<uint8_t, 32>& EasrV2Reader::header_digest() const {
  return state_->header_digest;
}

bool EasrV2Reader::GetFileInfo(const base::FilePath& path,
                               Archive::FileInfo* info) const {
  const uint32_t index = ResolveEntry(*state_, FindEntry(*state_, path));
  return info && FillFileInfo(*state_, index, info);
}

bool EasrV2Reader::Stat(const base::FilePath& path,
                        Archive::Stats* stats) const {
  if (!stats)
    return false;
  const std::string lookup = LookupPath(path);
  if (lookup.empty()) {
    stats->is_file = false;
    stats->is_directory = true;
    stats->is_link = false;
    stats->size = 0;
    return true;
  }
  const uint32_t index = FindEntry(*state_, path);
  if (index >= state_->entries.size())
    return false;
  const auto& entry = state_->entries[index];
  stats->is_file = entry.kind == State::Kind::kFile;
  stats->is_directory = entry.kind == State::Kind::kDirectory;
  stats->is_link = entry.kind == State::Kind::kSymlink;
  if (stats->is_file)
    return FillFileInfo(*state_, index, stats);
  stats->size = 0;
  stats->offset = 0;
  stats->unpacked = false;
  stats->executable = false;
  stats->easr_entry = index;
  return true;
}

bool EasrV2Reader::Readdir(const base::FilePath& path,
                           std::vector<base::FilePath>* files) const {
  if (!files)
    return false;
  const std::string lookup = LookupPath(path);
  const std::vector<uint32_t>* children = nullptr;
  if (lookup.empty()) {
    children = &state_->root_children;
  } else {
    const uint32_t index = ResolveEntry(*state_, FindEntry(*state_, path));
    if (index >= state_->entries.size() ||
        state_->entries[index].kind != State::Kind::kDirectory) {
      return false;
    }
    children = &state_->entries[index].children;
  }
  for (uint32_t child : *children) {
    files->push_back(
        base::FilePath::FromUTF8Unsafe(Basename(state_->entries[child].path)));
  }
  return true;
}

bool EasrV2Reader::Realpath(const base::FilePath& path,
                            base::FilePath* realpath) const {
  if (!realpath)
    return false;
  const uint32_t index = FindEntry(*state_, path);
  if (index >= state_->entries.size())
    return false;
  const auto& entry = state_->entries[index];
  *realpath = entry.kind == State::Kind::kSymlink
                  ? base::FilePath::FromUTF8Unsafe(entry.target)
                  : path;
  return true;
}

bool EasrV2Reader::ReadFile(base::File* file,
                            const base::FilePath& path,
                            std::string* contents,
                            Error* error) const {
  Archive::FileInfo info;
  if (!GetFileInfo(path, &info)) {
    SetError(error, Error::kNotFound);
    return false;
  }
  if (info.unpacked) {
    if (!VerifyUnpackedFile(*state_, info.easr_entry, contents, nullptr)) {
      SetError(error, Error::kUnpackedAuthentication);
      return false;
    }
    SetError(error, Error::kNone);
    return true;
  }
  if (info.size > std::numeric_limits<size_t>::max()) {
    SetError(error, Error::kInvalidRange);
    return false;
  }
  return ReadRange(file, info, 0, static_cast<size_t>(info.size), contents,
                   error);
}

bool EasrV2Reader::ReadRange(base::File* file,
                             const Archive::FileInfo& info,
                             uint64_t offset,
                             size_t size,
                             std::string* contents,
                             Error* error) const {
  if (!contents) {
    SetError(error, Error::kInvalidRange);
    return false;
  }
  CleanseAndClear(contents);
  if (offset > info.size || size > info.size - offset ||
      size > contents->max_size()) {
    SetError(error, Error::kInvalidRange);
    return false;
  }
  contents->resize(size);
  if (!ReadRange(file, info, offset, base::make_span(*contents), error)) {
    CleanseAndClear(contents);
    return false;
  }
  return true;
}

bool EasrV2Reader::ReadRange(base::File* file,
                             const Archive::FileInfo& info,
                             uint64_t offset,
                             base::span<char> contents,
                             Error* error) const {
  if (!file || !file->IsValid() || info.easr_entry >= state_->entries.size()) {
    CleanseOutput(contents);
    SetError(error, Error::kInvalidRange);
    return false;
  }
  const State::Entry& entry = state_->entries[info.easr_entry];
  if (entry.kind != State::Kind::kFile || entry.unpacked ||
      offset > entry.size || contents.size() > entry.size - offset) {
    CleanseOutput(contents);
    SetError(error, Error::kInvalidRange);
    return false;
  }
  if (contents.empty()) {
    SetError(error, Error::kNone);
    return true;
  }

  const uint64_t end = offset + contents.size();
  const uint32_t first_chunk =
      static_cast<uint32_t>(offset / state_->block_size);
  const uint32_t last_chunk =
      static_cast<uint32_t>((end - 1) / state_->block_size);
  ChunkScratch scratch;
  for (uint32_t chunk_in_file = first_chunk; chunk_in_file <= last_chunk;
       ++chunk_in_file) {
    const State::Chunk& chunk =
        state_->chunks[entry.first_chunk + chunk_in_file];
    std::shared_ptr<State::SecureChunk> plaintext =
        GetAuthenticatedChunk(state_.get(), file, chunk, &scratch, error);
    if (!plaintext) {
      CleanseOutput(contents);
      return false;
    }

    const uint64_t chunk_logical_offset =
        static_cast<uint64_t>(chunk.chunk_in_file) * state_->block_size;
    const uint64_t copy_start =
        std::max<uint64_t>(offset, chunk_logical_offset);
    const uint64_t copy_end =
        std::min<uint64_t>(end, chunk_logical_offset + chunk.plain_size);
    const size_t copy_size = static_cast<size_t>(copy_end - copy_start);
    memcpy(contents.data() + (copy_start - offset),
           plaintext->bytes.data() + (copy_start - chunk_logical_offset),
           copy_size);
  }
  SetError(error, Error::kNone);
  return true;
}

bool EasrV2Reader::CopyFileTo(base::File* archive_file,
                              const Archive::FileInfo& info,
                              base::File* destination,
                              Error* error) const {
  if (!destination || !destination->IsValid() ||
      info.easr_entry >= state_->entries.size()) {
    SetError(error, Error::kInvalidRange);
    return false;
  }
  const State::Entry& entry = state_->entries[info.easr_entry];
  if (entry.kind != State::Kind::kFile) {
    SetError(error, Error::kInvalidRange);
    return false;
  }
  if (entry.unpacked) {
    if (!VerifyUnpackedFile(*state_, info.easr_entry, nullptr, destination)) {
      SetError(error, Error::kUnpackedAuthentication);
      return false;
    }
    SetError(error, Error::kNone);
    return true;
  }
  if (entry.chunk_count != 0 && (!archive_file || !archive_file->IsValid())) {
    SetError(error, Error::kInvalidRange);
    return false;
  }

  uint64_t logical_offset = 0;
  ChunkScratch scratch;
  for (uint32_t chunk_in_file = 0; chunk_in_file < entry.chunk_count;
       ++chunk_in_file) {
    const State::Chunk& chunk =
        state_->chunks[entry.first_chunk + chunk_in_file];
    std::shared_ptr<State::SecureChunk> plaintext = GetAuthenticatedChunk(
        state_.get(), archive_file, chunk, &scratch, error);
    if (!plaintext)
      return false;

    const uint64_t chunk_logical_offset =
        static_cast<uint64_t>(chunk.chunk_in_file) * state_->block_size;
    if (chunk_logical_offset != logical_offset ||
        plaintext->bytes.size() != chunk.plain_size) {
      SetError(error, Error::kIo);
      return false;
    }
    if (!WriteExact(destination, logical_offset,
                    base::make_span(plaintext->bytes))) {
      SetError(error, Error::kIo);
      return false;
    }
    logical_offset += chunk.plain_size;
  }
  if (logical_offset != entry.size) {
    SetError(error, Error::kIo);
    return false;
  }
  SetError(error, Error::kNone);
  return true;
}

void EasrV2Reader::SetChunkCacheLimitsForTesting(size_t byte_limit,
                                                 size_t chunk_limit) {
  base::AutoLock auto_lock(state_->chunk_cache_lock);
  state_->chunk_cache_byte_limit = byte_limit;
  state_->chunk_cache_entry_limit = chunk_limit;
  while (!state_->chunk_cache_lru.empty() &&
         (state_->chunk_cache.size() > chunk_limit ||
          state_->chunk_cache_bytes > byte_limit)) {
    EvictChunkLocked(state_.get(), state_->chunk_cache_lru.front());
  }
}

Archive::EasrChunkCacheStats EasrV2Reader::GetChunkCacheStatsForTesting()
    const {
  Archive::EasrChunkCacheStats stats;
  base::AutoLock auto_lock(state_->chunk_cache_lock);
  stats.hits = state_->cache_counters->hits.load(std::memory_order_relaxed);
  stats.misses = state_->cache_counters->misses.load(std::memory_order_relaxed);
  stats.coalesced =
      state_->cache_counters->coalesced.load(std::memory_order_relaxed);
  stats.evictions =
      state_->cache_counters->evictions.load(std::memory_order_relaxed);
  stats.cleansed_bytes =
      state_->cache_counters->cleansed_bytes.load(std::memory_order_relaxed);
  stats.entries = state_->chunk_cache.size();
  stats.bytes = state_->chunk_cache_bytes;
  return stats;
}

void EasrV2Reader::ClearChunkCacheForTesting() {
  base::AutoLock auto_lock(state_->chunk_cache_lock);
  while (!state_->chunk_cache_lru.empty())
    EvictChunkLocked(state_.get(), state_->chunk_cache_lru.front());
}

}  // namespace asar
