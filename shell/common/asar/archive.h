// Copyright (c) 2014 GitHub, Inc.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#ifndef ELECTRON_SHELL_COMMON_ASAR_ARCHIVE_H_
#define ELECTRON_SHELL_COMMON_ASAR_ARCHIVE_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "base/containers/span.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/synchronization/lock.h"
#include "base/values.h"
#include "electron/buildflags/buildflags.h"
#include "third_party/abseil-cpp/absl/types/optional.h"

namespace asar {

#if BUILDFLAG(ENABLE_EASR_V2)
using EasrKeyId = std::array<uint8_t, 16>;

// Supplies EASR keys from embedder-owned trusted storage. Implementations must
// outlive every Archive and must be safe to call from any thread. The runtime
// has no built-in key and never falls back when an id is unknown.
class EasrKeyProvider {
 public:
  virtual ~EasrKeyProvider() = default;

  // Returns the 32-byte AES-256 master key identified by |id|.
  virtual bool GetDataKey(const EasrKeyId& id,
                          std::array<uint8_t, 32>* key) const = 0;

  // Returns the raw 32-byte Ed25519 public key identified by |id|.
  virtual bool GetSigningPublicKey(
      const EasrKeyId& id,
      std::array<uint8_t, 32>* public_key) const = 0;

  // Signed archives below this trusted epoch are rejected after signature
  // verification. Embedders can use this for rollback protection.
  virtual uint64_t GetMinimumEpoch(const EasrKeyId& data_key_id,
                                   const EasrKeyId& signing_key_id) const;
};

// The provider pointer is borrowed and must remain valid until process exit.
// Passing nullptr removes it. Production embedders should install it before
// any archive is opened.
void SetEasrKeyProviderForProcess(const EasrKeyProvider* provider);

// Ordinary ASAR remains compatible by default. Enabling this process policy
// rejects every non-EASR-v2 archive, including legacy EASR v1.
void SetRequireEncryptedAsarForProcess(bool require_encrypted);

// Installs immutable build-time key material and the ordinary-ASAR policy.
// Safe to call repeatedly and early enough for run-as-node entry points.
void InstallEasrBuildPolicy();
#endif  // BUILDFLAG(ENABLE_EASR_V2)

#if BUILDFLAG(ENABLE_EASR_V2)
// Test-only process-wide EASR materialized-file registry controls. The
// registry owns authenticated plaintext paths because those paths can outlive
// the Archive that produced them. Ordinary ASAR never uses this registry.
size_t GetRetainedExternalFileCountForTesting();
uint64_t GetRetainedExternalFileBytesForTesting();
void ClearRetainedExternalFilesForTesting();
void SetEasrSingleFileMaterializationLimitForTesting(uint64_t byte_limit);
void ResetEasrSingleFileMaterializationLimitForTesting();
void SetEasrExternalFileDeleteFailureForTesting(bool fail);

// Test-only process-wide authenticated chunk-cache budget controls.
size_t GetEasrGlobalChunkCacheBytesForTesting();
void SetEasrGlobalChunkCacheByteLimitForTesting(size_t byte_limit);
void ResetEasrGlobalChunkCacheByteLimitForTesting();
#endif

class ScopedTemporaryFile;
#if BUILDFLAG(ENABLE_EASR_V2)
class EasrV2Reader;
#endif

enum HashAlgorithm {
  SHA256,
  NONE,
};

struct IntegrityPayload {
  IntegrityPayload();
  ~IntegrityPayload();
  IntegrityPayload(const IntegrityPayload& other);
  HashAlgorithm algorithm;
  std::string hash;
  uint32_t block_size;
  std::vector<std::string> blocks;
};

// This class represents an asar package, and provides methods to read
// information from it. It is thread-safe after |Init| has been called.
class Archive {
 public:
  enum class Error {
    kNone = 0,
    kNotFound,
    kIo,
    kInvalidArchive,
#if BUILDFLAG(ENABLE_EASR_V2)
    kEncryptedArchiveRequired,
    kLegacyVersion,
    kUnsupportedVersion,
    kMalformedSuperblock,
    kUnknownSigningKey,
    kSigningKeyIdMismatch,
    kInvalidSignature,
    kRollback,
    kArchiveSize,
    kIndexHash,
    kMalformedIndex,
    kUnknownDataKey,
    kDataKeyIdMismatch,
    kAuthentication,
    kDecompression,
    kUnpackedAuthentication,
#endif
    kInvalidRange,
    kResourceExhausted,
  };

#if BUILDFLAG(ENABLE_EASR_V2)
  struct EasrChunkCacheStats {
    uint64_t hits = 0;
    uint64_t misses = 0;
    uint64_t coalesced = 0;
    uint64_t evictions = 0;
    uint64_t cleansed_bytes = 0;
    size_t entries = 0;
    size_t bytes = 0;
  };
#endif

  struct FileInfo {
    FileInfo();
    ~FileInfo();
    FileInfo(const FileInfo& other);
    FileInfo& operator=(const FileInfo& other);
    bool unpacked;
    bool executable;
    uint64_t size;
#if BUILDFLAG(ENABLE_EASR_V2)
    uint64_t packed_size;
#endif
    uint64_t offset;
#if BUILDFLAG(ENABLE_EASR_V2)
    // Internal authenticated entry handle. Callers must treat it as opaque.
    uint32_t easr_entry;
#endif
    absl::optional<IntegrityPayload> integrity;
  };

  struct Stats : public FileInfo {
    Stats() : is_file(true), is_directory(false), is_link(false) {}
    bool is_file;
    bool is_directory;
    bool is_link;
  };

  explicit Archive(const base::FilePath& path);
  virtual ~Archive();

  // disable copy
  Archive(const Archive&) = delete;
  Archive& operator=(const Archive&) = delete;

  // Read and parse the header.
  bool Init();

  Error init_error() const { return init_error_; }

  absl::optional<IntegrityPayload> HeaderIntegrity() const;
  absl::optional<base::FilePath> RelativePath() const;

  // Get the info of a file.
  bool GetFileInfo(const base::FilePath& path, FileInfo* info) const;

  // Fs.stat(path).
  bool Stat(const base::FilePath& path, Stats* stats) const;

  // Fs.readdir(path).
  bool Readdir(const base::FilePath& path,
               std::vector<base::FilePath>* files) const;

  // Fs.realpath(path).
  bool Realpath(const base::FilePath& path, base::FilePath* realpath) const;

  // Copy the file into a temporary file, and return the new path.
  // For unpacked file, this method will return its real path.
  bool CopyFileOut(const base::FilePath& path,
                   base::FilePath* out,
                   Error* error = nullptr);

  // Reads a file out of the archive. Encrypted archives return plaintext.
  bool ReadFile(const base::FilePath& path,
                std::string* contents,
                Error* error = nullptr);
  bool ReadFile(const base::FilePath& path,
                std::string* contents,
                uint64_t max_size,
                Error* error);

  // Reads a byte range from the file described by |info|. |offset| is relative
  // to the file, not the archive.
  bool ReadRange(const FileInfo& info,
                 uint64_t offset,
                 size_t size,
                 std::string* contents,
                 Error* error = nullptr);
  bool ReadRange(const FileInfo& info,
                 uint64_t offset,
                 base::span<char> contents,
                 Error* error = nullptr);

  // Returns the file's fd.
  // Using this fd will not validate the integrity of any files
  // you read out of the ASAR manually.  Callers are responsible
  // for integrity validation after this fd is handed over.
  int GetUnsafeFD() const;

#if BUILDFLAG(ENABLE_EASR_V2)
  bool is_encrypted() const { return encrypted_; }
#else
  bool is_encrypted() const { return false; }
#endif
  base::FilePath path() const { return path_; }

#if BUILDFLAG(ENABLE_EASR_V2)
  // Test-only observability and limit injection. These are deliberately not
  // exposed through the JavaScript binding.
  void SetEasrChunkCacheLimitsForTesting(size_t byte_limit, size_t chunk_limit);
  EasrChunkCacheStats GetEasrChunkCacheStatsForTesting() const;
  void ClearEasrChunkCacheForTesting();
  size_t GetEasrExternalFileSlotCountForTesting();
#endif

 private:
#if BUILDFLAG(ENABLE_EASR_V2)
  // The resolved entry id is authenticated by the signed EASR index. Keep the
  // extension in the key because native loaders can require a specific suffix.
  struct EasrExternalFileKey {
    uint32_t easr_entry = 0;
    base::FilePath::StringType entry_extension;

    bool operator==(const EasrExternalFileKey& other) const {
      return easr_entry == other.easr_entry &&
             entry_extension == other.entry_extension;
    }
  };

  struct EasrExternalFileKeyHash {
    size_t operator()(const EasrExternalFileKey& key) const {
      const size_t entry_hash = std::hash<uint32_t>{}(key.easr_entry);
      const size_t extension_hash =
          std::hash<base::FilePath::StringType>{}(key.entry_extension);
      return entry_hash ^ (extension_hash + static_cast<size_t>(0x9e3779b9U) +
                           (entry_hash << 6) + (entry_hash >> 2));
    }
  };

  struct PendingExternalFile;
#endif

  bool InitStandard(const std::array<char, 8>* prefix = nullptr);
#if BUILDFLAG(ENABLE_EASR_V2)
  bool InitEncryptedV2(base::span<const uint8_t> superblock);
#endif

  bool initialized_;
  bool header_validated_ = false;
#if BUILDFLAG(ENABLE_EASR_V2)
  bool encrypted_ = false;
#endif
  Error init_error_ = Error::kNone;
  const base::FilePath path_;
  base::File file_;
  int fd_ = -1;
  uint32_t header_size_ = 0;
#if BUILDFLAG(ENABLE_EASR_V2)
  std::unique_ptr<EasrV2Reader> easr_v2_;
#endif
  absl::optional<base::Value::Dict> header_;

  // Cached external temporary files.
  base::Lock external_files_lock_;
#if BUILDFLAG(ENABLE_EASR_V2)
  // Paths escape this object without a lifetime token (for example dlopen),
  // so entries are admission-bounded rather than evicted while callers may
  // still be using them. Aliases of one authenticated entry share a slot when
  // their required output extension is the same.
  static constexpr size_t kMaxEasrExternalFiles = 32;
  std::unordered_map<EasrExternalFileKey,
                     base::FilePath,
                     EasrExternalFileKeyHash>
      easr_external_files_;
  std::unordered_map<EasrExternalFileKey,
                     std::shared_ptr<PendingExternalFile>,
                     EasrExternalFileKeyHash>
      pending_external_files_;
#endif
  // Ordinary materializations are owned process-wide because returned paths
  // may outlive this Archive. This per-Archive map only avoids duplicate work;
  // it is intentionally unbounded and never participates in EASR admission.
  std::unordered_map<base::FilePath::StringType, base::FilePath>
      external_files_;
};

// Stable machine-readable error identifier used by the internal Node binding.
const char* ArchiveErrorName(Archive::Error error);

}  // namespace asar

#endif  // ELECTRON_SHELL_COMMON_ASAR_ARCHIVE_H_
