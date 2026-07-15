// Copyright (c) 2026 Electron authors.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#ifndef ELECTRON_SHELL_COMMON_ASAR_EASAR_V2_H_
#define ELECTRON_SHELL_COMMON_ASAR_EASAR_V2_H_

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "shell/common/asar/archive.h"

namespace base {
class File;
}

namespace asar {

// Verified, immutable EASR v2 metadata and per-archive crypto state. The
// implementation deliberately remains private to the ASAR runtime.
class EasrV2Reader {
 public:
  class State;

  static std::unique_ptr<EasrV2Reader> Create(
      base::File* file,
      const base::FilePath& archive_path,
      const EasrKeyProvider* key_provider,
      base::span<const uint8_t> superblock,
      Archive::Error* error);

  EasrV2Reader(const EasrV2Reader&) = delete;
  EasrV2Reader& operator=(const EasrV2Reader&) = delete;
  ~EasrV2Reader();

  bool GetFileInfo(const base::FilePath& path, Archive::FileInfo* info) const;
  bool Stat(const base::FilePath& path, Archive::Stats* stats) const;
  bool Readdir(const base::FilePath& path,
               std::vector<base::FilePath>* files) const;
  bool Realpath(const base::FilePath& path, base::FilePath* realpath) const;

  bool ReadFile(base::File* file,
                const base::FilePath& path,
                std::string* contents,
                Archive::Error* error) const;
  bool ReadRange(base::File* file,
                 const Archive::FileInfo& info,
                 uint64_t offset,
                 size_t size,
                 std::string* contents,
                 Archive::Error* error) const;
  bool ReadRange(base::File* file,
                 const Archive::FileInfo& info,
                 uint64_t offset,
                 base::span<char> contents,
                 Archive::Error* error) const;

  // Streams authenticated plaintext into an embedder-owned private file. For
  // unpacked entries the digest is finalized before the caller exposes the
  // destination, eliminating a verify-then-reopen race.
  bool CopyFileTo(base::File* archive_file,
                  const Archive::FileInfo& info,
                  base::File* destination,
                  Archive::Error* error) const;

  // SHA-256 of the fixed signed superblock, used to bind a packaged archive
  // to the macOS ElectronAsarIntegrity entry without re-reading its index.
  const std::array<uint8_t, 32>& header_digest() const;

  void SetChunkCacheLimitsForTesting(size_t byte_limit, size_t chunk_limit);
  Archive::EasrChunkCacheStats GetChunkCacheStatsForTesting() const;
  void ClearChunkCacheForTesting();

 private:
  explicit EasrV2Reader(std::unique_ptr<State> state);

  std::unique_ptr<State> state_;
};

}  // namespace asar

#endif  // ELECTRON_SHELL_COMMON_ASAR_EASAR_V2_H_
