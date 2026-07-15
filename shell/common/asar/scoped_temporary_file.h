// Copyright (c) 2014 GitHub, Inc.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#ifndef ELECTRON_SHELL_COMMON_ASAR_SCOPED_TEMPORARY_FILE_H_
#define ELECTRON_SHELL_COMMON_ASAR_SCOPED_TEMPORARY_FILE_H_

#include "base/files/file_path.h"
#include "shell/common/asar/archive.h"
#include "third_party/abseil-cpp/absl/types/optional.h"

namespace base {
class File;
}

namespace asar {

#if BUILDFLAG(ENABLE_EASR_V2)
// Creates the private per-process materialization directory and reclaims stale
// directories left by processes that bypassed AtExit.
bool PrepareTemporaryFileDirectory();

// Test controls for isolating the process-global directory and exercising
// concurrent stale-session reclamation. Callers must not hold materialized
// files while resetting the state.
void ResetTemporaryFileDirectoryForTesting();
bool CleanupStaleTemporaryDirectoriesForTesting(const base::FilePath& parent);
bool IsTemporaryLeasePrivateForTesting();
#endif

// An object representing a temporary file that should be cleaned up when this
// object goes out of scope.  Note that since deletion occurs during the
// destructor, no further error handling is possible if the directory fails to
// be deleted.  As a result, deletion is not guaranteed by this class.
class ScopedTemporaryFile {
 public:
  ScopedTemporaryFile();
  ScopedTemporaryFile(const ScopedTemporaryFile&) = delete;
  ScopedTemporaryFile& operator=(const ScopedTemporaryFile&) = delete;
  virtual ~ScopedTemporaryFile();

  // Init an empty temporary file with a certain extension.
  bool Init(const base::FilePath::StringType& ext);

#if BUILDFLAG(ENABLE_EASR_V2)
  // Atomically creates the final temporary path and returns its still-open
  // private handle. This avoids a create/reopen replacement window while
  // authenticated bytes are being materialized. The caller must close the
  // handle before exposing path().
  bool InitForWrite(const base::FilePath::StringType& ext, base::File* file);
#endif

  // Init an temporary file and fill it with content of |path|.
  bool InitFromFile(base::File* src,
                    const base::FilePath::StringType& ext,
                    uint64_t offset,
                    uint64_t size,
                    const absl::optional<IntegrityPayload>& integrity);

#if BUILDFLAG(ENABLE_EASR_V2)
  // Failure-only cleanup for files that have never been published. Writers
  // must cleanse/truncate through their original handle before calling this;
  // this method never reopens a path that an attacker could have replaced.
  bool DeleteNow();
#endif

  base::FilePath path() const { return path_; }

 private:
  base::FilePath path_;
};

}  // namespace asar

#endif  // ELECTRON_SHELL_COMMON_ASAR_SCOPED_TEMPORARY_FILE_H_
