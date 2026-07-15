// Copyright (c) 2015 GitHub, Inc.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#ifndef ELECTRON_SHELL_COMMON_ASAR_ASAR_UTIL_H_
#define ELECTRON_SHELL_COMMON_ASAR_ASAR_UTIL_H_

#include <cstddef>
#include <memory>
#include <string>

#include "base/containers/span.h"
#include "shell/common/asar/archive.h"

namespace base {
class FilePath;
}

namespace asar {

struct IntegrityPayload;
class ScopedTemporaryFile;

// Gets or creates and caches a new Archive from the path.
std::shared_ptr<Archive> GetOrCreateAsarArchive(
    const base::FilePath& path,
    Archive::Error* error = nullptr);

// Destroy cached Archive objects.
void ClearArchives();

// Keeps an ordinary ASAR materialization alive for the rest of the process.
// Returned paths have no lifetime token, so Archive cache eviction must not
// delete them. This owner intentionally does not deduplicate or impose EASR's
// materialization limits.
void RetainOrdinaryAsarTemporaryFile(std::unique_ptr<ScopedTemporaryFile> file);

size_t GetArchiveCacheSizeForTesting();
size_t GetDirectoryCacheSizeForTesting();

// Separates the path to Archive out.
bool GetAsarArchivePath(const base::FilePath& full_path,
                        base::FilePath* asar_path,
                        base::FilePath* relative_path,
                        bool allow_root = false);

// Same with base::ReadFileToString but supports asar Archive.
bool ReadFileToString(const base::FilePath& path, std::string* contents);

void ValidateIntegrityOrDie(const char* data,
                            size_t size,
                            const IntegrityPayload& integrity);
void ValidateIntegrityDigestOrDie(base::span<const uint8_t> digest,
                                  const IntegrityPayload& integrity);

}  // namespace asar

#endif  // ELECTRON_SHELL_COMMON_ASAR_ASAR_UTIL_H_
