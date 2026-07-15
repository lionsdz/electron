// Copyright (c) 2015 GitHub, Inc.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#include "shell/common/asar/asar_util.h"

#include <cstdint>
#include <iterator>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/at_exit.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/no_destructor.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread_restrictions.h"
#include "base/time/time.h"
#include "crypto/secure_hash.h"
#include "crypto/sha2.h"
#include "shell/common/asar/archive.h"
#include "shell/common/asar/scoped_temporary_file.h"

namespace asar {

namespace {

const base::FilePath::CharType kAsarExtension[] = FILE_PATH_LITERAL(".asar");
constexpr size_t kArchiveCacheLimit = 32;
constexpr size_t kDirectoryCacheLimit = 256;
constexpr base::TimeDelta kDirectoryCacheTtl = base::Seconds(1);

struct ArchiveCacheEntry {
  std::shared_ptr<Archive> archive;
  std::list<base::FilePath>::iterator lru;
};

struct PendingArchive {
  explicit PendingArchive(uint64_t cache_generation)
      : generation(cache_generation),
        ready(base::WaitableEvent::ResetPolicy::MANUAL,
              base::WaitableEvent::InitialState::NOT_SIGNALED) {}

  const uint64_t generation;
  base::WaitableEvent ready;
  std::shared_ptr<Archive> archive;
  Archive::Error error = Archive::Error::kIo;
};

struct ArchiveCache {
  base::Lock lock;
  std::map<base::FilePath, ArchiveCacheEntry> entries;
  std::list<base::FilePath> lru;
  std::map<base::FilePath, std::shared_ptr<PendingArchive>> pending;
  // CopyFileOut exposes bare paths that native loaders may keep after their
  // Archive is evicted. This is ownership only: no lookup, deduplication, or
  // admission limit is applied to ordinary ASAR materializations.
  std::vector<std::unique_ptr<ScopedTemporaryFile>> ordinary_external_files;
  bool ordinary_external_files_cleanup_registered = false;
  uint64_t generation = 0;
};

ArchiveCache& GetArchiveCache() {
  static base::NoDestructor<ArchiveCache> cache;
  return *cache;
}

void CleanupOrdinaryExternalFiles(void* opaque) {
  auto* cache = static_cast<ArchiveCache*>(opaque);
  std::vector<std::unique_ptr<ScopedTemporaryFile>> files;
  {
    base::AutoLock auto_lock(cache->lock);
    files.swap(cache->ordinary_external_files);
  }
}

struct DirectoryCacheEntry {
  bool is_directory;
  base::TimeTicks checked_at;
  std::list<base::FilePath>::iterator lru;
};

struct DirectoryCache {
  base::Lock lock;
  std::map<base::FilePath, DirectoryCacheEntry> entries;
  std::list<base::FilePath> lru;
};

DirectoryCache& GetDirectoryCache() {
  static base::NoDestructor<DirectoryCache> cache;
  return *cache;
}

bool IsDirectoryCached(const base::FilePath& path) {
  DirectoryCache& cache = GetDirectoryCache();
  const base::TimeTicks now = base::TimeTicks::Now();
  {
    base::AutoLock auto_lock(cache.lock);
    auto found = cache.entries.find(path);
    if (found != cache.entries.end()) {
      if (now - found->second.checked_at <= kDirectoryCacheTtl) {
        cache.lru.splice(cache.lru.end(), cache.lru, found->second.lru);
        return found->second.is_directory;
      }
      cache.lru.erase(found->second.lru);
      cache.entries.erase(found);
    }
  }

  base::ThreadRestrictions::ScopedAllowIO allow_io;
  const bool is_directory = base::DirectoryExists(path);
  {
    base::AutoLock auto_lock(cache.lock);
    auto found = cache.entries.find(path);
    if (found != cache.entries.end()) {
      cache.lru.splice(cache.lru.end(), cache.lru, found->second.lru);
      return found->second.is_directory;
    }
    while (cache.entries.size() >= kDirectoryCacheLimit) {
      cache.entries.erase(cache.lru.front());
      cache.lru.pop_front();
    }
    cache.lru.push_back(path);
    cache.entries.emplace(
        path, DirectoryCacheEntry{is_directory, base::TimeTicks::Now(),
                                  std::prev(cache.lru.end())});
  }
  return is_directory;
}

}  // namespace

std::shared_ptr<Archive> GetOrCreateAsarArchive(const base::FilePath& path,
                                                Archive::Error* error) {
  ArchiveCache& cache = GetArchiveCache();
  std::shared_ptr<PendingArchive> pending;
  bool is_loader = false;
  {
    base::AutoLock auto_lock(cache.lock);
    auto cached = cache.entries.find(path);
    if (cached != cache.entries.end()) {
      cache.lru.splice(cache.lru.end(), cache.lru, cached->second.lru);
      if (error)
        *error = Archive::Error::kNone;
      return cached->second.archive;
    }
    auto loading = cache.pending.find(path);
    if (loading != cache.pending.end()) {
      pending = loading->second;
    } else {
      pending = std::make_shared<PendingArchive>(cache.generation);
      cache.pending.emplace(path, pending);
      is_loader = true;
    }
  }

  if (!is_loader) {
    pending->ready.Wait();
    if (error)
      *error = pending->error;
    return pending->archive;
  }

  // Archive parsing and signature verification can block on I/O. Do not hold
  // the global cache lock or serialize unrelated archive opens while doing it.
  auto archive = std::make_shared<Archive>(path);
  const bool initialized = archive->Init();
  const Archive::Error init_error =
      initialized ? Archive::Error::kNone : archive->init_error();
  {
    base::AutoLock auto_lock(cache.lock);
    cache.pending.erase(path);
    if (initialized && pending->generation == cache.generation) {
      while (cache.entries.size() >= kArchiveCacheLimit) {
        cache.entries.erase(cache.lru.front());
        cache.lru.pop_front();
      }
      cache.lru.push_back(path);
      cache.entries.emplace(
          path, ArchiveCacheEntry{archive, std::prev(cache.lru.end())});
    }
    pending->archive = initialized ? archive : nullptr;
    pending->error = init_error;
  }
  pending->ready.Signal();

  if (error)
    *error = init_error;
  return initialized ? archive : nullptr;
}

void ClearArchives() {
  ArchiveCache& cache = GetArchiveCache();
  base::AutoLock auto_lock(cache.lock);
  ++cache.generation;
  cache.entries.clear();
  cache.lru.clear();
}

void RetainOrdinaryAsarTemporaryFile(
    std::unique_ptr<ScopedTemporaryFile> file) {
  ArchiveCache& cache = GetArchiveCache();
  base::AutoLock auto_lock(cache.lock);
  if (!cache.ordinary_external_files_cleanup_registered) {
    base::AtExitManager::RegisterCallback(&CleanupOrdinaryExternalFiles,
                                          &cache);
    cache.ordinary_external_files_cleanup_registered = true;
  }
  cache.ordinary_external_files.push_back(std::move(file));
}

size_t GetArchiveCacheSizeForTesting() {
  ArchiveCache& cache = GetArchiveCache();
  base::AutoLock auto_lock(cache.lock);
  return cache.entries.size();
}

size_t GetDirectoryCacheSizeForTesting() {
  DirectoryCache& cache = GetDirectoryCache();
  base::AutoLock auto_lock(cache.lock);
  return cache.entries.size();
}

bool GetAsarArchivePath(const base::FilePath& full_path,
                        base::FilePath* asar_path,
                        base::FilePath* relative_path,
                        bool allow_root) {
  base::FilePath iter = full_path;
  while (true) {
    base::FilePath dirname = iter.DirName();
    if (iter.MatchesExtension(kAsarExtension) && !IsDirectoryCached(iter))
      break;
    else if (iter == dirname)
      return false;
    iter = dirname;
  }

  base::FilePath tail;
  if (!((allow_root && iter == full_path) ||
        iter.AppendRelativePath(full_path, &tail)))
    return false;

  *asar_path = iter;
  *relative_path = tail;
  return true;
}

bool ReadFileToString(const base::FilePath& path, std::string* contents) {
  base::FilePath asar_path, relative_path;
  if (!GetAsarArchivePath(path, &asar_path, &relative_path))
    return base::ReadFileToString(path, contents);

  std::shared_ptr<Archive> archive = GetOrCreateAsarArchive(asar_path);
  if (!archive)
    return false;

  Archive::FileInfo info;
  if (!archive->GetFileInfo(relative_path, &info))
    return false;

#if BUILDFLAG(ENABLE_EASR_V2)
  if (archive->is_encrypted())
    return archive->ReadFile(relative_path, contents);
#endif

  if (info.unpacked) {
    base::FilePath real_path;
    // For unpacked file it will return the real path instead of doing the copy.
    archive->CopyFileOut(relative_path, &real_path);
    return base::ReadFileToString(real_path, contents);
  }

  base::File src(asar_path, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!src.IsValid())
    return false;

  if (info.size > static_cast<uint64_t>(std::numeric_limits<int>::max()))
    return false;
  contents->resize(static_cast<size_t>(info.size));
  if (static_cast<int>(info.size) !=
      src.Read(info.offset, const_cast<char*>(contents->data()),
               static_cast<int>(contents->size()))) {
    return false;
  }

  if (info.integrity.has_value()) {
    ValidateIntegrityOrDie(contents->data(), contents->size(),
                           info.integrity.value());
  }

  return true;
}

void ValidateIntegrityOrDie(const char* data,
                            size_t size,
                            const IntegrityPayload& integrity) {
  if (integrity.algorithm == HashAlgorithm::SHA256) {
    uint8_t hash[crypto::kSHA256Length];
    auto hasher = crypto::SecureHash::Create(crypto::SecureHash::SHA256);
    hasher->Update(data, size);
    hasher->Finish(hash, sizeof(hash));
    ValidateIntegrityDigestOrDie(base::make_span(hash), integrity);
  } else {
    LOG(FATAL) << "Unsupported hashing algorithm in ValidateIntegrityOrDie";
  }
}

void ValidateIntegrityDigestOrDie(base::span<const uint8_t> digest,
                                  const IntegrityPayload& integrity) {
  if (integrity.algorithm != HashAlgorithm::SHA256 ||
      digest.size() != crypto::kSHA256Length) {
    LOG(FATAL) << "Unsupported hashing algorithm or digest size in "
                  "ValidateIntegrityDigestOrDie";
  }
  const std::string hex_hash =
      base::ToLowerASCII(base::HexEncode(digest.data(), digest.size()));
  if (integrity.hash != hex_hash) {
    LOG(FATAL) << "Integrity check failed for asar archive (" << integrity.hash
               << " vs " << hex_hash << ")";
  }
}

}  // namespace asar
