// Copyright (c) 2014 GitHub, Inc.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#include "shell/common/asar/scoped_temporary_file.h"

#include <algorithm>
#include <array>
#include <limits>
#include <vector>

#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/threading/thread_restrictions.h"
#include "shell/common/asar/asar_util.h"

#if BUILDFLAG(ENABLE_EASR_V2)
#include <cstddef>
#include <cstring>
#include <string>

#include "base/at_exit.h"
#include "base/files/file_enumerator.h"
#include "base/guid.h"
#include "base/no_destructor.h"
#include "base/process/process.h"
#include "base/process/process_handle.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/synchronization/lock.h"
#include "base/time/time.h"
#include "crypto/secure_hash.h"
#include "crypto/sha2.h"

#if BUILDFLAG(IS_POSIX)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/posix/eintr_wrapper.h"
#endif

#if BUILDFLAG(IS_WIN)
#include <aclapi.h>
#include <sddl.h>
#include <windows.h>

#include "base/strings/utf_string_conversions.h"
#include "base/win/scoped_handle.h"
#include "base/win/scoped_localalloc.h"
#include "base/win/win_util.h"
#endif
#endif  // BUILDFLAG(ENABLE_EASR_V2)

namespace asar {

namespace {

#if BUILDFLAG(ENABLE_EASR_V2)
constexpr char kTemporaryParentPrefix[] = "electron-easar-v2";
constexpr char kLeaseFileName[] = ".lease";
#if BUILDFLAG(IS_WIN)
constexpr char kClaimFilePrefix[] = ".claim-";
#endif
constexpr char kMaterializedFilePrefix[] = "easar-";
constexpr base::TimeDelta kUnopenableProcessCleanupAge = base::Minutes(5);

struct TemporaryDirectoryState {
  base::Lock lock;
  base::FilePath path;
  base::File lease_file;
};

TemporaryDirectoryState& GetTemporaryDirectoryState() {
  static base::NoDestructor<TemporaryDirectoryState> state;
  return *state;
}

bool ParseSessionDirectory(const base::FilePath& path,
                           base::ProcessId* pid,
                           int64_t* creation_time) {
  const std::vector<std::string> parts =
      base::SplitString(path.BaseName().AsUTF8Unsafe(), "-",
                        base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  const auto is_hex = [](const std::string& value, size_t length) {
    return value.size() == length &&
           std::all_of(value.begin(), value.end(), [](char character) {
             return (character >= '0' && character <= '9') ||
                    (character >= 'a' && character <= 'f') ||
                    (character >= 'A' && character <= 'F');
           });
  };
#if BUILDFLAG(IS_WIN)
  const bool valid_suffix =
      (parts.size() == 3 && is_hex(parts[2], 32)) ||
      (parts.size() == 7 && is_hex(parts[2], 8) && is_hex(parts[3], 4) &&
       is_hex(parts[4], 4) && is_hex(parts[5], 4) && is_hex(parts[6], 12));
#else
  const bool valid_suffix = parts.size() == 3 && !parts[2].empty();
#endif
  int parsed_pid = 0;
  return valid_suffix && parts[0].size() > 1 && parts[0][0] == 'p' &&
         parts[1].size() > 1 && parts[1][0] == 't' &&
         base::StringToInt(parts[0].substr(1), &parsed_pid) && parsed_pid > 0 &&
         base::StringToInt64(parts[1].substr(1), creation_time) &&
         (*pid = static_cast<base::ProcessId>(parsed_pid), true);
}

bool GetUserScopedParentName(std::string* name) {
  if (!name)
    return false;
#if BUILDFLAG(IS_WIN)
  std::wstring user_sid;
  if (!base::win::GetUserSidString(&user_sid))
    return false;
  *name =
      std::string(kTemporaryParentPrefix) + "-" + base::WideToUTF8(user_sid);
#elif BUILDFLAG(IS_POSIX)
  *name = std::string(kTemporaryParentPrefix) + "-" +
          base::NumberToString(geteuid());
#else
  *name = kTemporaryParentPrefix;
#endif
  return true;
}

#if BUILDFLAG(IS_WIN)
constexpr DWORD kDirectoryGuardShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
constexpr DWORD kDirectoryInspectionShareMode =
    kDirectoryGuardShareMode | FILE_SHARE_DELETE;

class WindowsPrivateSecurity {
 public:
  bool Initialize(bool directory) {
    std::wstring user_sid;
    if (!base::win::GetUserSidString(&user_sid))
      return false;
    const wchar_t* inheritance = directory ? L"OICI" : L"";
    const std::wstring sddl = L"O:" + user_sid + L"D:P(A;" + inheritance +
                              L";FA;;;" + user_sid + L")(A;" + inheritance +
                              L";FA;;;SY)(A;" + inheritance + L";FA;;;BA)";
    PSECURITY_DESCRIPTOR raw_descriptor = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &raw_descriptor, nullptr)) {
      return false;
    }
    descriptor_.reset(raw_descriptor);

    BOOL owner_defaulted = FALSE;
    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = FALSE;
    if (!::GetSecurityDescriptorOwner(descriptor_.get(), &owner_,
                                      &owner_defaulted) ||
        !owner_ || !::IsValidSid(owner_) ||
        !::GetSecurityDescriptorDacl(descriptor_.get(), &dacl_present, &dacl_,
                                     &dacl_defaulted) ||
        !dacl_present || !dacl_) {
      return false;
    }
    attributes_ = {sizeof(SECURITY_ATTRIBUTES), descriptor_.get(), FALSE};
    return true;
  }

  SECURITY_ATTRIBUTES* attributes() const {
    return const_cast<SECURITY_ATTRIBUTES*>(&attributes_);
  }
  PSID owner() const { return owner_; }
  PACL dacl() const { return dacl_; }

 private:
  base::win::ScopedLocalAlloc descriptor_;
  SECURITY_ATTRIBUTES attributes_{};
  PSID owner_ = nullptr;
  PACL dacl_ = nullptr;
};

struct WindowsPrivateSecurityPair {
  WindowsPrivateSecurityPair() {
    valid = directory.Initialize(true) && file.Initialize(false);
  }

  WindowsPrivateSecurity directory;
  WindowsPrivateSecurity file;
  bool valid = false;
};

const WindowsPrivateSecurity* GetWindowsPrivateSecurity(bool directory) {
  static base::NoDestructor<WindowsPrivateSecurityPair> security;
  if (!security->valid)
    return nullptr;
  return directory ? &security->directory : &security->file;
}

PSID GetSimpleAllowedAceSid(const ACE_HEADER* header) {
  constexpr size_t kSidHeaderSize = 8;
  constexpr size_t kSidOffset = offsetof(ACCESS_ALLOWED_ACE, SidStart);
  if (!header || header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
      header->AceSize < kSidOffset + kSidHeaderSize) {
    return nullptr;
  }
  const uint8_t* begin = reinterpret_cast<const uint8_t*>(header);
  const uint8_t* sid_bytes = begin + kSidOffset;
  const size_t sid_size =
      kSidHeaderSize + static_cast<size_t>(sid_bytes[1]) * sizeof(DWORD);
  if (sid_size != header->AceSize - kSidOffset)
    return nullptr;
  PSID sid = const_cast<uint8_t*>(sid_bytes);
  return ::IsValidSid(sid) ? sid : nullptr;
}

bool PrivateDaclsMatch(PACL actual, PACL expected) {
  if (!actual || !expected || actual->AceCount != expected->AceCount ||
      expected->AceCount != 3) {
    return false;
  }
  std::array<bool, 3> matched{};
  for (DWORD actual_index = 0; actual_index < actual->AceCount;
       ++actual_index) {
    void* raw_actual = nullptr;
    if (!::GetAce(actual, actual_index, &raw_actual))
      return false;
    const auto* actual_header = static_cast<const ACE_HEADER*>(raw_actual);
    const auto* actual_ace =
        reinterpret_cast<const ACCESS_ALLOWED_ACE*>(actual_header);
    const PSID actual_sid = GetSimpleAllowedAceSid(actual_header);
    if (!actual_sid)
      return false;

    bool found = false;
    for (DWORD expected_index = 0; expected_index < expected->AceCount;
         ++expected_index) {
      if (matched[expected_index])
        continue;
      void* raw_expected = nullptr;
      if (!::GetAce(expected, expected_index, &raw_expected))
        return false;
      const auto* expected_header =
          static_cast<const ACE_HEADER*>(raw_expected);
      const auto* expected_ace =
          reinterpret_cast<const ACCESS_ALLOWED_ACE*>(expected_header);
      const PSID expected_sid = GetSimpleAllowedAceSid(expected_header);
      if (expected_sid &&
          actual_header->AceFlags == expected_header->AceFlags &&
          actual_ace->Mask == expected_ace->Mask &&
          ::EqualSid(actual_sid, expected_sid)) {
        matched[expected_index] = true;
        found = true;
        break;
      }
    }
    if (!found)
      return false;
  }
  return true;
}

bool IsExpectedWindowsObject(HANDLE handle, bool directory) {
  BY_HANDLE_FILE_INFORMATION info = {};
  return handle && handle != INVALID_HANDLE_VALUE &&
         ::GetFileType(handle) == FILE_TYPE_DISK &&
         ::GetFileInformationByHandle(handle, &info) &&
         static_cast<bool>(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ==
             directory &&
         !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
}

bool VerifyPrivateWindowsObject(HANDLE handle,
                                bool directory,
                                const WindowsPrivateSecurity& security,
                                bool verify_dacl) {
  if (!IsExpectedWindowsObject(handle, directory))
    return false;

  PSID owner = nullptr;
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR raw_descriptor = nullptr;
  SECURITY_INFORMATION information = OWNER_SECURITY_INFORMATION;
  if (verify_dacl)
    information |= DACL_SECURITY_INFORMATION;
  if (::GetSecurityInfo(handle, SE_FILE_OBJECT, information, &owner, nullptr,
                        verify_dacl ? &dacl : nullptr, nullptr,
                        &raw_descriptor) != ERROR_SUCCESS) {
    return false;
  }
  base::win::ScopedLocalAlloc descriptor(raw_descriptor);
  if (!owner || !::EqualSid(owner, security.owner()))
    return false;
  if (!verify_dacl)
    return true;

  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  return ::GetSecurityDescriptorControl(descriptor.get(), &control,
                                        &revision) &&
         (control & SE_DACL_PROTECTED) &&
         PrivateDaclsMatch(dacl, security.dacl());
}

bool HardenPrivateWindowsHandle(HANDLE handle,
                                bool directory,
                                const WindowsPrivateSecurity& security) {
  if (!VerifyPrivateWindowsObject(handle, directory, security, false))
    return false;
  if (::SetSecurityInfo(
          handle, SE_FILE_OBJECT,
          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
          nullptr, nullptr, security.dacl(), nullptr) != ERROR_SUCCESS) {
    return false;
  }
  return VerifyPrivateWindowsObject(handle, directory, security, true);
}

bool MarkWindowsHandleForDeletion(HANDLE handle) {
  FILE_DISPOSITION_INFO disposition = {};
  disposition.DeleteFile = TRUE;
  return ::SetFileInformationByHandle(handle, FileDispositionInfo, &disposition,
                                      sizeof(disposition));
}

base::win::ScopedHandle OpenPrivateWindowsDirectory(
    const base::FilePath& path,
    const WindowsPrivateSecurity& security,
    bool harden,
    DWORD data_access,
    DWORD share_mode) {
  base::win::ScopedHandle handle(::CreateFileW(
      path.value().c_str(),
      READ_CONTROL | (harden ? WRITE_DAC : 0) | data_access, share_mode,
      nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (!handle.is_valid())
    return base::win::ScopedHandle();
  const bool valid =
      harden ? HardenPrivateWindowsHandle(handle.get(), true, security)
             : VerifyPrivateWindowsObject(handle.get(), true, security, true);
  if (!valid)
    return base::win::ScopedHandle();
  return handle;
}

bool CreateOrSecurePrivateWindowsDirectory(
    const base::FilePath& path,
    const WindowsPrivateSecurity& security,
    base::win::ScopedHandle* retained_handle) {
  if (!retained_handle)
    return false;
  if (!::CreateDirectoryW(path.value().c_str(), security.attributes())) {
    const DWORD error = ::GetLastError();
    if (error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS)
      return false;
  }
  base::win::ScopedHandle handle = OpenPrivateWindowsDirectory(
      path, security, true, 0, kDirectoryGuardShareMode);
  if (!handle.is_valid())
    return false;
  *retained_handle = std::move(handle);
  return true;
}

bool CreatePrivateWindowsDirectory(const base::FilePath& path,
                                   const WindowsPrivateSecurity& security,
                                   base::win::ScopedHandle* retained_handle) {
  if (!retained_handle) {
    ::SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }
  if (!::CreateDirectoryW(path.value().c_str(), security.attributes())) {
    return false;
  }
  base::win::ScopedHandle handle(::CreateFileW(
      path.value().c_str(), READ_CONTROL | DELETE,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (!handle.is_valid() ||
      !VerifyPrivateWindowsObject(handle.get(), true, security, true)) {
    if (handle.is_valid())
      MarkWindowsHandleForDeletion(handle.get());
    ::SetLastError(ERROR_ACCESS_DENIED);
    return false;
  }
  *retained_handle = std::move(handle);
  return true;
}

bool RenameWindowsHandle(HANDLE handle, const base::FilePath& destination) {
  const size_t name_bytes = destination.value().size() * sizeof(wchar_t);
  const size_t total_size = offsetof(FILE_RENAME_INFO, FileName) + name_bytes;
  if (name_bytes == 0 || total_size > std::numeric_limits<DWORD>::max())
    return false;
  base::win::ScopedLocalAlloc storage(::LocalAlloc(LPTR, total_size));
  if (!storage)
    return false;
  auto* rename = static_cast<FILE_RENAME_INFO*>(storage.get());
  rename->ReplaceIfExists = FALSE;
  rename->RootDirectory = nullptr;
  rename->FileNameLength = static_cast<DWORD>(name_bytes);
  memcpy(rename->FileName, destination.value().data(), name_bytes);
  return ::SetFileInformationByHandle(handle, FileRenameInfo, rename,
                                      static_cast<DWORD>(total_size));
}

base::win::ScopedHandle CreatePrivateWindowsFile(
    const base::FilePath& path,
    const WindowsPrivateSecurity& security,
    DWORD data_access) {
  base::win::ScopedHandle handle(::CreateFileW(
      path.value().c_str(), data_access | DELETE | READ_CONTROL | WRITE_DAC, 0,
      security.attributes(), CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (!handle.is_valid())
    return base::win::ScopedHandle();
  if (!VerifyPrivateWindowsObject(handle.get(), false, security, true)) {
    MarkWindowsHandleForDeletion(handle.get());
    ::SetLastError(ERROR_ACCESS_DENIED);
    return base::win::ScopedHandle();
  }
  return handle;
}

base::win::ScopedHandle OpenPrivateWindowsFile(
    const base::FilePath& path,
    const WindowsPrivateSecurity& security,
    DWORD data_access,
    DWORD share_mode,
    bool harden) {
  base::win::ScopedHandle handle(::CreateFileW(
      path.value().c_str(),
      data_access | READ_CONTROL | (harden ? WRITE_DAC : 0), share_mode,
      nullptr, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (!handle.is_valid())
    return base::win::ScopedHandle();
  const bool valid =
      harden ? HardenPrivateWindowsHandle(handle.get(), false, security)
             : VerifyPrivateWindowsObject(handle.get(), false, security, true);
  if (!valid) {
    return base::win::ScopedHandle();
  }
  return handle;
}

bool WindowsPathIsMissing(const base::FilePath& path) {
  const DWORD attributes = ::GetFileAttributesW(path.value().c_str());
  if (attributes != INVALID_FILE_ATTRIBUTES)
    return false;
  const DWORD error = ::GetLastError();
  return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}
#endif

#if !BUILDFLAG(IS_WIN)
bool HardenPrivateDirectory(const base::FilePath& path) {
#if BUILDFLAG(IS_POSIX)
  struct stat info = {};
  if (lstat(path.value().c_str(), &info) != 0 || !S_ISDIR(info.st_mode) ||
      info.st_uid != geteuid()) {
    return false;
  }
  if (!base::SetPosixFilePermissions(path, 0700) ||
      lstat(path.value().c_str(), &info) != 0) {
    return false;
  }
  return S_ISDIR(info.st_mode) && info.st_uid == geteuid() &&
         (info.st_mode & 0777) == 0700;
#else
  return true;
#endif
}
#endif

#if BUILDFLAG(IS_POSIX)
bool CanonicalizeAndValidatePosixTemporaryRoot(base::FilePath* root) {
  if (!root)
    return false;
  const base::FilePath canonical = base::MakeAbsoluteFilePath(*root);
  if (canonical.empty() || !canonical.IsAbsolute())
    return false;

  base::FilePath current;
  for (const auto& component : canonical.GetComponents()) {
    current =
        current.empty() ? base::FilePath(component) : current.Append(component);
    struct stat info = {};
    if (lstat(current.value().c_str(), &info) != 0 || !S_ISDIR(info.st_mode) ||
        (info.st_uid != 0 && info.st_uid != geteuid())) {
      return false;
    }
    const bool shared_writable = (info.st_mode & (S_IWGRP | S_IWOTH)) != 0;
    if (shared_writable && (info.st_mode & S_ISVTX) == 0)
      return false;
  }
  *root = canonical;
  return true;
}

bool IsPrivatePosixFileDescriptor(int descriptor) {
  struct stat info = {};
  return descriptor >= 0 && fstat(descriptor, &info) == 0 &&
         S_ISREG(info.st_mode) && info.st_uid == geteuid() &&
         (info.st_mode & 0777) == 0600;
}

base::File CreatePrivatePosixFile(const base::FilePath& path) {
  const int descriptor = HANDLE_EINTR(
      open(path.value().c_str(),
           O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (descriptor < 0)
    return base::File(base::File::FILE_ERROR_FAILED);
  if (fchmod(descriptor, 0600) != 0 ||
      !IsPrivatePosixFileDescriptor(descriptor)) {
    unlink(path.value().c_str());
    close(descriptor);
    return base::File(base::File::FILE_ERROR_SECURITY);
  }
  return base::File(descriptor);
}

base::File OpenAndHardenPrivatePosixFile(const base::FilePath& path) {
  const int descriptor = HANDLE_EINTR(
      open(path.value().c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  struct stat info = {};
  if (descriptor < 0 || fstat(descriptor, &info) != 0 ||
      !S_ISREG(info.st_mode) || info.st_uid != geteuid() ||
      fchmod(descriptor, 0600) != 0 ||
      !IsPrivatePosixFileDescriptor(descriptor)) {
    if (descriptor >= 0)
      close(descriptor);
    return base::File(base::File::FILE_ERROR_SECURITY);
  }
  return base::File(descriptor);
}
#endif

bool IsExpectedProcessAlive(base::ProcessId pid, int64_t expected_creation) {
  base::Process process = base::Process::Open(pid);
  if (!process.IsValid())
    return false;
  const base::Time creation = process.CreationTime();
  return !creation.is_null() && creation.ToInternalValue() == expected_creation;
}

#if BUILDFLAG(IS_WIN)
constexpr size_t kMaxSessionEntries = 256;

bool MoveClaimedLeaseToParent(const base::FilePath& parent, base::File* lease) {
  if (!lease || !lease->IsValid())
    return false;
  for (size_t attempt = 0; attempt < 100; ++attempt) {
    base::FilePath candidate = parent.AppendASCII(
        std::string(kClaimFilePrefix) + base::GenerateGUID());
    if (RenameWindowsHandle(lease->GetPlatformFile(), candidate))
      return true;
    const DWORD error = ::GetLastError();
    if (error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS)
      return false;
  }
  return false;
}

bool DeleteSessionDirectory(const base::FilePath& parent,
                            const base::FilePath& path,
                            const WindowsPrivateSecurity& directory_security,
                            const WindowsPrivateSecurity& file_security,
                            base::File* claimed_lease) {
  base::win::ScopedHandle session = OpenPrivateWindowsDirectory(
      path, directory_security, false, DELETE, kDirectoryGuardShareMode);
  if (!session.is_valid())
    return false;

  std::vector<base::win::ScopedHandle> materialized_files;
  bool saw_lease = false;
  base::FileEnumerator entries(path, false, base::FileEnumerator::NAMES_ONLY);
  for (base::FilePath entry = entries.Next(); !entry.empty();
       entry = entries.Next()) {
    if (materialized_files.size() >= kMaxSessionEntries)
      return false;
    const std::string name = entry.BaseName().AsUTF8Unsafe();
    if (name == kLeaseFileName) {
      if (!claimed_lease || saw_lease)
        return false;
      saw_lease = true;
      continue;
    }
    if (name.rfind(kMaterializedFilePrefix, 0) != 0)
      return false;
    base::win::ScopedHandle file = OpenPrivateWindowsFile(
        entry, file_security, DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, true);
    if (!file.is_valid())
      return false;
    materialized_files.push_back(std::move(file));
  }
  if (claimed_lease && !saw_lease)
    return false;

  if (claimed_lease && !MoveClaimedLeaseToParent(parent, claimed_lease)) {
    return false;
  }
  if (claimed_lease &&
      !MarkWindowsHandleForDeletion(claimed_lease->GetPlatformFile())) {
    return false;
  }

  for (auto& file : materialized_files) {
    if (!MarkWindowsHandleForDeletion(file.get()))
      return false;
  }
  materialized_files.clear();
  if (!MarkWindowsHandleForDeletion(session.get()))
    return false;
  session.Close();
  return WindowsPathIsMissing(path);
}

void CleanupStaleClaimFiles(const base::FilePath& parent,
                            const WindowsPrivateSecurity& file_security) {
  base::FileEnumerator files(parent, false, base::FileEnumerator::FILES);
  for (base::FilePath path = files.Next(); !path.empty(); path = files.Next()) {
    if (path.BaseName().AsUTF8Unsafe().rfind(kClaimFilePrefix, 0) != 0)
      continue;
    base::win::ScopedHandle handle = OpenPrivateWindowsFile(
        path, file_security, GENERIC_READ | GENERIC_WRITE | DELETE, 0, false);
    if (!handle.is_valid())
      continue;
    base::File claim(std::move(handle));
    if (claim.Lock(base::File::LockMode::kExclusive) == base::File::FILE_OK)
      MarkWindowsHandleForDeletion(claim.GetPlatformFile());
  }
}

bool ClaimAndDeleteStaleSession(
    const base::FilePath& parent,
    const base::FilePath& path,
    const WindowsPrivateSecurity& directory_security,
    const WindowsPrivateSecurity& file_security) {
  base::win::ScopedHandle handle =
      OpenPrivateWindowsFile(path.AppendASCII(kLeaseFileName), file_security,
                             GENERIC_READ | GENERIC_WRITE | DELETE, 0, true);
  if (!handle.is_valid())
    return false;
  base::File lease(std::move(handle));
  if (lease.Lock(base::File::LockMode::kExclusive) != base::File::FILE_OK)
    return false;
  // The lock is intentionally released only when |lease| closes after the
  // verified session directory has been removed.
  return DeleteSessionDirectory(parent, path, directory_security, file_security,
                                &lease);
}

void CleanupStaleSessionDirectories(
    const base::FilePath& parent,
    const WindowsPrivateSecurity& directory_security,
    const WindowsPrivateSecurity& file_security) {
  CleanupStaleClaimFiles(parent, file_security);
  base::FileEnumerator directories(parent, false,
                                   base::FileEnumerator::DIRECTORIES);
  for (base::FilePath path = directories.Next(); !path.empty();
       path = directories.Next()) {
    base::ProcessId pid = 0;
    int64_t expected_creation = 0;
    if (!ParseSessionDirectory(path, &pid, &expected_creation))
      continue;

    base::win::ScopedHandle session_guard = OpenPrivateWindowsDirectory(
        path, directory_security, false, 0, kDirectoryInspectionShareMode);
    if (!session_guard.is_valid())
      continue;

    if (IsExpectedProcessAlive(pid, expected_creation))
      continue;

    session_guard.Close();
    if (ClaimAndDeleteStaleSession(parent, path, directory_security,
                                   file_security)) {
      continue;
    }
    session_guard = OpenPrivateWindowsDirectory(
        path, directory_security, false, 0, kDirectoryInspectionShareMode);
    if (!session_guard.is_valid())
      continue;

    // A missing lease can only be an interrupted directory creation or a
    // directory from an older build. Give a potentially live process enough
    // time to finish publishing its lease before reclaiming it.
    BY_HANDLE_FILE_INFORMATION info = {};
    const bool old_missing_lease =
        WindowsPathIsMissing(path.AppendASCII(kLeaseFileName)) &&
        ::GetFileInformationByHandle(session_guard.get(), &info) &&
        base::Time::Now() - base::Time::FromFileTime(info.ftLastWriteTime) >=
            kUnopenableProcessCleanupAge;
    session_guard.Close();
    if (old_missing_lease) {
      DeleteSessionDirectory(parent, path, directory_security, file_security,
                             nullptr);
    }
  }
}
#else
bool DeleteSessionDirectory(const base::FilePath& path) {
  bool removable = true;
  base::FileEnumerator entries(path, false, base::FileEnumerator::NAMES_ONLY);
  for (base::FilePath entry = entries.Next(); !entry.empty();
       entry = entries.Next()) {
    const std::string name = entry.BaseName().AsUTF8Unsafe();
    if (name != kLeaseFileName && name.rfind(kMaterializedFilePrefix, 0) != 0) {
      removable = false;
      continue;
    }
    if (!base::DeleteFile(entry))
      removable = false;
  }
  return removable && base::DeleteFile(path);
}

bool ClaimStaleSession(const base::FilePath& path, base::File* lease) {
#if BUILDFLAG(IS_FUCHSIA)
  (void)path;
  (void)lease;
  return false;
#else
  if (!lease)
    return false;
#if BUILDFLAG(IS_POSIX)
  *lease = OpenAndHardenPrivatePosixFile(path.AppendASCII(kLeaseFileName));
#else
  *lease = base::File(
      path.AppendASCII(kLeaseFileName),
      base::File::FLAG_OPEN | base::File::FLAG_READ | base::File::FLAG_WRITE);
#endif
  return lease->IsValid() &&
         lease->Lock(base::File::LockMode::kExclusive) == base::File::FILE_OK;
#endif
}

void CleanupStaleSessionDirectories(const base::FilePath& parent) {
  base::FileEnumerator directories(parent, false,
                                   base::FileEnumerator::DIRECTORIES);
  for (base::FilePath path = directories.Next(); !path.empty();
       path = directories.Next()) {
    base::ProcessId pid = 0;
    int64_t expected_creation = 0;
    if (!ParseSessionDirectory(path, &pid, &expected_creation) ||
        IsExpectedProcessAlive(pid, expected_creation)) {
      continue;
    }

    base::File lease;
    if (ClaimStaleSession(path, &lease)) {
      DeleteSessionDirectory(path);
      continue;
    }

    base::File::Info info;
    if (!base::PathExists(path.AppendASCII(kLeaseFileName)) &&
        base::GetFileInfo(path, &info) &&
        base::Time::Now() - info.last_modified >=
            kUnopenableProcessCleanupAge) {
      DeleteSessionDirectory(path);
    }
  }
}
#endif

void CleanupCurrentSessionDirectory(void* opaque) {
  auto* state = static_cast<TemporaryDirectoryState*>(opaque);
  base::FilePath path;
  base::File lease;
  {
    base::AutoLock auto_lock(state->lock);
    lease = std::move(state->lease_file);
    path = std::move(state->path);
  }
  if (!path.empty()) {
    base::ThreadRestrictions::ScopedAllowIO allow_io;
#if BUILDFLAG(IS_WIN)
    const WindowsPrivateSecurity* directory_security =
        GetWindowsPrivateSecurity(true);
    const WindowsPrivateSecurity* file_security =
        GetWindowsPrivateSecurity(false);
    if (!directory_security || !file_security) {
      return;
    }
    base::win::ScopedHandle parent_guard =
        OpenPrivateWindowsDirectory(path.DirName(), *directory_security, false,
                                    0, kDirectoryGuardShareMode);
    if (!parent_guard.is_valid())
      return;
    DeleteSessionDirectory(path.DirName(), path, *directory_security,
                           *file_security, lease.IsValid() ? &lease : nullptr);
#else
    DeleteSessionDirectory(path);
#endif
  }
}

bool GetOrCreateTemporaryDirectory(base::FilePath* result) {
  if (!result)
    return false;
  base::ThreadRestrictions::ScopedAllowIO allow_io;
  TemporaryDirectoryState& state = GetTemporaryDirectoryState();
  base::AutoLock auto_lock(state.lock);
  if (!state.path.empty()) {
    *result = state.path;
    return true;
  }

  base::FilePath system_temp;
  if (!base::GetTempDir(&system_temp))
    return false;
#if BUILDFLAG(IS_POSIX)
  // Resolve environment-provided TMPDIR symlinks once, then require every
  // directory in the canonical chain to be controlled by root or this user.
  // Shared writable directories are safe only with sticky rename protection.
  if (!CanonicalizeAndValidatePosixTemporaryRoot(&system_temp))
    return false;
#endif
  std::string parent_name;
  if (!GetUserScopedParentName(&parent_name))
    return false;
  const base::FilePath parent = system_temp.AppendASCII(parent_name);
#if BUILDFLAG(IS_WIN)
  const WindowsPrivateSecurity* directory_security =
      GetWindowsPrivateSecurity(true);
  const WindowsPrivateSecurity* file_security =
      GetWindowsPrivateSecurity(false);
  base::win::ScopedHandle parent_guard;
  if (!directory_security || !file_security ||
      !CreateOrSecurePrivateWindowsDirectory(parent, *directory_security,
                                             &parent_guard)) {
    return false;
  }
  CleanupStaleSessionDirectories(parent, *directory_security, *file_security);
#else
  if (!base::CreateDirectory(parent))
    return false;
  if (!HardenPrivateDirectory(parent))
    return false;
  CleanupStaleSessionDirectories(parent);
#endif

  const base::Process current = base::Process::Current();
  const std::string prefix =
      "p" + base::NumberToString(base::GetCurrentProcId()) + "-t" +
      base::NumberToString(current.CreationTime().ToInternalValue()) + "-";
#if BUILDFLAG(IS_WIN)
  base::win::ScopedHandle session_guard;
  for (size_t attempt = 0; attempt < 100; ++attempt) {
    std::string token = base::GenerateGUID();
    token.erase(std::remove(token.begin(), token.end(), '-'), token.end());
    if (token.size() != 32)
      return false;
    const base::FilePath candidate = parent.AppendASCII(prefix + token);
    if (CreatePrivateWindowsDirectory(candidate, *directory_security,
                                      &session_guard)) {
      state.path = candidate;
      break;
    }
    const DWORD error = ::GetLastError();
    if (error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS)
      return false;
  }
  if (state.path.empty())
    return false;

  base::win::ScopedHandle lease_handle =
      CreatePrivateWindowsFile(state.path.AppendASCII(kLeaseFileName),
                               *file_security, GENERIC_READ | GENERIC_WRITE);
  base::File lease_file(std::move(lease_handle));
  if (!lease_file.IsValid() ||
      lease_file.Lock(base::File::LockMode::kExclusive) !=
          base::File::FILE_OK) {
    if (lease_file.IsValid())
      MarkWindowsHandleForDeletion(lease_file.GetPlatformFile());
    lease_file.Close();
    session_guard.Close();
    DeleteSessionDirectory(parent, state.path, *directory_security,
                           *file_security, nullptr);
    state.path.clear();
    return false;
  }
#else
  if (!base::CreateTemporaryDirInDir(
          parent, base::FilePath::FromUTF8Unsafe(prefix).value(),
          &state.path)) {
    return false;
  }
  if (!HardenPrivateDirectory(state.path)) {
    DeleteSessionDirectory(state.path);
    state.path.clear();
    return false;
  }
#if BUILDFLAG(IS_POSIX)
  base::File lease_file =
      CreatePrivatePosixFile(state.path.AppendASCII(kLeaseFileName));
#else
  base::File lease_file(
      state.path.AppendASCII(kLeaseFileName),
      base::File::FLAG_CREATE | base::File::FLAG_READ | base::File::FLAG_WRITE);
#endif
#if !BUILDFLAG(IS_FUCHSIA)
  if (!lease_file.IsValid() ||
      lease_file.Lock(base::File::LockMode::kExclusive) !=
          base::File::FILE_OK) {
#else
  if (!lease_file.IsValid()) {
#endif
    lease_file.Close();
    DeleteSessionDirectory(state.path);
    state.path.clear();
    return false;
  }
#endif
  state.lease_file = std::move(lease_file);
  base::AtExitManager::RegisterCallback(&CleanupCurrentSessionDirectory,
                                        &state);
  *result = state.path;
  return true;
}
#endif  // BUILDFLAG(ENABLE_EASR_V2)

bool WriteAll(base::File* destination, const char* data, int size) {
  if (!destination || !destination->IsValid())
    return false;
  int written = 0;
  while (written < size) {
    const int result =
        destination->WriteAtCurrentPos(data + written, size - written);
    if (result <= 0)
      return false;
    written += result;
  }
  return true;
}

template <typename ChunkConsumer>
bool ReadFileRange(base::File* source,
                   uint64_t offset,
                   uint64_t size,
                   const ChunkConsumer& consume) {
  constexpr size_t kBufferSize = 64 * 1024;
  if (!source || !source->IsValid() ||
      offset > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ||
      size >
          static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) - offset) {
    return false;
  }
  std::array<char, kBufferSize> buffer;
  uint64_t consumed = 0;
  while (consumed < size) {
    const int wanted =
        static_cast<int>(std::min<uint64_t>(buffer.size(), size - consumed));
    const int read = source->Read(static_cast<int64_t>(offset + consumed),
                                  buffer.data(), wanted);
    if (read != wanted)
      return false;
    if (!consume(buffer.data(), read))
      return false;
    consumed += static_cast<uint64_t>(read);
  }
  return true;
}

bool StreamFileRange(base::File* source,
                     uint64_t offset,
                     uint64_t size,
                     base::File* destination) {
  return ReadFileRange(source, offset, size,
                       [destination](const char* data, int length) {
                         return WriteAll(destination, data, length);
                       });
}

#if BUILDFLAG(ENABLE_EASR_V2)
bool StreamFileRangeAndHash(base::File* source,
                            uint64_t offset,
                            uint64_t size,
                            base::File* destination,
                            crypto::SecureHash* hash) {
  return ReadFileRange(source, offset, size,
                       [destination, hash](const char* data, int length) {
                         if (hash)
                           hash->Update(data, static_cast<size_t>(length));
                         return WriteAll(destination, data, length);
                       });
}
#endif

}  // namespace

#if BUILDFLAG(ENABLE_EASR_V2)
bool PrepareTemporaryFileDirectory() {
  base::FilePath path;
  return GetOrCreateTemporaryDirectory(&path);
}

void ResetTemporaryFileDirectoryForTesting() {
  CleanupCurrentSessionDirectory(&GetTemporaryDirectoryState());
}

bool IsTemporaryLeasePrivateForTesting() {
  TemporaryDirectoryState& state = GetTemporaryDirectoryState();
  base::AutoLock auto_lock(state.lock);
  if (!state.lease_file.IsValid())
    return false;
#if BUILDFLAG(IS_WIN)
  const WindowsPrivateSecurity* security = GetWindowsPrivateSecurity(false);
  return security &&
         VerifyPrivateWindowsObject(state.lease_file.GetPlatformFile(), false,
                                    *security, true);
#elif BUILDFLAG(IS_POSIX)
  return IsPrivatePosixFileDescriptor(state.lease_file.GetPlatformFile());
#else
  return true;
#endif
}

bool CleanupStaleTemporaryDirectoriesForTesting(const base::FilePath& parent) {
  base::ThreadRestrictions::ScopedAllowIO allow_io;
#if BUILDFLAG(IS_WIN)
  const WindowsPrivateSecurity* directory_security =
      GetWindowsPrivateSecurity(true);
  const WindowsPrivateSecurity* file_security =
      GetWindowsPrivateSecurity(false);
  if (!directory_security || !file_security)
    return false;
  base::win::ScopedHandle parent_guard = OpenPrivateWindowsDirectory(
      parent, *directory_security, false, 0, kDirectoryGuardShareMode);
  if (!parent_guard.is_valid())
    return false;
  CleanupStaleSessionDirectories(parent, *directory_security, *file_security);
#else
  if (!HardenPrivateDirectory(parent))
    return false;
  CleanupStaleSessionDirectories(parent);
#endif
  return true;
}
#endif  // BUILDFLAG(ENABLE_EASR_V2)

ScopedTemporaryFile::ScopedTemporaryFile() = default;

ScopedTemporaryFile::~ScopedTemporaryFile() {
  if (!path_.empty()) {
    base::ThreadRestrictions::ScopedAllowIO allow_io;
#if BUILDFLAG(IS_WIN)
    base::DeleteFileAfterReboot(path_);
#else
    base::DeleteFile(path_);
#endif
  }
}

bool ScopedTemporaryFile::Init(const base::FilePath::StringType& ext) {
  if (!path_.empty())
    return true;

  base::ThreadRestrictions::ScopedAllowIO allow_io;
  if (!base::CreateTemporaryFile(&path_))
    return false;

#if BUILDFLAG(IS_WIN)
  if (!ext.empty()) {
    const base::FilePath with_extension = path_.AddExtension(ext);
    if (!base::Move(path_, with_extension)) {
      base::DeleteFile(path_);
      path_.clear();
      return false;
    }
    path_ = with_extension;
  }
#endif
  return true;
}

#if BUILDFLAG(ENABLE_EASR_V2)
bool ScopedTemporaryFile::InitForWrite(const base::FilePath::StringType& ext,
                                       base::File* file) {
  if (!file || !path_.empty())
    return false;

  base::ThreadRestrictions::ScopedAllowIO allow_io;
  base::FilePath temporary_directory;
  if (!GetOrCreateTemporaryDirectory(&temporary_directory))
    return false;

#if BUILDFLAG(IS_WIN)
  const WindowsPrivateSecurity* file_security =
      GetWindowsPrivateSecurity(false);
  if (!file_security)
    return false;
  for (size_t attempt = 0; attempt < 100; ++attempt) {
    base::FilePath candidate = temporary_directory.AppendASCII(
        std::string(kMaterializedFilePrefix) + base::GenerateGUID());
    if (!ext.empty())
      candidate = candidate.AddExtension(ext);
    base::win::ScopedHandle handle = CreatePrivateWindowsFile(
        candidate, *file_security, GENERIC_READ | GENERIC_WRITE);
    if (!handle.is_valid()) {
      const DWORD error = ::GetLastError();
      if (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS)
        continue;
      return false;
    }
    path_ = std::move(candidate);
    *file = base::File(std::move(handle));
    return true;
  }
#else
  for (size_t attempt = 0; attempt < 100; ++attempt) {
    base::FilePath candidate = temporary_directory.AppendASCII(
        std::string(kMaterializedFilePrefix) + base::GenerateGUID());
    if (!ext.empty())
      candidate = candidate.AddExtension(ext);
#if BUILDFLAG(IS_POSIX)
    base::File opened = CreatePrivatePosixFile(candidate);
#else
    base::File opened(candidate, base::File::FLAG_CREATE |
                                     base::File::FLAG_READ |
                                     base::File::FLAG_WRITE);
#endif
    if (!opened.IsValid())
      continue;
    path_ = std::move(candidate);
    *file = std::move(opened);
    return true;
  }
#endif
  return false;
}
#endif  // BUILDFLAG(ENABLE_EASR_V2)

bool ScopedTemporaryFile::InitFromFile(
    base::File* src,
    const base::FilePath::StringType& ext,
    uint64_t offset,
    uint64_t size,
    const absl::optional<IntegrityPayload>& integrity) {
  if (!src->IsValid())
    return false;

  if (!Init(ext))
    return false;

  base::ThreadRestrictions::ScopedAllowIO allow_io;
  base::File dest(path_, base::File::FLAG_OPEN | base::File::FLAG_WRITE);
  if (!dest.IsValid())
    return false;

#if BUILDFLAG(ENABLE_EASR_V2)
  bool valid = false;
  if (integrity.has_value()) {
    auto hash = crypto::SecureHash::Create(crypto::SecureHash::SHA256);
    valid = StreamFileRangeAndHash(src, offset, size, &dest, hash.get());
    if (valid) {
      std::array<uint8_t, crypto::kSHA256Length> digest{};
      hash->Finish(digest.data(), digest.size());
      ValidateIntegrityDigestOrDie(base::make_span(digest), *integrity);
    }
  } else {
    valid = StreamFileRange(src, offset, size, &dest);
  }
#else
  bool valid = true;
  if (integrity.has_value()) {
    valid =
        size <= static_cast<uint64_t>(std::numeric_limits<int>::max()) &&
        offset <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    std::vector<char> contents;
    if (valid) {
      contents.resize(static_cast<size_t>(size));
      valid = src->Read(static_cast<int64_t>(offset), contents.data(),
                        static_cast<int>(contents.size())) ==
              static_cast<int>(contents.size());
    }
    if (valid) {
      ValidateIntegrityOrDie(contents.data(), contents.size(), *integrity);
      valid =
          WriteAll(&dest, contents.data(), static_cast<int>(contents.size()));
    }
  } else {
    valid = StreamFileRange(src, offset, size, &dest);
  }
#endif
  if (!valid) {
    dest.SetLength(0);
#if BUILDFLAG(IS_WIN)
    dest.DeleteOnClose(true);
#endif
  }
  return valid;
}

#if BUILDFLAG(ENABLE_EASR_V2)
bool ScopedTemporaryFile::DeleteNow() {
  if (path_.empty())
    return true;

  base::ThreadRestrictions::ScopedAllowIO allow_io;
  if (!base::PathExists(path_)) {
    path_.clear();
    return true;
  }
  if (base::DeleteFile(path_)) {
    path_.clear();
    return true;
  }
#if BUILDFLAG(IS_WIN)
  base::DeleteFileAfterReboot(path_);
#endif
  return false;
}
#endif  // BUILDFLAG(ENABLE_EASR_V2)

}  // namespace asar
