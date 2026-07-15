// Copyright (c) 2026 Electron authors.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#include "shell/common/asar/scoped_temporary_file.h"

#include <array>
#include <memory>
#include <string>
#include <thread>

#if BUILDFLAG(IS_POSIX)
#include <sys/stat.h>
#endif

#include "base/environment.h"
#include "base/files/file.h"
#include "base/files/file_enumerator.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/guid.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"

#if BUILDFLAG(IS_WIN)
#include <aclapi.h>
#include <sddl.h>
#include <windows.h>

#include "base/strings/utf_string_conversions.h"
#include "base/win/scoped_handle.h"
#include "base/win/scoped_localalloc.h"
#include "base/win/win_util.h"
#endif

namespace asar {

#if BUILDFLAG(IS_WIN)
namespace {

constexpr char kParentPrefix[] = "electron-easar-v2-";

class TestSecurityAttributes {
 public:
  bool Initialize(const std::wstring& sddl) {
    PSECURITY_DESCRIPTOR raw = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &raw, nullptr)) {
      return false;
    }
    descriptor_.reset(raw);
    attributes_ = {sizeof(attributes_), descriptor_.get(), FALSE};
    return true;
  }

  SECURITY_ATTRIBUTES* get() { return &attributes_; }

 private:
  base::win::ScopedLocalAlloc descriptor_;
  SECURITY_ATTRIBUTES attributes_{};
};

std::wstring CurrentUserSid() {
  std::wstring sid;
  EXPECT_TRUE(base::win::GetUserSidString(&sid));
  return sid;
}

std::wstring PrivateSddl(bool directory,
                         const std::wstring& owner = std::wstring()) {
  const std::wstring user = CurrentUserSid();
  const wchar_t* inheritance = directory ? L"OICI" : L"";
  return L"O:" + (owner.empty() ? user : owner) + L"D:P(A;" + inheritance +
         L";FA;;;" + user + L")(A;" + inheritance + L";FA;;;SY)(A;" +
         inheritance + L";FA;;;BA)";
}

std::wstring UnsafeCurrentUserSddl(bool directory) {
  const wchar_t* inheritance = directory ? L"OICI" : L"";
  return L"O:" + CurrentUserSid() + L"D:(A;" + inheritance + L";FA;;;WD)";
}

testing::AssertionResult IsPrivateHandle(HANDLE handle, bool directory) {
  BY_HANDLE_FILE_INFORMATION file_info = {};
  if (!handle || handle == INVALID_HANDLE_VALUE ||
      ::GetFileType(handle) != FILE_TYPE_DISK ||
      !::GetFileInformationByHandle(handle, &file_info) ||
      static_cast<bool>(file_info.dwFileAttributes &
                        FILE_ATTRIBUTE_DIRECTORY) != directory ||
      (file_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
    return testing::AssertionFailure() << "unexpected object type";
  }

  PSID owner = nullptr;
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR raw_descriptor = nullptr;
  if (::GetSecurityInfo(handle, SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        &owner, nullptr, &dacl, nullptr,
                        &raw_descriptor) != ERROR_SUCCESS) {
    return testing::AssertionFailure() << "GetSecurityInfo failed";
  }
  base::win::ScopedLocalAlloc descriptor(raw_descriptor);
  PSID raw_user = nullptr;
  if (!::ConvertStringSidToSidW(CurrentUserSid().c_str(), &raw_user))
    return testing::AssertionFailure() << "current SID conversion failed";
  base::win::ScopedLocalAlloc user(raw_user);

  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  if (!owner || !::EqualSid(owner, user.get()) || !dacl ||
      dacl->AceCount != 3 ||
      !::GetSecurityDescriptorControl(descriptor.get(), &control, &revision) ||
      !(control & SE_DACL_PROTECTED)) {
    return testing::AssertionFailure() << "owner or protected DACL mismatch";
  }

  const BYTE expected_flags =
      directory ? OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE : 0;
  bool saw_user = false;
  bool saw_system = false;
  bool saw_administrators = false;
  for (DWORD index = 0; index < dacl->AceCount; ++index) {
    void* raw_ace = nullptr;
    if (!::GetAce(dacl, index, &raw_ace))
      return testing::AssertionFailure() << "GetAce failed";
    const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw_ace);
    if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
        ace->Header.AceFlags != expected_flags ||
        ace->Mask != FILE_ALL_ACCESS) {
      return testing::AssertionFailure() << "unexpected private ACE";
    }
    PSID sid = const_cast<DWORD*>(&ace->SidStart);
    if (!::IsValidSid(sid))
      return testing::AssertionFailure() << "invalid ACE SID";
    if (::EqualSid(sid, user.get()))
      saw_user = true;
    else if (::IsWellKnownSid(sid, WinLocalSystemSid))
      saw_system = true;
    else if (::IsWellKnownSid(sid, WinBuiltinAdministratorsSid))
      saw_administrators = true;
    else
      return testing::AssertionFailure() << "unexpected ACE SID";
  }
  return saw_user && saw_system && saw_administrators
             ? testing::AssertionSuccess()
             : testing::AssertionFailure() << "missing private ACE";
}

testing::AssertionResult IsPrivatePath(const base::FilePath& path,
                                       bool directory) {
  base::win::ScopedHandle handle(
      ::CreateFileW(path.value().c_str(), READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT |
                        (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0),
                    nullptr));
  if (!handle.is_valid())
    return testing::AssertionFailure()
           << "CreateFile failed: " << ::GetLastError();
  return IsPrivateHandle(handle.get(), directory);
}

class ScopedTemporaryFileSecurityTest : public testing::Test {
 protected:
  void SetUp() override {
    ResetTemporaryFileDirectoryForTesting();
    ASSERT_TRUE(root_.CreateUniqueTempDir());
    environment_ = base::Environment::Create();
    had_temp_ = environment_->GetVar("TEMP", &old_temp_);
    had_tmp_ = environment_->GetVar("TMP", &old_tmp_);
    const std::string root = root_.GetPath().AsUTF8Unsafe();
    ASSERT_TRUE(environment_->SetVar("TEMP", root));
    ASSERT_TRUE(environment_->SetVar("TMP", root));
  }

  void TearDown() override {
    ResetTemporaryFileDirectoryForTesting();
    Restore("TEMP", had_temp_, old_temp_);
    Restore("TMP", had_tmp_, old_tmp_);
  }

  void Restore(const char* name, bool existed, const std::string& value) {
    if (existed)
      EXPECT_TRUE(environment_->SetVar(name, value));
    else
      EXPECT_TRUE(environment_->UnSetVar(name));
  }

  base::FilePath ParentPath() const {
    return root_.GetPath().AppendASCII(kParentPrefix +
                                       base::WideToUTF8(CurrentUserSid()));
  }

  bool CreateDirectoryWithSddl(const base::FilePath& path,
                               const std::wstring& sddl) {
    TestSecurityAttributes security;
    return security.Initialize(sddl) &&
           ::CreateDirectoryW(path.value().c_str(), security.get());
  }

  bool CreateFileWithSddl(const base::FilePath& path,
                          const std::wstring& sddl) {
    TestSecurityAttributes security;
    if (!security.Initialize(sddl))
      return false;
    base::win::ScopedHandle handle(::CreateFileW(
        path.value().c_str(), GENERIC_READ | GENERIC_WRITE, 0, security.get(),
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    return handle.is_valid();
  }

  base::ScopedTempDir root_;
  std::unique_ptr<base::Environment> environment_;
  bool had_temp_ = false;
  bool had_tmp_ = false;
  std::string old_temp_;
  std::string old_tmp_;
};

TEST_F(ScopedTemporaryFileSecurityTest,
       AtomicallyCreatesPrivateParentSessionLeaseAndMaterializedFile) {
  ScopedTemporaryFile materialized;
  base::File file;
  ASSERT_TRUE(materialized.InitForWrite(FILE_PATH_LITERAL("bin"), &file));
  ASSERT_TRUE(file.IsValid());
  EXPECT_TRUE(IsPrivateHandle(file.GetPlatformFile(), false));

  base::win::ScopedHandle competing(
      ::CreateFileW(materialized.path().value().c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  const DWORD competing_error = ::GetLastError();
  EXPECT_FALSE(competing.is_valid());
  EXPECT_EQ(competing_error, static_cast<DWORD>(ERROR_SHARING_VIOLATION));

  file.Close();
  EXPECT_TRUE(IsPrivatePath(materialized.path(), false));
  EXPECT_TRUE(IsPrivatePath(materialized.path().DirName(), true));
  EXPECT_TRUE(IsPrivatePath(materialized.path().DirName().DirName(), true));
  EXPECT_TRUE(IsTemporaryLeasePrivateForTesting());

  base::win::ScopedHandle competing_lease(::CreateFileW(
      materialized.path().DirName().AppendASCII(".lease").value().c_str(),
      GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  const DWORD lease_error = ::GetLastError();
  EXPECT_FALSE(competing_lease.is_valid());
  EXPECT_EQ(lease_error, static_cast<DWORD>(ERROR_SHARING_VIOLATION));
}

TEST_F(ScopedTemporaryFileSecurityTest, HardensCurrentOwnerParentDacl) {
  ASSERT_TRUE(
      CreateDirectoryWithSddl(ParentPath(), UnsafeCurrentUserSddl(true)));
  ASSERT_TRUE(PrepareTemporaryFileDirectory());
  EXPECT_TRUE(IsPrivatePath(ParentPath(), true));
}

TEST_F(ScopedTemporaryFileSecurityTest, RejectsForeignOwnerParent) {
  if (!CreateDirectoryWithSddl(ParentPath(), PrivateSddl(true, L"BA"))) {
    GTEST_SKIP() << "setting a foreign owner requires an elevated token: "
                 << ::GetLastError();
  }
  EXPECT_FALSE(PrepareTemporaryFileDirectory());
}

TEST_F(ScopedTemporaryFileSecurityTest, RejectsForeignOwnerSession) {
  ASSERT_TRUE(CreateDirectoryWithSddl(ParentPath(), PrivateSddl(true)));
  const base::FilePath session = ParentPath().AppendASCII(
      "p2147483647-t1-00000000000000000000000000000000");
  if (!CreateDirectoryWithSddl(session, PrivateSddl(true, L"BA"))) {
    GTEST_SKIP() << "setting a foreign owner requires an elevated token: "
                 << ::GetLastError();
  }
  ASSERT_TRUE(CleanupStaleTemporaryDirectoriesForTesting(ParentPath()));
  EXPECT_TRUE(base::DirectoryExists(session));
}

TEST_F(ScopedTemporaryFileSecurityTest, RejectsReparseParent) {
  const base::FilePath target = root_.GetPath().AppendASCII("target");
  ASSERT_TRUE(base::CreateDirectory(target));
  constexpr DWORD kAllowUnprivilegedCreate = 0x2;
  if (!::CreateSymbolicLinkW(
          ParentPath().value().c_str(), target.value().c_str(),
          SYMBOLIC_LINK_FLAG_DIRECTORY | kAllowUnprivilegedCreate) &&
      !::CreateSymbolicLinkW(ParentPath().value().c_str(),
                             target.value().c_str(),
                             SYMBOLIC_LINK_FLAG_DIRECTORY)) {
    GTEST_SKIP() << "symbolic-link creation unavailable: " << ::GetLastError();
  }
  EXPECT_FALSE(PrepareTemporaryFileDirectory());
}

TEST_F(ScopedTemporaryFileSecurityTest,
       ConcurrentStaleClaimHardensLegacyFilesAndLeavesNoClaim) {
  ASSERT_TRUE(CreateDirectoryWithSddl(ParentPath(), PrivateSddl(true)));
  const base::FilePath session = ParentPath().AppendASCII(
      "p2147483647-t1-11111111111111111111111111111111");
  ASSERT_TRUE(CreateDirectoryWithSddl(session, PrivateSddl(true)));
  ASSERT_TRUE(CreateFileWithSddl(session.AppendASCII(".lease"),
                                 UnsafeCurrentUserSddl(false)));
  ASSERT_TRUE(CreateFileWithSddl(session.AppendASCII("easar-legacy.bin"),
                                 UnsafeCurrentUserSddl(false)));

  std::array<bool, 2> completed{};
  std::thread first([&] {
    completed[0] = CleanupStaleTemporaryDirectoriesForTesting(ParentPath());
  });
  std::thread second([&] {
    completed[1] = CleanupStaleTemporaryDirectoriesForTesting(ParentPath());
  });
  first.join();
  second.join();
  EXPECT_TRUE(completed[0]);
  EXPECT_TRUE(completed[1]);
  EXPECT_FALSE(base::PathExists(session));

  base::FileEnumerator files(ParentPath(), false, base::FileEnumerator::FILES);
  for (base::FilePath path = files.Next(); !path.empty(); path = files.Next()) {
    EXPECT_NE(path.BaseName().AsUTF8Unsafe().rfind(".claim-", 0),
              static_cast<size_t>(0));
  }
}

}  // namespace
#endif  // BUILDFLAG(IS_WIN)

#if BUILDFLAG(IS_POSIX)
namespace {

class ScopedTemporaryFilePosixSecurityTest : public testing::Test {
 protected:
  void SetUp() override {
    ResetTemporaryFileDirectoryForTesting();
    ASSERT_TRUE(root_.CreateUniqueTempDir());
    environment_ = base::Environment::Create();
    had_tmpdir_ = environment_->GetVar("TMPDIR", &old_tmpdir_);
    SetTmpDir(root_.GetPath());
  }

  void TearDown() override {
    ResetTemporaryFileDirectoryForTesting();
    if (had_tmpdir_)
      EXPECT_TRUE(environment_->SetVar("TMPDIR", old_tmpdir_));
    else
      EXPECT_TRUE(environment_->UnSetVar("TMPDIR"));
  }

  void SetTmpDir(const base::FilePath& path) {
    ASSERT_TRUE(environment_->SetVar("TMPDIR", path.AsUTF8Unsafe()));
  }

  void SetMode(const base::FilePath& path, mode_t mode) {
    ASSERT_EQ(chmod(path.value().c_str(), mode), 0);
  }

  base::ScopedTempDir root_;
  std::unique_ptr<base::Environment> environment_;
  bool had_tmpdir_ = false;
  std::string old_tmpdir_;
};

TEST_F(ScopedTemporaryFilePosixSecurityTest,
       AcceptsPrivateTemporaryRootAndPrivateLease) {
  SetMode(root_.GetPath(), 0700);
  EXPECT_TRUE(PrepareTemporaryFileDirectory());
  EXPECT_TRUE(IsTemporaryLeasePrivateForTesting());
}

TEST_F(ScopedTemporaryFilePosixSecurityTest,
       RejectsSharedWritableTemporaryRootWithoutStickyBit) {
  SetMode(root_.GetPath(), 0777);
  EXPECT_FALSE(PrepareTemporaryFileDirectory());
}

TEST_F(ScopedTemporaryFilePosixSecurityTest,
       AcceptsSharedWritableTemporaryRootWithStickyBit) {
  SetMode(root_.GetPath(), 01777);
  EXPECT_TRUE(PrepareTemporaryFileDirectory());
  EXPECT_TRUE(IsTemporaryLeasePrivateForTesting());
}

TEST_F(ScopedTemporaryFilePosixSecurityTest,
       RejectsPrivateRootBelowReplaceableAncestor) {
  const base::FilePath nested = root_.GetPath().AppendASCII("nested");
  ASSERT_TRUE(base::CreateDirectory(nested));
  SetMode(nested, 0700);
  SetMode(root_.GetPath(), 0777);
  SetTmpDir(nested);
  EXPECT_FALSE(PrepareTemporaryFileDirectory());
}

}  // namespace
#endif  // BUILDFLAG(IS_POSIX)

}  // namespace asar
