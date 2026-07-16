// Copyright (c) 2014 GitHub, Inc.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/task/thread_pool.h"
#include "electron/buildflags/buildflags.h"
#include "gin/handle.h"
#include "shell/common/asar/archive.h"
#include "shell/common/asar/asar_util.h"
#include "shell/common/gin_converters/file_path_converter.h"
#include "shell/common/gin_helper/dictionary.h"
#include "shell/common/gin_helper/promise.h"
#include "shell/common/node_includes.h"
#include "shell/common/node_util.h"
#if BUILDFLAG(ENABLE_EASR_V2)
#include "third_party/boringssl/src/include/openssl/mem.h"
#endif

namespace {

struct ReadFileStorage {
#if BUILDFLAG(ENABLE_EASR_V2)
  ~ReadFileStorage() {
    if (secure && !contents.empty())
      OPENSSL_cleanse(contents.data(), contents.size());
  }

  bool secure = false;
#endif
  std::string contents;
};

using OwnedReadFileStorage = std::unique_ptr<ReadFileStorage>;

struct ReadFileResult {
  ReadFileResult() = default;
  ReadFileResult(ReadFileResult&&) noexcept = default;
  ReadFileResult& operator=(ReadFileResult&&) noexcept = default;
  ReadFileResult(const ReadFileResult&) = delete;
  ReadFileResult& operator=(const ReadFileResult&) = delete;
  ~ReadFileResult() = default;

  OwnedReadFileStorage storage = std::make_unique<ReadFileStorage>();
  base::FilePath archive_path;
  base::FilePath file_path;
  bool is_asar = true;
  asar::Archive::Error error = asar::Archive::Error::kIo;
};

ReadFileResult ReadArchiveFile(std::shared_ptr<asar::Archive> archive,
                               const base::FilePath& path) {
  ReadFileResult result;
  result.file_path = path;
  if (!archive)
    return result;
  result.archive_path = archive->path();
#if BUILDFLAG(ENABLE_EASR_V2)
  result.storage->secure = archive->is_encrypted();
#endif
  archive->ReadFile(path, &result.storage->contents, node::Buffer::kMaxLength,
                    &result.error);
  return result;
}

ReadFileResult OpenAndReadPath(const base::FilePath& full_path) {
  base::FilePath archive_path;
  base::FilePath path;
  if (!asar::GetAsarArchivePath(full_path, &archive_path, &path, true)) {
    ReadFileResult result;
    result.is_asar = false;
    result.error = asar::Archive::Error::kNone;
    return result;
  }

  asar::Archive::Error error = asar::Archive::Error::kIo;
  std::shared_ptr<asar::Archive> archive =
      asar::GetOrCreateAsarArchive(archive_path, &error);
  if (!archive) {
    ReadFileResult result;
    result.archive_path = archive_path;
    result.file_path = path;
    result.error = error;
    return result;
  }
  return ReadArchiveFile(std::move(archive), path);
}

v8::Local<v8::Object> MakeReadFileBuffer(v8::Isolate* isolate,
                                         OwnedReadFileStorage storage) {
  if (!storage || storage->contents.empty())
    return node::Buffer::New(isolate, 0).ToLocalChecked();

  // EASR decrypts and decompresses into embedder-owned memory. V8's memory
  // sandbox cannot expose that allocation as an ArrayBuffer backing store, so
  // copy the verified bytes into V8-owned memory. Destroying |storage| here
  // also promptly cleanses plaintext produced by encrypted archives.
  return node::Buffer::Copy(isolate, storage->contents.data(),
                            storage->contents.size())
      .ToLocalChecked();
}

v8::Local<v8::Value> MakeArchiveError(v8::Isolate* isolate,
                                      v8::Local<v8::Context> context,
                                      asar::Archive::Error error,
                                      const base::FilePath& archive_path,
                                      const base::FilePath& path) {
  const char* internal_code = asar::ArchiveErrorName(error);
  const char* code = "EIO";
  int error_number = -5;
  if (error == asar::Archive::Error::kNotFound) {
    code = "ENOENT";
    error_number = -2;
  } else if (error == asar::Archive::Error::kInvalidRange) {
    code = "EINVAL";
    error_number = -22;
  }

  std::string message = internal_code;
  if (!path.empty())
    message.append(": ").append(path.AsUTF8Unsafe());
  message.append(" in ").append(archive_path.AsUTF8Unsafe());
  v8::Local<v8::Object> exception =
      v8::Exception::Error(
          v8::String::NewFromUtf8(isolate, message.c_str()).ToLocalChecked())
          .As<v8::Object>();
  exception
      ->Set(context, node::FIXED_ONE_BYTE_STRING(isolate, "code"),
            node::OneByteString(isolate, code))
      .Check();
  exception
      ->Set(context, node::FIXED_ONE_BYTE_STRING(isolate, "errno"),
            v8::Integer::New(isolate, error_number))
      .Check();
  exception
      ->Set(context, node::FIXED_ONE_BYTE_STRING(isolate, "easrError"),
            v8::String::NewFromUtf8(isolate, internal_code).ToLocalChecked())
      .Check();
  exception
      ->Set(context, node::FIXED_ONE_BYTE_STRING(isolate, "asarPath"),
            gin::ConvertToV8(isolate, archive_path))
      .Check();
  if (!path.empty()) {
    exception
        ->Set(context, node::FIXED_ONE_BYTE_STRING(isolate, "filePath"),
              gin::ConvertToV8(isolate, path))
        .Check();
    exception
        ->Set(context, node::FIXED_ONE_BYTE_STRING(isolate, "path"),
              gin::ConvertToV8(isolate, archive_path.Append(path)))
        .Check();
  }
  return exception;
}

void FinishReadArchiveFile(gin_helper::Promise<v8::Local<v8::Value>> promise,
                           ReadFileResult result) {
  v8::Isolate* isolate = promise.isolate();
  v8::HandleScope handle_scope(isolate);
  if (isolate->IsExecutionTerminating())
    return;
  v8::Local<v8::Context> context = promise.GetContext();
  if (node::Environment::GetCurrent(context) == nullptr)
    return;
  v8::Context::Scope context_scope(context);
  if (!result.is_asar) {
    promise.Resolve(v8::Undefined(isolate));
    return;
  }
  if (result.error != asar::Archive::Error::kNone) {
    promise.Reject(MakeArchiveError(isolate, context, result.error,
                                    result.archive_path, result.file_path));
    return;
  }
  promise.Resolve(MakeReadFileBuffer(isolate, std::move(result.storage)));
}

v8::Local<v8::Promise> StartReadArchiveFile(
    v8::Isolate* isolate,
    std::shared_ptr<asar::Archive> archive,
    const base::FilePath& path) {
  gin_helper::Promise<v8::Local<v8::Value>> promise(isolate);
  v8::Local<v8::Promise> handle = promise.GetHandle();
  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE,
      {base::MayBlock(), base::WithBaseSyncPrimitives(),
       base::TaskPriority::USER_VISIBLE,
       base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN},
      base::BindOnce(&ReadArchiveFile, std::move(archive), path),
      base::BindOnce(&FinishReadArchiveFile, std::move(promise)));
  return handle;
}

void ReadFileAsync(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  base::FilePath full_path;
  if (!gin::ConvertFromV8(isolate, args[0], &full_path)) {
    isolate->ThrowException(v8::Exception::TypeError(
        node::FIXED_ONE_BYTE_STRING(isolate, "invalid ASAR path")));
    return;
  }

  gin_helper::Promise<v8::Local<v8::Value>> promise(isolate);
  v8::Local<v8::Promise> handle = promise.GetHandle();
  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE,
      {base::MayBlock(), base::WithBaseSyncPrimitives(),
       base::TaskPriority::USER_VISIBLE,
       base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN},
      base::BindOnce(&OpenAndReadPath, full_path),
      base::BindOnce(&FinishReadArchiveFile, std::move(promise)));
  args.GetReturnValue().Set(handle);
}

class Archive : public node::ObjectWrap {
 public:
  static v8::Local<v8::FunctionTemplate> CreateFunctionTemplate(
      v8::Isolate* isolate) {
    auto tpl = v8::FunctionTemplate::New(isolate, Archive::New);
    tpl->SetClassName(
        v8::String::NewFromUtf8(isolate, "Archive").ToLocalChecked());
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(tpl, "getFileInfo", &Archive::GetFileInfo);
    NODE_SET_PROTOTYPE_METHOD(tpl, "stat", &Archive::Stat);
    NODE_SET_PROTOTYPE_METHOD(tpl, "readdir", &Archive::Readdir);
    NODE_SET_PROTOTYPE_METHOD(tpl, "realpath", &Archive::Realpath);
    NODE_SET_PROTOTYPE_METHOD(tpl, "copyFileOut", &Archive::CopyFileOut);
    NODE_SET_PROTOTYPE_METHOD(tpl, "readFile", &Archive::ReadFile);
    NODE_SET_PROTOTYPE_METHOD(tpl, "readFileAsync", &Archive::ReadFileAsync);
    NODE_SET_PROTOTYPE_METHOD(tpl, "getFdAndValidateIntegrityLater",
                              &Archive::GetFD);

    return tpl;
  }

  // disable copy
  Archive(const Archive&) = delete;
  Archive& operator=(const Archive&) = delete;

 protected:
  explicit Archive(std::shared_ptr<asar::Archive> archive)
      : archive_(std::move(archive)) {}

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args) {
    auto* isolate = args.GetIsolate();

    base::FilePath path;
    if (!gin::ConvertFromV8(isolate, args[0], &path)) {
      isolate->ThrowException(v8::Exception::Error(node::FIXED_ONE_BYTE_STRING(
          isolate, "failed to convert path to V8")));
      return;
    }

    asar::Archive::Error error = asar::Archive::Error::kIo;
    std::shared_ptr<asar::Archive> archive =
        asar::GetOrCreateAsarArchive(path, &error);
    if (!archive) {
      isolate->ThrowException(MakeArchiveError(isolate,
                                               isolate->GetCurrentContext(),
                                               error, path, base::FilePath()));
      return;
    }

    auto* archive_wrap = new Archive(std::move(archive));
    archive_wrap->Wrap(args.This());
    args.GetReturnValue().Set(args.This());
  }

  // Reads the offset and size of file.
  static void GetFileInfo(const v8::FunctionCallbackInfo<v8::Value>& args) {
    auto* isolate = args.GetIsolate();
    auto* wrap = node::ObjectWrap::Unwrap<Archive>(args.Holder());

    base::FilePath path;
    if (!gin::ConvertFromV8(isolate, args[0], &path)) {
      args.GetReturnValue().Set(v8::False(isolate));
      return;
    }

    asar::Archive::FileInfo info;
    if (!wrap->archive_ || !wrap->archive_->GetFileInfo(path, &info)) {
      args.GetReturnValue().Set(v8::False(isolate));
      return;
    }

    gin_helper::Dictionary dict(isolate, v8::Object::New(isolate));
    dict.Set("size", info.size);
    dict.Set("unpacked", info.unpacked);
    dict.Set("offset", info.offset);
    if (info.integrity.has_value()) {
      gin_helper::Dictionary integrity(isolate, v8::Object::New(isolate));
      asar::HashAlgorithm algorithm = info.integrity.value().algorithm;
      switch (algorithm) {
        case asar::HashAlgorithm::SHA256:
          integrity.Set("algorithm", "SHA256");
          break;
        case asar::HashAlgorithm::NONE:
          CHECK(false);
          break;
      }
      integrity.Set("hash", info.integrity.value().hash);
      dict.Set("integrity", integrity);
    }
    args.GetReturnValue().Set(dict.GetHandle());
  }

  // Returns a fake result of fs.stat(path).
  static void Stat(const v8::FunctionCallbackInfo<v8::Value>& args) {
    auto* isolate = args.GetIsolate();
    auto* wrap = node::ObjectWrap::Unwrap<Archive>(args.Holder());
    base::FilePath path;
    if (!gin::ConvertFromV8(isolate, args[0], &path)) {
      args.GetReturnValue().Set(v8::False(isolate));
      return;
    }

    asar::Archive::Stats stats;
    if (!wrap->archive_ || !wrap->archive_->Stat(path, &stats)) {
      args.GetReturnValue().Set(v8::False(isolate));
      return;
    }

    gin_helper::Dictionary dict(isolate, v8::Object::New(isolate));
    dict.Set("size", stats.size);
    dict.Set("offset", stats.offset);
    dict.Set("isFile", stats.is_file);
    dict.Set("isDirectory", stats.is_directory);
    dict.Set("isLink", stats.is_link);
    args.GetReturnValue().Set(dict.GetHandle());
  }

  // Returns all files under a directory.
  static void Readdir(const v8::FunctionCallbackInfo<v8::Value>& args) {
    auto* isolate = args.GetIsolate();
    auto* wrap = node::ObjectWrap::Unwrap<Archive>(args.Holder());
    base::FilePath path;
    if (!gin::ConvertFromV8(isolate, args[0], &path)) {
      args.GetReturnValue().Set(v8::False(isolate));
      return;
    }

    std::vector<base::FilePath> files;
    if (!wrap->archive_ || !wrap->archive_->Readdir(path, &files)) {
      args.GetReturnValue().Set(v8::False(isolate));
      return;
    }
    args.GetReturnValue().Set(gin::ConvertToV8(isolate, files));
  }

  // Returns the path of file with symbol link resolved.
  static void Realpath(const v8::FunctionCallbackInfo<v8::Value>& args) {
    auto* isolate = args.GetIsolate();
    auto* wrap = node::ObjectWrap::Unwrap<Archive>(args.Holder());
    base::FilePath path;
    if (!gin::ConvertFromV8(isolate, args[0], &path)) {
      args.GetReturnValue().Set(v8::False(isolate));
      return;
    }

    base::FilePath realpath;
    if (!wrap->archive_ || !wrap->archive_->Realpath(path, &realpath)) {
      args.GetReturnValue().Set(v8::False(isolate));
      return;
    }
    args.GetReturnValue().Set(gin::ConvertToV8(isolate, realpath));
  }

  // Copy the file out into a temporary file and returns the new path.
  static void CopyFileOut(const v8::FunctionCallbackInfo<v8::Value>& args) {
    auto* isolate = args.GetIsolate();
    auto* wrap = node::ObjectWrap::Unwrap<Archive>(args.Holder());
    base::FilePath path;
    if (!gin::ConvertFromV8(isolate, args[0], &path)) {
      args.GetReturnValue().Set(v8::False(isolate));
      return;
    }

    base::FilePath new_path;
    asar::Archive::Error error = asar::Archive::Error::kIo;
    if (!wrap->archive_ ||
        !wrap->archive_->CopyFileOut(path, &new_path, &error)) {
      if (error != asar::Archive::Error::kNotFound) {
        isolate->ThrowException(MakeArchiveError(
            isolate, isolate->GetCurrentContext(), error,
            wrap->archive_ ? wrap->archive_->path() : base::FilePath(), path));
        return;
      }
      args.GetReturnValue().Set(v8::False(isolate));
      return;
    }
    args.GetReturnValue().Set(gin::ConvertToV8(isolate, new_path));
  }

  // Read file contents and return a Buffer.
  static void ReadFile(const v8::FunctionCallbackInfo<v8::Value>& args) {
    auto* isolate = args.GetIsolate();
    auto* wrap = node::ObjectWrap::Unwrap<Archive>(args.Holder());
    base::FilePath path;
    if (!gin::ConvertFromV8(isolate, args[0], &path)) {
      args.GetReturnValue().Set(v8::False(isolate));
      return;
    }

    OwnedReadFileStorage storage = std::make_unique<ReadFileStorage>();
    asar::Archive::Error error = asar::Archive::Error::kIo;
    asar::Archive::FileInfo info;
    if (wrap->archive_ && wrap->archive_->GetFileInfo(path, &info) &&
        info.size > node::Buffer::kMaxLength) {
      isolate->ThrowException(
          MakeArchiveError(isolate, isolate->GetCurrentContext(),
                           asar::Archive::Error::kResourceExhausted,
                           wrap->archive_->path(), path));
      return;
    }
#if BUILDFLAG(ENABLE_EASR_V2)
    if (wrap->archive_)
      storage->secure = wrap->archive_->is_encrypted();
#endif
    if (!wrap->archive_ ||
        !wrap->archive_->ReadFile(path, &storage->contents, &error)) {
      if (error != asar::Archive::Error::kNotFound) {
        isolate->ThrowException(MakeArchiveError(
            isolate, isolate->GetCurrentContext(), error,
            wrap->archive_ ? wrap->archive_->path() : base::FilePath(), path));
        return;
      }
      args.GetReturnValue().Set(v8::False(isolate));
      return;
    }

    args.GetReturnValue().Set(MakeReadFileBuffer(isolate, std::move(storage)));
  }

  // Read/decrypt/decompress on a worker and create the Buffer only after the
  // reply returns to this isolate's sequence.
  static void ReadFileAsync(const v8::FunctionCallbackInfo<v8::Value>& args) {
    auto* isolate = args.GetIsolate();
    auto* wrap = node::ObjectWrap::Unwrap<Archive>(args.Holder());
    base::FilePath path;
    if (!gin::ConvertFromV8(isolate, args[0], &path)) {
      isolate->ThrowException(v8::Exception::TypeError(
          node::FIXED_ONE_BYTE_STRING(isolate, "invalid ASAR path")));
      return;
    }

    std::shared_ptr<asar::Archive> archive = wrap->archive_;
    args.GetReturnValue().Set(
        StartReadArchiveFile(isolate, std::move(archive), path));
  }

  // Return the file descriptor.
  static void GetFD(const v8::FunctionCallbackInfo<v8::Value>& args) {
    auto* isolate = args.GetIsolate();
    auto* wrap = node::ObjectWrap::Unwrap<Archive>(args.Holder());

    args.GetReturnValue().Set(gin::ConvertToV8(
        isolate, wrap->archive_ ? wrap->archive_->GetUnsafeFD() : -1));
  }

  std::shared_ptr<asar::Archive> archive_;
};

static void InitAsarSupport(const v8::FunctionCallbackInfo<v8::Value>& args) {
  auto* isolate = args.GetIsolate();
  auto require = args[0];

  // Evaluate asar_bundle.js.
  std::vector<v8::Local<v8::String>> asar_bundle_params = {
      node::FIXED_ONE_BYTE_STRING(isolate, "require")};
  std::vector<v8::Local<v8::Value>> asar_bundle_args = {require};
  electron::util::CompileAndCall(
      isolate->GetCurrentContext(), "electron/js2c/asar_bundle",
      &asar_bundle_params, &asar_bundle_args, nullptr);
}

static void SplitPath(const v8::FunctionCallbackInfo<v8::Value>& args) {
  auto* isolate = args.GetIsolate();

  base::FilePath path;
  if (!gin::ConvertFromV8(isolate, args[0], &path)) {
    args.GetReturnValue().Set(v8::False(isolate));
    return;
  }

  gin_helper::Dictionary dict = gin::Dictionary::CreateEmpty(isolate);
  base::FilePath asar_path, file_path;
  if (asar::GetAsarArchivePath(path, &asar_path, &file_path, true)) {
    dict.Set("isAsar", true);
    dict.Set("asarPath", asar_path);
    dict.Set("filePath", file_path);
  } else {
    dict.Set("isAsar", false);
  }
  args.GetReturnValue().Set(dict.GetHandle());
}

void Initialize(v8::Local<v8::Object> exports,
                v8::Local<v8::Value> unused,
                v8::Local<v8::Context> context,
                void* priv) {
  auto* isolate = exports->GetIsolate();

  auto cons = Archive::CreateFunctionTemplate(isolate)
                  ->GetFunction(context)
                  .ToLocalChecked();
  cons->SetName(node::FIXED_ONE_BYTE_STRING(isolate, "Archive"));

  exports->Set(context, node::FIXED_ONE_BYTE_STRING(isolate, "Archive"), cons)
      .Check();
  NODE_SET_METHOD(exports, "splitPath", &SplitPath);
  NODE_SET_METHOD(exports, "readFileAsync", &ReadFileAsync);
  NODE_SET_METHOD(exports, "initAsarSupport", &InitAsarSupport);
}

}  // namespace

NODE_LINKED_MODULE_CONTEXT_AWARE(electron_common_asar, Initialize)
