// Copyright (c) 2013 GitHub, Inc.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#include "shell/browser/electron_browser_context.h"

#include <array>
#include <memory>
#include <utility>

#include "base/barrier_closure.h"
#include "base/base_paths.h"
#include "base/check.h"
#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/fingerprint_secret_store.h"
#include "base/logging.h"
#include "base/no_destructor.h"
#include "base/noise_generator.h"
#include "base/path_service.h"
#include "base/rand_util.h"
#include "base/strings/escape.h"
#include "base/strings/strcat.h"
#include "base/strings/string_util.h"
#include "base/synchronization/lock.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "base/threading/thread_restrictions.h"
#include "chrome/common/chrome_paths.h"
#include "chrome/common/pref_names.h"
#include "components/keyed_service/content/browser_context_dependency_manager.h"
#include "components/prefs/json_pref_store.h"
#include "components/prefs/pref_registry_simple.h"
#include "components/prefs/pref_service.h"
#include "components/prefs/pref_service_factory.h"
#include "components/prefs/value_map_pref_store.h"
#include "components/proxy_config/pref_proxy_config_tracker_impl.h"
#include "components/proxy_config/proxy_config_pref_names.h"
#include "content/browser/blob_storage/chrome_blob_storage_context.h"  // nogncheck
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/cors_origin_pattern_setter.h"
#include "content/public/browser/render_process_host.h"
#include "content/public/browser/shared_cors_origin_access_list.h"
#include "content/public/browser/storage_partition.h"
#include "content/public/browser/web_contents_media_capture_id.h"
#include "content/public/common/content_switches.h"
#include "crypto/hmac.h"
#include "media/audio/audio_device_description.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/wrapper_shared_url_loader_factory.h"
#include "services/network/public/mojom/network_context.mojom.h"
#include "shell/browser/cookie_change_notifier.h"
#include "shell/browser/electron_browser_client.h"
#include "shell/browser/electron_browser_main_parts.h"
#include "shell/browser/electron_download_manager_delegate.h"
#include "shell/browser/electron_permission_manager.h"
#include "shell/browser/net/resolve_proxy_helper.h"
#include "shell/browser/protocol_registry.h"
#include "shell/browser/special_storage_policy.h"
#include "shell/browser/ui/inspectable_web_contents.h"
#include "shell/browser/web_contents_permission_helper.h"
#include "shell/browser/web_view_manager.h"
#include "shell/browser/zoom_level_delegate.h"
#include "shell/common/application_info.h"
#include "shell/common/electron_paths.h"
#include "shell/common/gin_converters/frame_converter.h"
#include "shell/common/gin_helper/error_thrower.h"
#include "shell/common/options_switches.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom.h"
#include "third_party/boringssl/src/include/openssl/mem.h"

#if BUILDFLAG(ENABLE_ELECTRON_EXTENSIONS)
#include "extensions/browser/browser_context_keyed_service_factories.h"
#include "extensions/browser/extension_pref_store.h"
#include "extensions/browser/extension_pref_value_map_factory.h"
#include "extensions/browser/extension_prefs.h"
#include "extensions/browser/pref_names.h"
#include "extensions/common/extension_api.h"
#include "shell/browser/extensions/electron_browser_context_keyed_service_factories.h"
#include "shell/browser/extensions/electron_extension_system.h"
#include "shell/browser/extensions/electron_extension_system_factory.h"
#include "shell/browser/extensions/electron_extensions_browser_client.h"
#include "shell/common/extensions/electron_extensions_client.h"
#endif  // BUILDFLAG(ENABLE_ELECTRON_EXTENSIONS)

#if BUILDFLAG(ENABLE_ELECTRON_EXTENSIONS) || \
    BUILDFLAG(ENABLE_BUILTIN_SPELLCHECKER)
#include "components/pref_registry/pref_registry_syncable.h"
#include "components/user_prefs/user_prefs.h"
#endif

#if BUILDFLAG(ENABLE_BUILTIN_SPELLCHECKER)
#include "base/i18n/rtl.h"
#include "components/language/core/browser/language_prefs.h"
#include "components/spellcheck/browser/pref_names.h"
#include "components/spellcheck/common/spellcheck_common.h"
#endif

using content::BrowserThread;

namespace electron {

namespace {

constexpr char kFingerprintTokenContext[] =
    "electron-fingerprint-profile-token-v1";

const FingerprintProfile::IgnoredDomains& GetFingerprintIgnoredDomains() {
  static const FingerprintProfile::IgnoredDomains ignored_domains = [] {
    FingerprintProfile::IgnoredDomains result;
    const base::CommandLine* command_line =
        base::CommandLine::ForCurrentProcess();
    if (command_line->HasSwitch(
            FingerprintProfile::kFingerprintIgnoresSwitch)) {
      FingerprintProfile::ParseIgnoredDomains(
          command_line->GetSwitchValueASCII(
              FingerprintProfile::kFingerprintIgnoresSwitch),
          &result);
    }
    return result;
  }();
  return ignored_domains;
}

// Convert string to lower case and escape it.
std::string MakePartitionName(const std::string& input) {
  return base::EscapePath(base::ToLowerASCII(input));
}

}  // namespace

class FingerprintProfileConfig
    : public base::RefCountedThreadSafe<FingerprintProfileConfig> {
 public:
  using FingerprintProfileSnapshot =
      ElectronBrowserContext::FingerprintProfileSnapshot;

  FingerprintProfileConfig(std::string partition,
                           bool in_memory,
                           base::FilePath profile_path)
      : partition_(std::move(partition)),
        in_memory_(in_memory),
        profile_path_(std::move(profile_path)) {}

  void Initialize() {
    base::AutoLock lock(lock_);
    if (status_ == FingerprintProfileSnapshot::Status::kReady ||
        status_ == FingerprintProfileSnapshot::Status::kDestroying) {
      return;
    }
    InitializeLocked();
  }

  ElectronBrowserContext::SetFingerprintResult SetFingerprint(
      const std::string& fingerprint) {
    base::AutoLock lock(lock_);
    if (status_ == FingerprintProfileSnapshot::Status::kUnavailable)
      InitializeLocked();
    if (status_ != FingerprintProfileSnapshot::Status::kReady)
      return ElectronBrowserContext::SetFingerprintResult::kUnavailable;
    if (locked_)
      return ElectronBrowserContext::SetFingerprintResult::kLocked;

    fingerprint_ = fingerprint;
    if (!UpdateTokenLocked())
      return ElectronBrowserContext::SetFingerprintResult::kUnavailable;
    return ElectronBrowserContext::SetFingerprintResult::kSuccess;
  }

  std::string GetFingerprint() const {
    base::AutoLock lock(lock_);
    if (!fingerprint_.empty())
      return fingerprint_;
    if (partition_.empty())
      return "default";
    return (in_memory_ ? "memory:" : "persist:") + partition_;
  }

  ElectronBrowserContext::FingerprintProfileSnapshot AcquireForRenderer() {
    base::AutoLock lock(lock_);
    if (status_ == FingerprintProfileSnapshot::Status::kReady &&
        !token_.empty()) {
      locked_ = true;
    }
    return SnapshotLocked();
  }

  ElectronBrowserContext::FingerprintProfileSnapshot Snapshot() const {
    base::AutoLock lock(lock_);
    return SnapshotLocked();
  }

  absl::optional<uint32_t> GetDeviceMemoryClientHintProfile() {
    base::AutoLock lock(lock_);
    if (status_ != FingerprintProfileSnapshot::Status::kReady)
      return absl::nullopt;
    if (device_memory_client_hint_profile_)
      locked_ = true;
    return device_memory_client_hint_profile_;
  }

  void MarkDestroying() {
    base::AutoLock lock(lock_);
    status_ = FingerprintProfileSnapshot::Status::kDestroying;
    status_message_ = "browser_context_destroying";
    token_.clear();
    device_memory_client_hint_profile_.reset();
  }

 private:
  friend class base::RefCountedThreadSafe<FingerprintProfileConfig>;

  ~FingerprintProfileConfig() {
    OPENSSL_cleanse(secret_.data(), secret_.size());
  }

  void InitializeLocked() {
    status_ = FingerprintProfileSnapshot::Status::kInitializing;
    status_message_ = "initializing";
    token_.clear();
    device_memory_client_hint_profile_.reset();
    OPENSSL_cleanse(secret_.data(), secret_.size());

    if (in_memory_) {
      base::RandBytes(secret_.data(), secret_.size());
    } else {
      base::ThreadRestrictions::ScopedAllowIO allow_io;
      auto result = base::FingerprintSecretStore::LoadOrCreate(profile_path_);
      if (!result.ok()) {
        SetUnavailableLocked(base::StrCat(
            {"secret_store:",
             base::FingerprintSecretStore::StatusToString(result.status)}));
        return;
      }
      secret_ = result.secret;
      OPENSSL_cleanse(result.secret.data(), result.secret.size());
    }

    if (!UpdateTokenLocked())
      return;
    status_ = FingerprintProfileSnapshot::Status::kReady;
    status_message_ = "ready";
  }

  bool UpdateTokenLocked() {
    std::string message(kFingerprintTokenContext);
    message.push_back('\0');
    if (fingerprint_.empty()) {
      message.append("default", 7);
      message.push_back('\0');
      message.append(in_memory_ ? "memory" : "persist");
      message.push_back('\0');
      message.append(partition_.empty() ? "default" : partition_);
    } else {
      message.append("explicit", 8);
      message.push_back('\0');
      message.append(fingerprint_);
    }

    crypto::HMAC hmac(crypto::HMAC::SHA256);
    if (!hmac.Init(secret_.data(), secret_.size())) {
      SetUnavailableLocked("token_hmac_init_failed");
      return false;
    }

    std::array<uint8_t, FingerprintProfile::kTokenDigestSize> digest{};
    if (!hmac.Sign(message, digest.data(), digest.size())) {
      SetUnavailableLocked("token_hmac_sign_failed");
      return false;
    }

    std::string token = FingerprintProfile::EncodeToken(digest);
    if (token.size() != FingerprintProfile::kEncodedTokenSize) {
      SetUnavailableLocked("token_encoding_failed");
      return false;
    }

    auto profile =
        FingerprintProfile::FromToken(token, GetFingerprintIgnoredDomains());
    if (!profile) {
      SetUnavailableLocked("token_validation_failed");
      return false;
    }

    token_ = std::move(token);
    if (profile->IsIgnored(FingerprintProfile::Domain::kNavigator)) {
      device_memory_client_hint_profile_.reset();
    } else {
      device_memory_client_hint_profile_ =
          profile->GetNavigatorSystemProfileIndex();
    }
    return true;
  }

  void SetUnavailableLocked(std::string status_message) {
    status_ = FingerprintProfileSnapshot::Status::kUnavailable;
    status_message_ = std::move(status_message);
    token_.clear();
    device_memory_client_hint_profile_.reset();
    OPENSSL_cleanse(secret_.data(), secret_.size());
  }

  ElectronBrowserContext::FingerprintProfileSnapshot SnapshotLocked() const {
    ElectronBrowserContext::FingerprintProfileSnapshot snapshot;
    snapshot.status = status_;
    snapshot.status_message = status_message_;
    snapshot.partition =
        partition_.empty() ? "default"
                           : (in_memory_ ? "memory:" : "persist:") + partition_;
    snapshot.profile_path = profile_path_;
    snapshot.ignored_domain_mask =
        ElectronBrowserContext::GetFingerprintIgnoredDomainMask();
    if (status_ == FingerprintProfileSnapshot::Status::kReady)
      snapshot.token = token_;
    return snapshot;
  }

  mutable base::Lock lock_;
  const std::string partition_;
  const bool in_memory_;
  const base::FilePath profile_path_;
  std::string fingerprint_;
  std::array<uint8_t, 32> secret_{};
  std::string token_;
  absl::optional<uint32_t> device_memory_client_hint_profile_;
  FingerprintProfileSnapshot::Status status_ =
      FingerprintProfileSnapshot::Status::kInitializing;
  std::string status_message_ = "initializing";
  bool locked_ = false;
};

ElectronBrowserContext::FingerprintProfileSnapshot::
    FingerprintProfileSnapshot() = default;
ElectronBrowserContext::FingerprintProfileSnapshot::FingerprintProfileSnapshot(
    const FingerprintProfileSnapshot&) = default;
ElectronBrowserContext::FingerprintProfileSnapshot&
ElectronBrowserContext::FingerprintProfileSnapshot::operator=(
    const FingerprintProfileSnapshot&) = default;
ElectronBrowserContext::FingerprintProfileSnapshot::
    ~FingerprintProfileSnapshot() = default;

namespace {

class FingerprintProfileRegistry {
 public:
  void Register(content::BrowserContext* context,
                scoped_refptr<FingerprintProfileConfig> profile) {
    base::AutoLock lock(lock_);
    profiles_[context] = std::move(profile);
  }

  scoped_refptr<FingerprintProfileConfig> Lookup(
      content::BrowserContext* context) {
    base::AutoLock lock(lock_);
    auto it = profiles_.find(context);
    return it == profiles_.end() ? nullptr : it->second;
  }

  void Unregister(content::BrowserContext* context,
                  FingerprintProfileConfig* expected_profile) {
    base::AutoLock lock(lock_);
    auto it = profiles_.find(context);
    if (it != profiles_.end() && it->second.get() == expected_profile)
      profiles_.erase(it);
  }

 private:
  base::Lock lock_;
  std::map<content::BrowserContext*, scoped_refptr<FingerprintProfileConfig>>
      profiles_;
};

FingerprintProfileRegistry& GetFingerprintProfileRegistry() {
  static base::NoDestructor<FingerprintProfileRegistry> registry;
  return *registry;
}

}  // namespace

// static
ElectronBrowserContext::BrowserContextMap&
ElectronBrowserContext::browser_context_map() {
  static base::NoDestructor<ElectronBrowserContext::BrowserContextMap>
      browser_context_map;
  return *browser_context_map;
}

ElectronBrowserContext::ElectronBrowserContext(const std::string& partition,
                                               bool in_memory,
                                               base::Value::Dict options)
    : in_memory_pref_store_(new ValueMapPrefStore),
      storage_policy_(base::MakeRefCounted<SpecialStoragePolicy>()),
      protocol_registry_(base::WrapUnique(new ProtocolRegistry)),
      partition_(partition),
      in_memory_(in_memory),
      ssl_config_(network::mojom::SSLConfig::New()) {
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();
  if (command_line->HasSwitch(::switches::kSingleProcess) ||
      content::RenderProcessHost::run_renderer_in_process()) {
    LOG(ERROR) << "Fingerprint profiles require renderer process isolation; "
                  "custom fingerprint parameters will be skipped";
  }

  // Read options.
  use_cache_ = !command_line->HasSwitch(switches::kDisableHttpCache);
  if (auto use_cache_opt = options.FindBool("cache")) {
    use_cache_ = use_cache_opt.value();
  }

  base::StringToInt(command_line->GetSwitchValueASCII(switches::kDiskCacheSize),
                    &max_cache_size_);

  base::PathService::Get(DIR_SESSION_DATA, &path_);
  if (!in_memory && !partition.empty()) {
    path_ = path_.Append(FILE_PATH_LITERAL("Partitions"))
                .Append(base::FilePath::FromUTF8Unsafe(
                    MakePartitionName(partition)));
  }

  BrowserContextDependencyManager::GetInstance()->MarkBrowserContextLive(this);

  // Initialize Pref Registry.
  InitPrefs();
  fingerprint_profile_ = base::MakeRefCounted<FingerprintProfileConfig>(
      partition_, in_memory_, path_);
  GetFingerprintProfileRegistry().Register(this, fingerprint_profile_);
  fingerprint_profile_->Initialize();
  auto fingerprint_snapshot = fingerprint_profile_->Snapshot();
  if (!fingerprint_snapshot.is_ready()) {
    LOG(ERROR) << "Fingerprint profile initialization failed"
               << " partition=" << fingerprint_snapshot.partition
               << " profile_path="
               << fingerprint_snapshot.profile_path.AsUTF8Unsafe()
               << " config_state="
               << FingerprintProfileStatusToString(fingerprint_snapshot.status)
               << " status=" << fingerprint_snapshot.status_message;
  }

  cookie_change_notifier_ = std::make_unique<CookieChangeNotifier>(this);

#if BUILDFLAG(ENABLE_ELECTRON_EXTENSIONS)
  if (!in_memory_) {
    BrowserContextDependencyManager::GetInstance()
        ->CreateBrowserContextServices(this);

    extension_system_ = static_cast<extensions::ElectronExtensionSystem*>(
        extensions::ExtensionSystem::Get(this));
    extension_system_->InitForRegularProfile(true /* extensions_enabled */);
    extension_system_->FinishInitialization();
  }
#endif
}

ElectronBrowserContext::~ElectronBrowserContext() {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
  if (fingerprint_profile_) {
    fingerprint_profile_->MarkDestroying();
    GetFingerprintProfileRegistry().Unregister(this,
                                               fingerprint_profile_.get());
    fingerprint_profile_.reset();
  }
  NotifyWillBeDestroyed();
  // Notify any keyed services of browser context destruction.
  BrowserContextDependencyManager::GetInstance()->DestroyBrowserContextServices(
      this);
  ShutdownStoragePartitions();

  BrowserThread::DeleteSoon(BrowserThread::IO, FROM_HERE,
                            std::move(resource_context_));
}

void ElectronBrowserContext::InitPrefs() {
  auto prefs_path = GetPath().Append(FILE_PATH_LITERAL("Preferences"));
  base::ThreadRestrictions::ScopedAllowIO allow_io;
  PrefServiceFactory prefs_factory;
  scoped_refptr<JsonPrefStore> pref_store =
      base::MakeRefCounted<JsonPrefStore>(prefs_path);
  pref_store->ReadPrefs();  // Synchronous.
  prefs_factory.set_user_prefs(pref_store);
  prefs_factory.set_command_line_prefs(in_memory_pref_store());

#if BUILDFLAG(ENABLE_ELECTRON_EXTENSIONS)
  if (!in_memory_) {
    auto* ext_pref_store = new ExtensionPrefStore(
        ExtensionPrefValueMapFactory::GetForBrowserContext(this),
        IsOffTheRecord());
    prefs_factory.set_extension_prefs(ext_pref_store);
  }
#endif

#if BUILDFLAG(ENABLE_ELECTRON_EXTENSIONS) || \
    BUILDFLAG(ENABLE_BUILTIN_SPELLCHECKER)
  auto registry = base::MakeRefCounted<user_prefs::PrefRegistrySyncable>();
#else
  auto registry = base::MakeRefCounted<PrefRegistrySimple>();
#endif

  registry->RegisterFilePathPref(prefs::kSelectFileLastDirectory,
                                 base::FilePath());
  base::FilePath download_dir;
  base::PathService::Get(chrome::DIR_DEFAULT_DOWNLOADS, &download_dir);
  registry->RegisterFilePathPref(prefs::kDownloadDefaultDirectory,
                                 download_dir);
  registry->RegisterDictionaryPref(prefs::kDevToolsFileSystemPaths);
  InspectableWebContents::RegisterPrefs(registry.get());
  MediaDeviceIDSalt::RegisterPrefs(registry.get());
  ZoomLevelDelegate::RegisterPrefs(registry.get());
  PrefProxyConfigTrackerImpl::RegisterPrefs(registry.get());
#if BUILDFLAG(ENABLE_ELECTRON_EXTENSIONS)
  if (!in_memory_)
    extensions::ExtensionPrefs::RegisterProfilePrefs(registry.get());
#endif

#if BUILDFLAG(ENABLE_BUILTIN_SPELLCHECKER)
  BrowserContextDependencyManager::GetInstance()
      ->RegisterProfilePrefsForServices(registry.get());

  language::LanguagePrefs::RegisterProfilePrefs(registry.get());
#endif

  prefs_ = prefs_factory.Create(registry.get());
#if BUILDFLAG(ENABLE_ELECTRON_EXTENSIONS) || \
    BUILDFLAG(ENABLE_BUILTIN_SPELLCHECKER)
  user_prefs::UserPrefs::Set(this, prefs_.get());
#endif

#if BUILDFLAG(ENABLE_BUILTIN_SPELLCHECKER)
  base::Value::List current_dictionaries =
      prefs()->GetList(spellcheck::prefs::kSpellCheckDictionaries).Clone();
  // No configured dictionaries, the default will be en-US
  if (current_dictionaries.empty()) {
    std::string default_code = spellcheck::GetCorrespondingSpellCheckLanguage(
        base::i18n::GetConfiguredLocale());
    if (!default_code.empty()) {
      base::Value::List language_codes;
      language_codes.Append(default_code);
      prefs()->Set(spellcheck::prefs::kSpellCheckDictionaries,
                   base::Value(std::move(language_codes)));
    }
  }
#endif
}

void ElectronBrowserContext::SetUserAgent(const std::string& user_agent) {
  user_agent_ = user_agent;
}

base::FilePath ElectronBrowserContext::GetPath() {
  return path_;
}

bool ElectronBrowserContext::IsOffTheRecord() {
  return in_memory_;
}

std::string ElectronBrowserContext::GetFingerprint() const {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
  return fingerprint_profile_ ? fingerprint_profile_->GetFingerprint()
                              : std::string();
}

ElectronBrowserContext::SetFingerprintResult
ElectronBrowserContext::SetFingerprint(const std::string& fingerprint) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
  DCHECK(base::IsStringUTF8(fingerprint));
  DCHECK_LE(fingerprint.size(), kMaxFingerprintSeedBytes);
  return fingerprint_profile_
             ? fingerprint_profile_->SetFingerprint(fingerprint)
             : SetFingerprintResult::kUnavailable;
}

// static
uint64_t ElectronBrowserContext::GetFingerprintIgnoredDomainMask() {
  return GetFingerprintIgnoredDomains().ToEnumBitmask();
}

// static
absl::optional<ElectronBrowserContext::FingerprintProfileSnapshot>
ElectronBrowserContext::AcquireFingerprintProfileForRenderer(
    content::BrowserContext* context) {
  if (!context)
    return absl::nullopt;
  auto profile = GetFingerprintProfileRegistry().Lookup(context);
  if (!profile)
    return absl::nullopt;
  return profile->AcquireForRenderer();
}

// static
const char* ElectronBrowserContext::FingerprintProfileStatusToString(
    FingerprintProfileSnapshot::Status status) {
  switch (status) {
    case FingerprintProfileSnapshot::Status::kInitializing:
      return "initializing";
    case FingerprintProfileSnapshot::Status::kReady:
      return "ready";
    case FingerprintProfileSnapshot::Status::kUnavailable:
      return "unavailable";
    case FingerprintProfileSnapshot::Status::kDestroying:
      return "destroying";
  }
  return "unknown";
}

bool ElectronBrowserContext::CanUseHttpCache() const {
  return use_cache_;
}

int ElectronBrowserContext::GetMaxCacheSize() const {
  return max_cache_size_;
}

content::ResourceContext* ElectronBrowserContext::GetResourceContext() {
  if (!resource_context_)
    resource_context_ = std::make_unique<content::ResourceContext>();
  return resource_context_.get();
}

std::string ElectronBrowserContext::GetMediaDeviceIDSalt() {
  if (!media_device_id_salt_.get())
    media_device_id_salt_ = std::make_unique<MediaDeviceIDSalt>(prefs_.get());
  return media_device_id_salt_->GetSalt();
}

std::unique_ptr<content::ZoomLevelDelegate>
ElectronBrowserContext::CreateZoomLevelDelegate(
    const base::FilePath& partition_path) {
  if (!IsOffTheRecord()) {
    return std::make_unique<ZoomLevelDelegate>(prefs(), partition_path);
  }
  return std::unique_ptr<content::ZoomLevelDelegate>();
}

content::DownloadManagerDelegate*
ElectronBrowserContext::GetDownloadManagerDelegate() {
  if (!download_manager_delegate_.get()) {
    auto* download_manager = this->GetDownloadManager();
    download_manager_delegate_ =
        std::make_unique<ElectronDownloadManagerDelegate>(download_manager);
  }
  return download_manager_delegate_.get();
}

content::BrowserPluginGuestManager* ElectronBrowserContext::GetGuestManager() {
  if (!guest_manager_)
    guest_manager_ = std::make_unique<WebViewManager>();
  return guest_manager_.get();
}

content::PlatformNotificationService*
ElectronBrowserContext::GetPlatformNotificationService() {
  return ElectronBrowserClient::Get()->GetPlatformNotificationService();
}

content::PermissionControllerDelegate*
ElectronBrowserContext::GetPermissionControllerDelegate() {
  if (!permission_manager_.get())
    permission_manager_ = std::make_unique<ElectronPermissionManager>();
  return permission_manager_.get();
}

storage::SpecialStoragePolicy*
ElectronBrowserContext::GetSpecialStoragePolicy() {
  return storage_policy_.get();
}

std::string ElectronBrowserContext::GetUserAgent() const {
  return user_agent_.value_or(ElectronBrowserClient::Get()->GetUserAgent());
}

predictors::PreconnectManager* ElectronBrowserContext::GetPreconnectManager() {
  if (!preconnect_manager_.get()) {
    preconnect_manager_ =
        std::make_unique<predictors::PreconnectManager>(nullptr, this);
  }
  return preconnect_manager_.get();
}

scoped_refptr<network::SharedURLLoaderFactory>
ElectronBrowserContext::GetURLLoaderFactory() {
  if (url_loader_factory_)
    return url_loader_factory_;

  mojo::PendingRemote<network::mojom::URLLoaderFactory> network_factory_remote;
  mojo::PendingReceiver<network::mojom::URLLoaderFactory> factory_receiver =
      network_factory_remote.InitWithNewPipeAndPassReceiver();

  // Consult the embedder.
  mojo::PendingRemote<network::mojom::TrustedURLLoaderHeaderClient>
      header_client;
  static_cast<content::ContentBrowserClient*>(ElectronBrowserClient::Get())
      ->WillCreateURLLoaderFactory(
          this, nullptr, -1,
          content::ContentBrowserClient::URLLoaderFactoryType::kNavigation,
          url::Origin(), absl::nullopt, ukm::kInvalidSourceIdObj,
          &factory_receiver, &header_client, nullptr, nullptr, nullptr);

  network::mojom::URLLoaderFactoryParamsPtr params =
      network::mojom::URLLoaderFactoryParams::New();
  params->header_client = std::move(header_client);
  params->process_id = network::mojom::kBrowserProcessId;
  params->is_trusted = true;
  params->is_corb_enabled = false;
  // The tests of net module would fail if this setting is true, it seems that
  // the non-NetworkService implementation always has web security enabled.
  params->disable_web_security = false;

  auto* storage_partition = GetDefaultStoragePartition();
  storage_partition->GetNetworkContext()->CreateURLLoaderFactory(
      std::move(factory_receiver), std::move(params));
  url_loader_factory_ =
      base::MakeRefCounted<network::WrapperSharedURLLoaderFactory>(
          std::move(network_factory_remote));
  return url_loader_factory_;
}

content::PushMessagingService*
ElectronBrowserContext::GetPushMessagingService() {
  return nullptr;
}

content::SSLHostStateDelegate*
ElectronBrowserContext::GetSSLHostStateDelegate() {
  return nullptr;
}

content::BackgroundFetchDelegate*
ElectronBrowserContext::GetBackgroundFetchDelegate() {
  return nullptr;
}

content::BackgroundSyncController*
ElectronBrowserContext::GetBackgroundSyncController() {
  return nullptr;
}

content::BrowsingDataRemoverDelegate*
ElectronBrowserContext::GetBrowsingDataRemoverDelegate() {
  return nullptr;
}

content::ClientHintsControllerDelegate*
ElectronBrowserContext::GetClientHintsControllerDelegate() {
  return nullptr;
}

absl::optional<uint32_t>
ElectronBrowserContext::GetDeviceMemoryClientHintProfile() {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
  if (!fingerprint_profile_)
    return absl::nullopt;
  return fingerprint_profile_->GetDeviceMemoryClientHintProfile();
}

content::StorageNotificationService*
ElectronBrowserContext::GetStorageNotificationService() {
  return nullptr;
}

content::ReduceAcceptLanguageControllerDelegate*
ElectronBrowserContext::GetReduceAcceptLanguageControllerDelegate() {
  // Needs implementation
  // Refs https://chromium-review.googlesource.com/c/chromium/src/+/3687391
  return nullptr;
}

ResolveProxyHelper* ElectronBrowserContext::GetResolveProxyHelper() {
  if (!resolve_proxy_helper_) {
    resolve_proxy_helper_ = base::MakeRefCounted<ResolveProxyHelper>(this);
  }
  return resolve_proxy_helper_.get();
}

network::mojom::SSLConfigPtr ElectronBrowserContext::GetSSLConfig() {
  return ssl_config_.Clone();
}

void ElectronBrowserContext::SetSSLConfig(network::mojom::SSLConfigPtr config) {
  ssl_config_ = std::move(config);
  if (ssl_config_client_) {
    ssl_config_client_->OnSSLConfigUpdated(ssl_config_.Clone());
  }
}

void ElectronBrowserContext::SetSSLConfigClient(
    mojo::Remote<network::mojom::SSLConfigClient> client) {
  ssl_config_client_ = std::move(client);
}

void ElectronBrowserContext::SetDisplayMediaRequestHandler(
    DisplayMediaRequestHandler handler) {
  display_media_request_handler_ = handler;
}

void ElectronBrowserContext::DisplayMediaDeviceChosen(
    const content::MediaStreamRequest& request,
    content::MediaResponseCallback callback,
    gin::Arguments* args) {
  blink::mojom::StreamDevicesSetPtr stream_devices_set =
      blink::mojom::StreamDevicesSet::New();
  v8::Local<v8::Value> result;
  if (!args->GetNext(&result) || result->IsNullOrUndefined()) {
    std::move(callback).Run(
        blink::mojom::StreamDevicesSet(),
        blink::mojom::MediaStreamRequestResult::CAPTURE_FAILURE, nullptr);
    return;
  }
  gin_helper::Dictionary result_dict;
  if (!gin::ConvertFromV8(args->isolate(), result, &result_dict)) {
    gin_helper::ErrorThrower(args->isolate())
        .ThrowTypeError(
            "Display Media Request streams callback must be called with null "
            "or a valid object");
    std::move(callback).Run(
        blink::mojom::StreamDevicesSet(),
        blink::mojom::MediaStreamRequestResult::CAPTURE_FAILURE, nullptr);
    return;
  }
  stream_devices_set->stream_devices.emplace_back(
      blink::mojom::StreamDevices::New());
  blink::mojom::StreamDevices& devices = *stream_devices_set->stream_devices[0];
  bool video_requested =
      request.video_type != blink::mojom::MediaStreamType::NO_SERVICE;
  bool audio_requested =
      request.audio_type != blink::mojom::MediaStreamType::NO_SERVICE;
  bool has_video = false;
  if (video_requested && result_dict.Has("video")) {
    gin_helper::Dictionary video_dict;
    std::string id;
    std::string name;
    content::RenderFrameHost* rfh;
    if (result_dict.Get("video", &video_dict) && video_dict.Get("id", &id) &&
        video_dict.Get("name", &name)) {
      devices.video_device =
          blink::MediaStreamDevice(request.video_type, id, name);
    } else if (result_dict.Get("video", &rfh)) {
      devices.video_device = blink::MediaStreamDevice(
          request.video_type,
          content::WebContentsMediaCaptureId(rfh->GetProcess()->GetID(),
                                             rfh->GetRoutingID())
              .ToString(),
          base::UTF16ToUTF8(
              content::WebContents::FromRenderFrameHost(rfh)->GetTitle()));
    } else {
      gin_helper::ErrorThrower(args->isolate())
          .ThrowTypeError(
              "video must be a WebFrameMain or DesktopCapturerSource");
      std::move(callback).Run(
          blink::mojom::StreamDevicesSet(),
          blink::mojom::MediaStreamRequestResult::CAPTURE_FAILURE, nullptr);
      return;
    }
    has_video = true;
  }
  if (audio_requested && result_dict.Has("audio")) {
    gin_helper::Dictionary audio_dict;
    std::string id;
    std::string name;
    content::RenderFrameHost* rfh;
    // NB. this is not permitted by the documentation, but is left here as an
    // "escape hatch" for providing an arbitrary name/id if needed in the
    // future.
    if (result_dict.Get("audio", &audio_dict) && audio_dict.Get("id", &id) &&
        audio_dict.Get("name", &name)) {
      devices.audio_device =
          blink::MediaStreamDevice(request.audio_type, id, name);
    } else if (result_dict.Get("audio", &rfh)) {
      devices.audio_device = blink::MediaStreamDevice(
          request.audio_type,
          content::WebContentsMediaCaptureId(rfh->GetProcess()->GetID(),
                                             rfh->GetRoutingID(),
                                             /* disable_local_echo= */ true)
              .ToString(),
          "Tab audio");
    } else if (result_dict.Get("audio", &id)) {
      devices.audio_device =
          blink::MediaStreamDevice(request.audio_type, id, "System audio");
    } else {
      gin_helper::ErrorThrower(args->isolate())
          .ThrowTypeError(
              "audio must be a WebFrameMain, \"loopback\" or "
              "\"loopbackWithMute\"");
      std::move(callback).Run(
          blink::mojom::StreamDevicesSet(),
          blink::mojom::MediaStreamRequestResult::CAPTURE_FAILURE, nullptr);
      return;
    }
  }

  if ((video_requested && !has_video)) {
    gin_helper::ErrorThrower(args->isolate())
        .ThrowTypeError(
            "Video was requested, but no video stream was provided");
    std::move(callback).Run(
        blink::mojom::StreamDevicesSet(),
        blink::mojom::MediaStreamRequestResult::CAPTURE_FAILURE, nullptr);
    return;
  }

  std::move(callback).Run(*stream_devices_set,
                          blink::mojom::MediaStreamRequestResult::OK, nullptr);
}

bool ElectronBrowserContext::ChooseDisplayMediaDevice(
    const content::MediaStreamRequest& request,
    content::MediaResponseCallback callback) {
  if (!display_media_request_handler_)
    return false;
  DisplayMediaResponseCallbackJs callbackJs =
      base::BindOnce(&DisplayMediaDeviceChosen, request, std::move(callback));
  display_media_request_handler_.Run(request, std::move(callbackJs));
  return true;
}

void ElectronBrowserContext::GrantDevicePermission(
    const url::Origin& origin,
    const base::Value& device,
    blink::PermissionType permission_type) {
  granted_devices_[permission_type][origin].push_back(
      std::make_unique<base::Value>(device.Clone()));
}

void ElectronBrowserContext::RevokeDevicePermission(
    const url::Origin& origin,
    const base::Value& device,
    blink::PermissionType permission_type) {
  const auto& current_devices_it = granted_devices_.find(permission_type);
  if (current_devices_it == granted_devices_.end())
    return;

  const auto& origin_devices_it = current_devices_it->second.find(origin);
  if (origin_devices_it == current_devices_it->second.end())
    return;

  for (auto it = origin_devices_it->second.begin();
       it != origin_devices_it->second.end();) {
    if (DoesDeviceMatch(device, it->get(), permission_type)) {
      it = origin_devices_it->second.erase(it);
    } else {
      ++it;
    }
  }
}

bool ElectronBrowserContext::DoesDeviceMatch(
    const base::Value& device,
    const base::Value* device_to_compare,
    blink::PermissionType permission_type) {
  if (permission_type ==
      static_cast<blink::PermissionType>(
          WebContentsPermissionHelper::PermissionType::HID)) {
    if (device.GetDict().FindInt(kHidVendorIdKey) !=
            device_to_compare->GetDict().FindInt(kHidVendorIdKey) ||
        device.GetDict().FindInt(kHidProductIdKey) !=
            device_to_compare->GetDict().FindInt(kHidProductIdKey)) {
      return false;
    }

    const auto* serial_number =
        device_to_compare->GetDict().FindString(kHidSerialNumberKey);
    const auto* device_serial_number =
        device.GetDict().FindString(kHidSerialNumberKey);

    if (serial_number && device_serial_number &&
        *device_serial_number == *serial_number)
      return true;
  } else if (permission_type ==
             static_cast<blink::PermissionType>(
                 WebContentsPermissionHelper::PermissionType::SERIAL)) {
#if BUILDFLAG(IS_WIN)
    const auto* instance_id = device.GetDict().FindString(kDeviceInstanceIdKey);
    const auto* port_instance_id =
        device_to_compare->GetDict().FindString(kDeviceInstanceIdKey);
    if (instance_id && port_instance_id && *instance_id == *port_instance_id)
      return true;
#else
    const auto* serial_number = device.GetDict().FindString(kSerialNumberKey);
    const auto* port_serial_number =
        device_to_compare->GetDict().FindString(kSerialNumberKey);
    if (device.GetDict().FindInt(kVendorIdKey) !=
            device_to_compare->GetDict().FindInt(kVendorIdKey) ||
        device.GetDict().FindInt(kProductIdKey) !=
            device_to_compare->GetDict().FindInt(kProductIdKey) ||
        (serial_number && port_serial_number &&
         *port_serial_number != *serial_number)) {
      return false;
    }

#if BUILDFLAG(IS_MAC)
    const auto* usb_driver_key = device.GetDict().FindString(kUsbDriverKey);
    const auto* port_usb_driver_key =
        device_to_compare->GetDict().FindString(kUsbDriverKey);
    if (usb_driver_key && port_usb_driver_key &&
        *usb_driver_key != *port_usb_driver_key) {
      return false;
    }
#endif  // BUILDFLAG(IS_MAC)
    return true;
#endif  // BUILDFLAG(IS_WIN)
  }
  return false;
}

bool ElectronBrowserContext::CheckDevicePermission(
    const url::Origin& origin,
    const base::Value& device,
    blink::PermissionType permission_type) {
  const auto& current_devices_it = granted_devices_.find(permission_type);
  if (current_devices_it == granted_devices_.end())
    return false;

  const auto& origin_devices_it = current_devices_it->second.find(origin);
  if (origin_devices_it == current_devices_it->second.end())
    return false;

  for (const auto& device_to_compare : origin_devices_it->second) {
    if (DoesDeviceMatch(device, device_to_compare.get(), permission_type))
      return true;
  }

  return false;
}

// static
ElectronBrowserContext* ElectronBrowserContext::From(
    const std::string& partition,
    bool in_memory,
    base::Value::Dict options) {
  PartitionKey key(partition, in_memory);
  ElectronBrowserContext* browser_context = browser_context_map()[key].get();
  if (browser_context) {
    return browser_context;
  }

  auto* new_context =
      new ElectronBrowserContext(partition, in_memory, std::move(options));
  browser_context_map()[key] =
      std::unique_ptr<ElectronBrowserContext>(new_context);
  return new_context;
}

}  // namespace electron
