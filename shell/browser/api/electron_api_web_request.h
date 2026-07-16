// Copyright (c) 2019 GitHub, Inc.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#ifndef ELECTRON_SHELL_BROWSER_API_ELECTRON_API_WEB_REQUEST_H_
#define ELECTRON_SHELL_BROWSER_API_ELECTRON_API_WEB_REQUEST_H_

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <vector>

#include "base/values.h"
#include "extensions/browser/api/web_request/web_request_resource_type.h"
#include "extensions/common/url_pattern.h"
#include "gin/arguments.h"
#include "gin/handle.h"
#include "gin/wrappable.h"
#include "shell/browser/net/web_request_api_interface.h"

namespace content {
class BrowserContext;
}

namespace electron::api {

class WebRequest : public gin::Wrappable<WebRequest>, public WebRequestAPI {
 public:
  static gin::WrapperInfo kWrapperInfo;

  // Return the WebRequest object attached to |browser_context|, create if there
  // is no one.
  // Note that the lifetime of WebRequest object is managed by Session, instead
  // of the caller.
  static gin::Handle<WebRequest> FromOrCreate(
      v8::Isolate* isolate,
      content::BrowserContext* browser_context);

  // Return a new WebRequest object, this should only be called by Session.
  static gin::Handle<WebRequest> Create(
      v8::Isolate* isolate,
      content::BrowserContext* browser_context);

  // Find the WebRequest object attached to |browser_context|.
  static gin::Handle<WebRequest> From(v8::Isolate* isolate,
                                      content::BrowserContext* browser_context);

  // gin::Wrappable:
  gin::ObjectTemplateBuilder GetObjectTemplateBuilder(
      v8::Isolate* isolate) override;
  const char* GetTypeName() override;

  // WebRequestAPI:
  bool HasListener() const override;
  int OnBeforeRequest(extensions::WebRequestInfo* info,
                      const network::ResourceRequest& request,
                      net::CompletionOnceCallback callback,
                      GURL* new_url) override;
  int OnBeforeSendHeaders(extensions::WebRequestInfo* info,
                          const network::ResourceRequest& request,
                          BeforeSendHeadersCallback callback,
                          net::HttpRequestHeaders* headers) override;
  int OnHeadersReceived(
      extensions::WebRequestInfo* info,
      const network::ResourceRequest& request,
      net::CompletionOnceCallback callback,
      const net::HttpResponseHeaders* original_response_headers,
      scoped_refptr<net::HttpResponseHeaders>* override_response_headers,
      GURL* allowed_unsafe_redirect_url) override;
  void OnSendHeaders(extensions::WebRequestInfo* info,
                     const network::ResourceRequest& request,
                     const net::HttpRequestHeaders& headers) override;
  void OnBeforeRedirect(extensions::WebRequestInfo* info,
                        const network::ResourceRequest& request,
                        const GURL& new_location) override;
  void OnResponseStarted(extensions::WebRequestInfo* info,
                         const network::ResourceRequest& request) override;
  bool ShouldCaptureResponseBody(
      extensions::WebRequestInfo* info,
      const network::ResourceRequest& request,
      const network::mojom::URLResponseHead& response,
      size_t* max_bytes) override;
  void OnResponseBody(extensions::WebRequestInfo* info,
                      const network::ResourceRequest& request,
                      const network::mojom::URLResponseHead& response,
                      std::vector<uint8_t> body,
                      bool truncated) override;
  void OnErrorOccurred(extensions::WebRequestInfo* info,
                       const network::ResourceRequest& request,
                       int net_error) override;
  void OnCompleted(extensions::WebRequestInfo* info,
                   const network::ResourceRequest& request,
                   int net_error) override;
  void OnRequestWillBeDestroyed(extensions::WebRequestInfo* info) override;

 private:
  WebRequest(v8::Isolate* isolate, content::BrowserContext* browser_context);
  ~WebRequest() override;

  enum class SimpleEvent {
    kOnSendHeaders,
    kOnBeforeRedirect,
    kOnResponseStarted,
    kOnCompleted,
    kOnErrorOccurred,
  };
  enum class ResponseEvent {
    kOnBeforeRequest,
    kOnBeforeSendHeaders,
    kOnHeadersReceived,
  };

  using SimpleListener = base::RepeatingCallback<void(v8::Local<v8::Value>)>;
  using ResponseCallback = base::OnceCallback<void(v8::Local<v8::Value>)>;
  using ResponseListener =
      base::RepeatingCallback<void(v8::Local<v8::Value>, ResponseCallback)>;
  using ResponseBodyListener =
      base::RepeatingCallback<void(v8::Local<v8::Value>)>;

  template <SimpleEvent event>
  void SetSimpleListener(gin::Arguments* args);
  template <ResponseEvent event>
  void SetResponseListener(gin::Arguments* args);
  void SetResponseBodyListener(gin::Arguments* args);
  template <typename Listener, typename Listeners, typename Event>
  void SetListener(Event event, Listeners* listeners, gin::Arguments* args);

  template <typename... Args>
  void HandleSimpleEvent(SimpleEvent event,
                         extensions::WebRequestInfo* info,
                         Args... args);
  template <typename Out, typename... Args>
  int HandleResponseEvent(ResponseEvent event,
                          extensions::WebRequestInfo* info,
                          net::CompletionOnceCallback callback,
                          Out out,
                          Args... args);

  template <typename T>
  void OnListenerResult(uint64_t id, T out, v8::Local<v8::Value> response);

  struct SimpleListenerInfo {
    std::set<URLPattern> url_patterns;
    SimpleListener listener;

    SimpleListenerInfo(std::set<URLPattern>, SimpleListener);
    SimpleListenerInfo();
    ~SimpleListenerInfo();
  };

  struct ResponseListenerInfo {
    std::set<URLPattern> url_patterns;
    ResponseListener listener;

    ResponseListenerInfo(std::set<URLPattern>, ResponseListener);
    ResponseListenerInfo();
    ~ResponseListenerInfo();
  };

  struct ResponseBodyListenerInfo {
    std::set<URLPattern> url_patterns;
    std::set<extensions::WebRequestResourceType> resource_types;
    std::set<std::string> content_types;
    size_t max_bytes = 0;
    uint64_t generation = 0;
    ResponseBodyListener listener;

    ResponseBodyListenerInfo(std::set<URLPattern>,
                             std::set<extensions::WebRequestResourceType>,
                             std::set<std::string>,
                             size_t,
                             uint64_t,
                             ResponseBodyListener);
    ResponseBodyListenerInfo();
    ~ResponseBodyListenerInfo();
  };

  std::map<SimpleEvent, SimpleListenerInfo> simple_listeners_;
  std::map<ResponseEvent, ResponseListenerInfo> response_listeners_;
  std::unique_ptr<ResponseBodyListenerInfo> response_body_listener_;
  uint64_t response_body_listener_generation_ = 0;
  std::map<uint64_t, uint64_t> response_body_capture_generations_;
  std::map<uint64_t, net::CompletionOnceCallback> callbacks_;

  // Weak-ref, it manages us.
  content::BrowserContext* browser_context_;
};

}  // namespace electron::api

#endif  // ELECTRON_SHELL_BROWSER_API_ELECTRON_API_WEB_REQUEST_H_
