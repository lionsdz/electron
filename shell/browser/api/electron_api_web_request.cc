// Copyright (c) 2019 GitHub, Inc.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#include "shell/browser/api/electron_api_web_request.h"

#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/stl_util.h"
#include "base/strings/string_util.h"
#include "base/values.h"
#include "extensions/browser/api/web_request/web_request_resource_type.h"
#include "gin/converter.h"
#include "gin/dictionary.h"
#include "gin/object_template_builder.h"
#include "net/http/http_content_disposition.h"
#include "shell/browser/api/electron_api_session.h"
#include "shell/browser/api/electron_api_web_contents.h"
#include "shell/browser/api/electron_api_web_frame_main.h"
#include "shell/browser/electron_browser_context.h"
#include "shell/browser/javascript_environment.h"
#include "shell/common/gin_converters/callback_converter.h"
#include "shell/common/gin_converters/frame_converter.h"
#include "shell/common/gin_converters/gurl_converter.h"
#include "shell/common/gin_converters/net_converter.h"
#include "shell/common/gin_converters/std_converter.h"
#include "shell/common/gin_converters/value_converter.h"
#include "shell/common/gin_helper/dictionary.h"
#include "shell/common/node_includes.h"

namespace gin {

template <>
struct Converter<extensions::WebRequestResourceType> {
  static v8::Local<v8::Value> ToV8(v8::Isolate* isolate,
                                   extensions::WebRequestResourceType type) {
    const char* result;
    switch (type) {
      case extensions::WebRequestResourceType::MAIN_FRAME:
        result = "mainFrame";
        break;
      case extensions::WebRequestResourceType::SUB_FRAME:
        result = "subFrame";
        break;
      case extensions::WebRequestResourceType::STYLESHEET:
        result = "stylesheet";
        break;
      case extensions::WebRequestResourceType::SCRIPT:
        result = "script";
        break;
      case extensions::WebRequestResourceType::IMAGE:
        result = "image";
        break;
      case extensions::WebRequestResourceType::FONT:
        result = "font";
        break;
      case extensions::WebRequestResourceType::OBJECT:
        result = "object";
        break;
      case extensions::WebRequestResourceType::XHR:
        result = "xhr";
        break;
      case extensions::WebRequestResourceType::PING:
        result = "ping";
        break;
      case extensions::WebRequestResourceType::CSP_REPORT:
        result = "cspReport";
        break;
      case extensions::WebRequestResourceType::MEDIA:
        result = "media";
        break;
      case extensions::WebRequestResourceType::WEB_SOCKET:
        result = "webSocket";
        break;
      case extensions::WebRequestResourceType::WEB_TRANSPORT:
        result = "webTransport";
        break;
      case extensions::WebRequestResourceType::WEBBUNDLE:
        result = "webBundle";
        break;
      default:
        result = "other";
    }
    return StringToV8(isolate, result);
  }
};

}  // namespace gin

namespace electron::api {

namespace {

const char kUserDataKey[] = "WebRequest";
constexpr int kDefaultResponseBodyMaxBytes = 1024 * 1024;
constexpr int kMaximumResponseBodyMaxBytes = 16 * 1024 * 1024;

// BrowserContext <=> WebRequest relationship.
struct UserData : public base::SupportsUserData::Data {
  explicit UserData(WebRequest* data) : data(data) {}
  WebRequest* data;
};

bool ParseWebRequestResourceType(const std::string& text,
                                 extensions::WebRequestResourceType* type) {
  if (text == "mainFrame" || text == "main_frame") {
    *type = extensions::WebRequestResourceType::MAIN_FRAME;
  } else if (text == "subFrame" || text == "sub_frame") {
    *type = extensions::WebRequestResourceType::SUB_FRAME;
  } else if (text == "stylesheet") {
    *type = extensions::WebRequestResourceType::STYLESHEET;
  } else if (text == "script") {
    *type = extensions::WebRequestResourceType::SCRIPT;
  } else if (text == "image") {
    *type = extensions::WebRequestResourceType::IMAGE;
  } else if (text == "font") {
    *type = extensions::WebRequestResourceType::FONT;
  } else if (text == "object") {
    *type = extensions::WebRequestResourceType::OBJECT;
  } else if (text == "xhr" || text == "xmlhttprequest") {
    *type = extensions::WebRequestResourceType::XHR;
  } else if (text == "ping") {
    *type = extensions::WebRequestResourceType::PING;
  } else if (text == "cspReport" || text == "csp_report") {
    *type = extensions::WebRequestResourceType::CSP_REPORT;
  } else if (text == "media") {
    *type = extensions::WebRequestResourceType::MEDIA;
  } else if (text == "webSocket" || text == "websocket") {
    *type = extensions::WebRequestResourceType::WEB_SOCKET;
  } else if (text == "webTransport" || text == "webtransport") {
    *type = extensions::WebRequestResourceType::WEB_TRANSPORT;
  } else if (text == "webBundle" || text == "webbundle") {
    *type = extensions::WebRequestResourceType::WEBBUNDLE;
  } else if (text == "other") {
    *type = extensions::WebRequestResourceType::OTHER;
  } else {
    return false;
  }
  return true;
}

std::string NormalizeContentType(std::string content_type) {
  const size_t semicolon = content_type.find(';');
  if (semicolon != std::string::npos)
    content_type = content_type.substr(0, semicolon);
  std::string trimmed;
  base::TrimWhitespaceASCII(content_type, base::TRIM_ALL, &trimmed);
  return base::ToLowerASCII(trimmed);
}

std::string GetResponseMimeType(
    const network::mojom::URLResponseHead& response) {
  std::string mime_type;
  if (response.headers)
    response.headers->GetMimeType(&mime_type);
  if (mime_type.empty())
    mime_type = response.mime_type;
  return NormalizeContentType(std::move(mime_type));
}

bool MatchesContentType(const std::string& mime_type,
                        const std::set<std::string>& patterns) {
  if (patterns.empty())
    return true;

  if (mime_type.empty())
    return false;

  for (const auto& pattern : patterns) {
    if (pattern == "*/*" || pattern == mime_type)
      return true;

    const size_t slash = pattern.find('/');
    if (slash != std::string::npos && pattern.substr(slash + 1) == "*" &&
        mime_type.compare(0, slash + 1, pattern, 0, slash + 1) == 0) {
      return true;
    }
  }
  return false;
}

// Test whether the URL of |request| matches |patterns|.
bool MatchesFilterCondition(extensions::WebRequestInfo* info,
                            const std::set<URLPattern>& patterns) {
  if (patterns.empty())
    return true;

  for (const auto& pattern : patterns) {
    if (pattern.MatchesURL(info->url))
      return true;
  }
  return false;
}

// Convert HttpResponseHeaders to V8.
//
// Note that while we already have converters for HttpResponseHeaders, we can
// not use it because it lowercases the header keys, while the webRequest has
// to pass the original keys.
v8::Local<v8::Value> HttpResponseHeadersToV8(
    net::HttpResponseHeaders* headers) {
  base::Value::Dict response_headers;
  if (headers) {
    size_t iter = 0;
    std::string key;
    std::string value;
    while (headers->EnumerateHeaderLines(&iter, &key, &value)) {
      // Note that Web servers not developed with nodejs allow non-utf8
      // characters in content-disposition's filename field. Use Chromium's
      // HttpContentDisposition class to decode the correct encoding instead of
      // arbitrarily converting it to UTF8. It should also be noted that if the
      // encoding is not specified, HttpContentDisposition will transcode
      // according to the system's encoding.
      if (base::EqualsCaseInsensitiveASCII("Content-Disposition", key) &&
          !value.empty()) {
        net::HttpContentDisposition header(value, std::string());
        std::string decodedFilename =
            header.is_attachment() ? " attachment" : " inline";
        // The filename must be encased in double quotes for serialization
        // to happen correctly.
        std::string filename = "\"" + header.filename() + "\"";
        value = decodedFilename + "; filename=" + filename;
      }
      base::Value::List* values = response_headers.FindList(key);
      if (!values)
        values = &response_headers.Set(key, base::Value::List())->GetList();
      values->Append(base::Value(value));
    }
  }
  return gin::ConvertToV8(v8::Isolate::GetCurrent(),
                          base::Value(std::move(response_headers)));
}

// Overloaded by multiple types to fill the |details| object.
void ToDictionary(gin_helper::Dictionary* details,
                  extensions::WebRequestInfo* info) {
  details->Set("id", info->id);
  details->Set("url", info->url);
  details->Set("method", info->method);
  details->Set("timestamp", base::Time::Now().ToDoubleT() * 1000);
  details->Set("resourceType", info->web_request_type);
  if (!info->response_ip.empty())
    details->Set("ip", info->response_ip);
  if (info->response_headers) {
    details->Set("fromCache", info->response_from_cache);
    details->Set("statusLine", info->response_headers->GetStatusLine());
    details->Set("statusCode", info->response_headers->response_code());
    details->Set("responseHeaders",
                 HttpResponseHeadersToV8(info->response_headers.get()));
  }

  auto* render_frame_host = content::RenderFrameHost::FromID(
      info->render_process_id, info->frame_routing_id);
  if (render_frame_host) {
    details->SetGetter("frame", render_frame_host);
    auto* web_contents =
        content::WebContents::FromRenderFrameHost(render_frame_host);
    auto* api_web_contents = WebContents::From(web_contents);
    if (api_web_contents) {
      details->Set("webContents", api_web_contents);
      details->Set("webContentsId", api_web_contents->ID());
    }
  }
}

void ToDictionary(gin_helper::Dictionary* details,
                  const network::ResourceRequest& request) {
  details->Set("referrer", request.referrer);
  if (request.request_body)
    details->Set("uploadData", *request.request_body);
}

void ToDictionary(gin_helper::Dictionary* details,
                  const net::HttpRequestHeaders& headers) {
  details->Set("requestHeaders", headers);
}

void ToDictionary(gin_helper::Dictionary* details, const GURL& location) {
  details->Set("redirectURL", location);
}

void ToDictionary(gin_helper::Dictionary* details, int net_error) {
  details->Set("error", net::ErrorToString(net_error));
}

// Helper function to fill |details| with arbitrary |args|.
template <typename Arg>
void FillDetails(gin_helper::Dictionary* details, Arg arg) {
  ToDictionary(details, arg);
}

template <typename Arg, typename... Args>
void FillDetails(gin_helper::Dictionary* details, Arg arg, Args... args) {
  ToDictionary(details, arg);
  FillDetails(details, args...);
}

// Fill the native types with the result from the response object.
void ReadFromResponse(v8::Isolate* isolate,
                      gin::Dictionary* response,
                      GURL* new_location) {
  response->Get("redirectURL", new_location);
}

void ReadFromResponse(v8::Isolate* isolate,
                      gin::Dictionary* response,
                      net::HttpRequestHeaders* headers) {
  v8::Local<v8::Value> value;
  if (response->Get("requestHeaders", &value) && value->IsObject()) {
    headers->Clear();
    gin::Converter<net::HttpRequestHeaders>::FromV8(isolate, value, headers);
  }
}

void ReadFromResponse(v8::Isolate* isolate,
                      gin::Dictionary* response,
                      const std::pair<scoped_refptr<net::HttpResponseHeaders>*,
                                      const std::string>& headers) {
  std::string status_line;
  if (!response->Get("statusLine", &status_line))
    status_line = headers.second;
  v8::Local<v8::Value> value;
  if (response->Get("responseHeaders", &value) && value->IsObject()) {
    *headers.first = new net::HttpResponseHeaders("");
    (*headers.first)->ReplaceStatusLine(status_line);
    gin::Converter<net::HttpResponseHeaders*>::FromV8(isolate, value,
                                                      (*headers.first).get());
  }
}

}  // namespace

gin::WrapperInfo WebRequest::kWrapperInfo = {gin::kEmbedderNativeGin};

WebRequest::SimpleListenerInfo::SimpleListenerInfo(
    std::set<URLPattern> patterns_,
    SimpleListener listener_)
    : url_patterns(std::move(patterns_)), listener(listener_) {}
WebRequest::SimpleListenerInfo::SimpleListenerInfo() = default;
WebRequest::SimpleListenerInfo::~SimpleListenerInfo() = default;

WebRequest::ResponseListenerInfo::ResponseListenerInfo(
    std::set<URLPattern> patterns_,
    ResponseListener listener_)
    : url_patterns(std::move(patterns_)), listener(listener_) {}
WebRequest::ResponseListenerInfo::ResponseListenerInfo() = default;
WebRequest::ResponseListenerInfo::~ResponseListenerInfo() = default;

WebRequest::ResponseBodyListenerInfo::ResponseBodyListenerInfo(
    std::set<URLPattern> patterns_,
    std::set<extensions::WebRequestResourceType> resource_types_,
    std::set<std::string> content_types_,
    size_t max_bytes_,
    uint64_t generation_,
    ResponseBodyListener listener_)
    : url_patterns(std::move(patterns_)),
      resource_types(std::move(resource_types_)),
      content_types(std::move(content_types_)),
      max_bytes(max_bytes_),
      generation(generation_),
      listener(listener_) {}
WebRequest::ResponseBodyListenerInfo::ResponseBodyListenerInfo() = default;
WebRequest::ResponseBodyListenerInfo::~ResponseBodyListenerInfo() = default;

WebRequest::WebRequest(v8::Isolate* isolate,
                       content::BrowserContext* browser_context)
    : browser_context_(browser_context) {
  browser_context_->SetUserData(kUserDataKey, std::make_unique<UserData>(this));
}

WebRequest::~WebRequest() {
  browser_context_->RemoveUserData(kUserDataKey);
}

gin::ObjectTemplateBuilder WebRequest::GetObjectTemplateBuilder(
    v8::Isolate* isolate) {
  return gin::Wrappable<WebRequest>::GetObjectTemplateBuilder(isolate)
      .SetMethod(
          "onBeforeRequest",
          &WebRequest::SetResponseListener<ResponseEvent::kOnBeforeRequest>)
      .SetMethod(
          "onBeforeSendHeaders",
          &WebRequest::SetResponseListener<ResponseEvent::kOnBeforeSendHeaders>)
      .SetMethod(
          "onHeadersReceived",
          &WebRequest::SetResponseListener<ResponseEvent::kOnHeadersReceived>)
      .SetMethod("onSendHeaders",
                 &WebRequest::SetSimpleListener<SimpleEvent::kOnSendHeaders>)
      .SetMethod("onBeforeRedirect",
                 &WebRequest::SetSimpleListener<SimpleEvent::kOnBeforeRedirect>)
      .SetMethod(
          "onResponseStarted",
          &WebRequest::SetSimpleListener<SimpleEvent::kOnResponseStarted>)
      .SetMethod("onResponseBody", &WebRequest::SetResponseBodyListener)
      .SetMethod("onErrorOccurred",
                 &WebRequest::SetSimpleListener<SimpleEvent::kOnErrorOccurred>)
      .SetMethod("onCompleted",
                 &WebRequest::SetSimpleListener<SimpleEvent::kOnCompleted>);
}

const char* WebRequest::GetTypeName() {
  return "WebRequest";
}

bool WebRequest::HasListener() const {
  return !(simple_listeners_.empty() && response_listeners_.empty() &&
           !response_body_listener_);
}

int WebRequest::OnBeforeRequest(extensions::WebRequestInfo* info,
                                const network::ResourceRequest& request,
                                net::CompletionOnceCallback callback,
                                GURL* new_url) {
  return HandleResponseEvent(ResponseEvent::kOnBeforeRequest, info,
                             std::move(callback), new_url, request);
}

int WebRequest::OnBeforeSendHeaders(extensions::WebRequestInfo* info,
                                    const network::ResourceRequest& request,
                                    BeforeSendHeadersCallback callback,
                                    net::HttpRequestHeaders* headers) {
  return HandleResponseEvent(
      ResponseEvent::kOnBeforeSendHeaders, info,
      base::BindOnce(std::move(callback), std::set<std::string>(),
                     std::set<std::string>()),
      headers, request, *headers);
}

int WebRequest::OnHeadersReceived(
    extensions::WebRequestInfo* info,
    const network::ResourceRequest& request,
    net::CompletionOnceCallback callback,
    const net::HttpResponseHeaders* original_response_headers,
    scoped_refptr<net::HttpResponseHeaders>* override_response_headers,
    GURL* allowed_unsafe_redirect_url) {
  const std::string& status_line =
      original_response_headers ? original_response_headers->GetStatusLine()
                                : std::string();
  return HandleResponseEvent(
      ResponseEvent::kOnHeadersReceived, info, std::move(callback),
      std::make_pair(override_response_headers, status_line), request);
}

void WebRequest::OnSendHeaders(extensions::WebRequestInfo* info,
                               const network::ResourceRequest& request,
                               const net::HttpRequestHeaders& headers) {
  HandleSimpleEvent(SimpleEvent::kOnSendHeaders, info, request, headers);
}

void WebRequest::OnBeforeRedirect(extensions::WebRequestInfo* info,
                                  const network::ResourceRequest& request,
                                  const GURL& new_location) {
  HandleSimpleEvent(SimpleEvent::kOnBeforeRedirect, info, request,
                    new_location);
}

void WebRequest::OnResponseStarted(extensions::WebRequestInfo* info,
                                   const network::ResourceRequest& request) {
  HandleSimpleEvent(SimpleEvent::kOnResponseStarted, info, request);
}

bool WebRequest::ShouldCaptureResponseBody(
    extensions::WebRequestInfo* info,
    const network::ResourceRequest&,
    const network::mojom::URLResponseHead& response,
    size_t* max_bytes) {
  if (!response_body_listener_)
    return false;

  if (!MatchesFilterCondition(info, response_body_listener_->url_patterns))
    return false;

  if (!response_body_listener_->resource_types.empty() &&
      !base::Contains(response_body_listener_->resource_types,
                      info->web_request_type)) {
    return false;
  }

  if (!MatchesContentType(GetResponseMimeType(response),
                          response_body_listener_->content_types)) {
    return false;
  }

  response_body_capture_generations_[info->id] =
      response_body_listener_->generation;
  *max_bytes = response_body_listener_->max_bytes;
  return true;
}

void WebRequest::OnResponseBody(extensions::WebRequestInfo* info,
                                const network::ResourceRequest& request,
                                const network::mojom::URLResponseHead& response,
                                std::vector<uint8_t> body,
                                bool truncated) {
  const auto capture = response_body_capture_generations_.find(info->id);
  if (capture == response_body_capture_generations_.end())
    return;
  const uint64_t capture_generation = capture->second;
  response_body_capture_generations_.erase(capture);
  if (!response_body_listener_ ||
      response_body_listener_->generation != capture_generation) {
    return;
  }

  const size_t max_bytes = response_body_listener_->max_bytes;
  ResponseBodyListener listener = response_body_listener_->listener;

  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  v8::HandleScope handle_scope(isolate);
  gin_helper::Dictionary details(isolate, v8::Object::New(isolate));
  FillDetails(&details, info, request);
  details.Set("mimeType", GetResponseMimeType(response));
  details.Set("bodySize", static_cast<double>(body.size()));
  details.Set("bodyTruncated", truncated);
  details.Set("maxBytes", static_cast<double>(max_bytes));
  if (body.empty()) {
    details.Set("body", node::Buffer::New(isolate, 0).ToLocalChecked());
  } else {
    details.Set("body", node::Buffer::Copy(
                            isolate, reinterpret_cast<const char*>(body.data()),
                            body.size())
                            .ToLocalChecked());
  }

  listener.Run(gin::ConvertToV8(isolate, details));
}

void WebRequest::OnErrorOccurred(extensions::WebRequestInfo* info,
                                 const network::ResourceRequest& request,
                                 int net_error) {
  callbacks_.erase(info->id);
  response_body_capture_generations_.erase(info->id);

  HandleSimpleEvent(SimpleEvent::kOnErrorOccurred, info, request, net_error);
}

void WebRequest::OnCompleted(extensions::WebRequestInfo* info,
                             const network::ResourceRequest& request,
                             int net_error) {
  callbacks_.erase(info->id);
  response_body_capture_generations_.erase(info->id);

  HandleSimpleEvent(SimpleEvent::kOnCompleted, info, request, net_error);
}

void WebRequest::OnRequestWillBeDestroyed(extensions::WebRequestInfo* info) {
  callbacks_.erase(info->id);
  response_body_capture_generations_.erase(info->id);
}

template <WebRequest::SimpleEvent event>
void WebRequest::SetSimpleListener(gin::Arguments* args) {
  SetListener<SimpleListener>(event, &simple_listeners_, args);
}

template <WebRequest::ResponseEvent event>
void WebRequest::SetResponseListener(gin::Arguments* args) {
  SetListener<ResponseListener>(event, &response_listeners_, args);
}

void WebRequest::SetResponseBodyListener(gin::Arguments* args) {
  v8::Isolate* isolate = args->isolate();
  v8::Local<v8::Value> arg;
  if (!args->GetNext(&arg)) {
    args->ThrowTypeError("Must pass a filter and null or a Function");
    return;
  }

  if (arg->IsNull()) {
    ++response_body_listener_generation_;
    response_body_listener_.reset();
    return;
  }

  if (arg->IsFunction()) {
    args->ThrowTypeError("onResponseBody requires a filter with 'urls'.");
    return;
  }

  std::set<std::string> filter_patterns;
  std::set<std::string> resource_type_names;
  std::set<std::string> content_type_names;
  int max_bytes = kDefaultResponseBodyMaxBytes;
  gin::Dictionary dict(isolate);
  if (!gin::ConvertFromV8(isolate, arg, &dict)) {
    args->ThrowTypeError("Parameter 'filter' must be an object.");
    return;
  }

  if (!dict.Get("urls", &filter_patterns) || filter_patterns.empty()) {
    args->ThrowTypeError("Parameter 'filter' must have property 'urls'.");
    return;
  }
  dict.Get("resourceTypes", &resource_type_names);
  if (!dict.Get("contentTypes", &content_type_names) ||
      content_type_names.empty()) {
    args->ThrowTypeError(
        "Parameter 'filter' must have property 'contentTypes'.");
    return;
  }
  dict.Get("maxBytes", &max_bytes);
  if (max_bytes <= 0 || max_bytes > kMaximumResponseBodyMaxBytes) {
    args->ThrowTypeError(
        "Parameter 'filter.maxBytes' must be between 1 and 16777216.");
    return;
  }

  if (!args->GetNext(&arg)) {
    args->ThrowTypeError("Must pass null or a Function");
    return;
  }

  ResponseBodyListener listener;
  if (!(gin::ConvertFromV8(isolate, arg, &listener) || arg->IsNull())) {
    args->ThrowTypeError("Must pass null or a Function");
    return;
  }

  if (listener.is_null()) {
    ++response_body_listener_generation_;
    response_body_listener_.reset();
    return;
  }

  std::set<URLPattern> patterns;
  for (const std::string& filter_pattern : filter_patterns) {
    URLPattern pattern(URLPattern::SCHEME_ALL);
    const URLPattern::ParseResult result = pattern.Parse(filter_pattern);
    if (result == URLPattern::ParseResult::kSuccess) {
      patterns.insert(pattern);
    } else {
      const char* error_type = URLPattern::GetParseResultString(result);
      args->ThrowTypeError("Invalid url pattern " + filter_pattern + ": " +
                           error_type);
      return;
    }
  }

  std::set<extensions::WebRequestResourceType> resource_types;
  if (resource_type_names.empty()) {
    resource_types.insert(extensions::WebRequestResourceType::XHR);
  } else {
    for (const auto& resource_type_name : resource_type_names) {
      extensions::WebRequestResourceType resource_type;
      if (!ParseWebRequestResourceType(resource_type_name, &resource_type)) {
        args->ThrowTypeError("Invalid resourceType " + resource_type_name);
        return;
      }
      resource_types.insert(resource_type);
    }
  }

  std::set<std::string> content_types;
  for (auto content_type : content_type_names) {
    content_type = NormalizeContentType(std::move(content_type));
    if (!content_type.empty())
      content_types.insert(std::move(content_type));
  }
  if (content_types.empty()) {
    args->ThrowTypeError(
        "Parameter 'filter.contentTypes' must contain a MIME type.");
    return;
  }

  const uint64_t generation = ++response_body_listener_generation_;
  response_body_listener_ = std::make_unique<ResponseBodyListenerInfo>(
      std::move(patterns), std::move(resource_types), std::move(content_types),
      static_cast<size_t>(max_bytes), generation, std::move(listener));
}

template <typename Listener, typename Listeners, typename Event>
void WebRequest::SetListener(Event event,
                             Listeners* listeners,
                             gin::Arguments* args) {
  v8::Local<v8::Value> arg;

  // { urls }.
  std::set<std::string> filter_patterns;
  gin::Dictionary dict(args->isolate());
  if (args->GetNext(&arg) && !arg->IsFunction()) {
    // Note that gin treats Function as Dictionary when doing conversions, so we
    // have to explicitly check if the argument is Function before trying to
    // convert it to Dictionary.
    if (gin::ConvertFromV8(args->isolate(), arg, &dict)) {
      if (!dict.Get("urls", &filter_patterns)) {
        args->ThrowTypeError("Parameter 'filter' must have property 'urls'.");
        return;
      }
      args->GetNext(&arg);
    }
  }

  std::set<URLPattern> patterns;
  for (const std::string& filter_pattern : filter_patterns) {
    URLPattern pattern(URLPattern::SCHEME_ALL);
    const URLPattern::ParseResult result = pattern.Parse(filter_pattern);
    if (result == URLPattern::ParseResult::kSuccess) {
      patterns.insert(pattern);
    } else {
      const char* error_type = URLPattern::GetParseResultString(result);
      args->ThrowTypeError("Invalid url pattern " + filter_pattern + ": " +
                           error_type);
      return;
    }
  }

  // Function or null.
  Listener listener;
  if (arg.IsEmpty() ||
      !(gin::ConvertFromV8(args->isolate(), arg, &listener) || arg->IsNull())) {
    args->ThrowTypeError("Must pass null or a Function");
    return;
  }

  if (listener.is_null())
    listeners->erase(event);
  else
    (*listeners)[event] = {std::move(patterns), std::move(listener)};
}

template <typename... Args>
void WebRequest::HandleSimpleEvent(SimpleEvent event,
                                   extensions::WebRequestInfo* request_info,
                                   Args... args) {
  const auto iter = simple_listeners_.find(event);
  if (iter == std::end(simple_listeners_))
    return;

  const auto& info = iter->second;
  if (!MatchesFilterCondition(request_info, info.url_patterns))
    return;

  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  v8::HandleScope handle_scope(isolate);
  gin_helper::Dictionary details(isolate, v8::Object::New(isolate));
  FillDetails(&details, request_info, args...);
  info.listener.Run(gin::ConvertToV8(isolate, details));
}

template <typename Out, typename... Args>
int WebRequest::HandleResponseEvent(ResponseEvent event,
                                    extensions::WebRequestInfo* request_info,
                                    net::CompletionOnceCallback callback,
                                    Out out,
                                    Args... args) {
  const auto iter = response_listeners_.find(event);
  if (iter == std::end(response_listeners_))
    return net::OK;

  const auto& info = iter->second;
  if (!MatchesFilterCondition(request_info, info.url_patterns))
    return net::OK;

  callbacks_[request_info->id] = std::move(callback);

  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  v8::HandleScope handle_scope(isolate);
  gin_helper::Dictionary details(isolate, v8::Object::New(isolate));
  FillDetails(&details, request_info, args...);

  ResponseCallback response =
      base::BindOnce(&WebRequest::OnListenerResult<Out>, base::Unretained(this),
                     request_info->id, out);
  info.listener.Run(gin::ConvertToV8(isolate, details), std::move(response));
  return net::ERR_IO_PENDING;
}

template <typename T>
void WebRequest::OnListenerResult(uint64_t id,
                                  T out,
                                  v8::Local<v8::Value> response) {
  const auto iter = callbacks_.find(id);
  if (iter == std::end(callbacks_))
    return;

  int result = net::OK;
  if (response->IsObject()) {
    v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
    gin::Dictionary dict(isolate, response.As<v8::Object>());

    bool cancel = false;
    dict.Get("cancel", &cancel);
    if (cancel)
      result = net::ERR_BLOCKED_BY_CLIENT;
    else
      ReadFromResponse(isolate, &dict, out);
  }

  // The ProxyingURLLoaderFactory expects the callback to be executed
  // asynchronously, because it used to work on IO thread before NetworkService.
  base::SequencedTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(std::move(callbacks_[id]), result));
  callbacks_.erase(iter);
}

// static
gin::Handle<WebRequest> WebRequest::FromOrCreate(
    v8::Isolate* isolate,
    content::BrowserContext* browser_context) {
  gin::Handle<WebRequest> handle = From(isolate, browser_context);
  if (handle.IsEmpty()) {
    // Make sure the |Session| object has the |webRequest| property created.
    v8::Local<v8::Value> web_request =
        Session::CreateFrom(
            isolate, static_cast<ElectronBrowserContext*>(browser_context))
            ->WebRequest(isolate);
    gin::ConvertFromV8(isolate, web_request, &handle);
  }
  DCHECK(!handle.IsEmpty());
  return handle;
}

// static
gin::Handle<WebRequest> WebRequest::Create(
    v8::Isolate* isolate,
    content::BrowserContext* browser_context) {
  DCHECK(From(isolate, browser_context).IsEmpty())
      << "WebRequest already created";
  return gin::CreateHandle(isolate, new WebRequest(isolate, browser_context));
}

// static
gin::Handle<WebRequest> WebRequest::From(
    v8::Isolate* isolate,
    content::BrowserContext* browser_context) {
  if (!browser_context)
    return gin::Handle<WebRequest>();
  auto* user_data =
      static_cast<UserData*>(browser_context->GetUserData(kUserDataKey));
  if (!user_data)
    return gin::Handle<WebRequest>();
  return gin::CreateHandle(isolate, user_data->data);
}

}  // namespace electron::api
