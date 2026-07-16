# WebRequestBodyFilter Object

* `urls` string[] - Array of [URL patterns](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Match_patterns)
  that will be used to select responses whose body can be captured.
* `resourceTypes` string[] (optional) - Array of resource types to capture.
  Supported values are `mainFrame`, `subFrame`, `stylesheet`, `script`, `image`,
  `font`, `object`, `xhr`, `ping`, `cspReport`, `media`, `webSocket`,
  `webTransport`, `webBundle` or `other`. Defaults to `['xhr']`.
* `contentTypes` string[] - Array of normalized MIME types to capture, for
  example `application/json` or `text/*`. Use an all-types wildcard to capture
  any MIME type.
* `maxBytes` Integer (optional) - Maximum number of response body bytes to copy
  for the listener. Defaults to `1048576` and cannot exceed `16777216`.
