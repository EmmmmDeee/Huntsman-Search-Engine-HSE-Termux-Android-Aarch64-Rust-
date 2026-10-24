- `domains::is_absolute_http_url` and `domains::is_tracking_param_key`, which nothing called. Each
  only forwarded to another function: use `http::parse_http_uri(s).is_ok()` and
  `canonical::is_tracking_param_key`. No output changes.
