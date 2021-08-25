# whois-gateway

Web-based whois gateway written in Python for lighttpd

## API

* <code>/w/202.12.29.175/lookup</code> or <code>/gateway.py?ip=202.12.29.175&lookup=true</code>
  * human-readable Whois result page, with a query form
* <code>/w/202.12.29.175/lookup/json</code> or <code>/gateway.py?ip=202.12.29.175&lookup=true&format=json</code>
  * Whois result in JSON
* <code>/w/202.12.29.175</code> or <code>/gateway.py?ip=202.12.29.175</code>
  * List of links to regional databases
* <code>/w/202.12.29.175/redirect/NAME</code> or <code>/gateway.py?ip=202.12.29.175&provider=NAME</code>
  * Redirect to a search result page provided by NAME

Requests are rate-limited. Your requests should not be more than 20 times per minute. Beyond that, the tool will give you ``429 Too Many Requests``.

## License

See [LICENSE.md](https://github.com/whym/whois-gateway/blob/master/LICENSE.md).
