# whois-gateway

Web-based whois gateway written in Python for lighttpd

## API

* <code>https://tools.wmflabs.org/whois/127.0.0.1/lookup</code> or <code>/gateway.py?ip=127.0.0.1&lookup=true</code>
  * human-readable Whois result page, with a query form
* <code>https://tools.wmflabs.org/whois/127.0.0.1/lookup/json</code> or <code>/gateway.py?ip=127.0.0.1&lookup=true&format=json</code>
  * Whois result in JSON
* <code>https://tools.wmflabs.org/whois/127.0.0.1</code> or <code>/gateway.py?ip=127.0.0.1</code>
  * List of links to regional databases
* <code>https://tools.wmflabs.org/whois/127.0.0.1/redirect/NAME</code> or <code>/gateway.py?ip=127.0.0.1&provider=NAME</code>
  * Redirect to a search result page provided by NAME

## License

See [License](https://github.com/whym/whois-gateway/blob/master/LICENSE.md).
