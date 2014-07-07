#! /usr/bin/env python
import sys
sys.path.insert(0, '/data/project/whois/local/lib/python2.7/site-packages')

import cgitb
import cgi
from ipwhois import IPWhois
import json

if __name__ == '__main__':
        SITE = 'http://tools.wmflabs.org/whois'
        providers = {
                "ARIN": lambda x: "http://whois.arin.net/rest/ip/" + x,
                "RIPE": lambda x: "https://apps.db.ripe.net/search/query.html?searchtext=%s#resultsAnchor" % x,
                "APNIC": lambda x: "http://wq.apnic.net/apnic-bin/whois.pl?searchtext=" + x,
                "LACNIC": lambda x: "http://lacnic.net/cgi-bin/lacnic/whois?lg=EN&query=" + x
        }
        cgitb.enable(display=0, logdir="/data/project/whois/logs")
        form = cgi.FieldStorage()
        ip = form.getfirst("ip", "")
        provider = form.getfirst("provider", "").upper()
        fmt = form.getfirst("format", "html").lower()
        doLookup = form.getfirst("lookup", "")

        result = ''
        if doLookup != '':
                query = IPWhois(ip)
                result = query.lookup()
        
        if providers.has_key(provider):
                print "Location: %s" % providers[provider](ip)
                print ""
                exit()

        if fmt == 'json' and doLookup:
                print "Content-type: text/plain"
                print ""
                print result
                exit()
                
        print "Content-type: text/html"
        print ""
        print '''<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8">
<link rel="stylesheet" href="%(site)s/css/bootstrap.min.css">
<link rel="stylesheet" href="%(site)s/css/bootstrap-theme.min.css">
<script src="%(site)s/js/bootstrap.min.js"></script>
<style type="text/css">
li a { display: inline-block; padding: .2em 0; font: normal normal sans-serif; }
</style>
<title>Whois Gateway</title>
</head.
<body>
<div class="container">
<header><h1>Whois Gateway</h1></header>

<div class="alert alert-warning" role="alert"><strong>This tool is expereimental.</strong> The URL and functionalities are not stable.</div>

<div class="row">
<div class="col-md-9">
''' % {'site': SITE}
        if doLookup:
                print '<h2>Result</h2><pre>%s</pre>' % json.dumps(result, indent=4)
        else:
                print '<a class="btn btn-default btn-lg" href="%(site)s/%(ip)s/lookup">Lookup %(ip)s</a>' % {'site': SITE, 'ip': ip}
        print '''
</div>
<div class="col-md-3">
<h2>External links</h2>
<ul>
'''
        for (name,q) in sorted(providers.items()):
                print '<li><a href="%s"><em>%s</em>@%s</a></li>' % (q(ip), ip, name)
        print "</ul>"

print '''
</div>
</div>
<h2>Usage<a name="usage"></a></h2>
<dl>
<dt><code>%(site)s/IPADDRESS/lookup</code></dt>
<dd>Whois result</dd>
<dt><code>%(site)s/IPADDRESS/lookup/json</code></dt>
<dd>Whois result in JSON</dd>
<dt><code>%(site)s/IPADDRESS</code></dt>
<dd>List of links to regional databases</dd>
<dt><code>%(site)s/IPADDRESS/redirect/NAME</code></dt>
<dd>Redirect to a search result page provided by NAME.<dd>
</dl>

</body></html>
''' % {'site': SITE}
