#! /usr/bin/env python
import sys
sys.path.insert(0, '/data/project/whois/local/lib/python2.7/site-packages')

import cgitb
import cgi
from ipwhois import IPWhois
import json

if __name__ == '__main__':
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
        print '''
<style type="text/css">
li a { display: inline-block; padding: .2em 0; font: normal normal sans-serif; }
#result { border: 1px solid; }
</style>
<title>Whois Gateway</title>
<body>
<h1>Whois Gateway</h1>
'''
        if doLookup:
                print '<div id="result"><pre>%s</pre></div>' % json.dumps(result, indent=4)
        print '''
<h2>External links</h2>
<ul>
'''
        for (name,q) in sorted(providers.items()):
                print '<li><a href="%s"><em>%s</em>@%s</a></li>' % (q(ip), ip, name)
        print "</ul></body>"

print '''
<h2>Usage</h2>
<dl><dt>http://tools.wmflabs.org/whois/IPADDRESS/lookup</dt>
<dd>Whois result</dd>
<dt>http://tools.wmflabs.org/whois/IPADDRESS</dt>
<dd>List of links to regional databases</dd>
<dt>http://tools.wmflabs.org/whois/IPADDRESS/redirect/NAME</dt>
<dd>Redirect to a search result page provided by NAME.<dd>
</dl>

<p><strong>This tool is expereimental. The URL and functionalities are not stable.</strong></p>
'''
