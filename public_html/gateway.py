#! /usr/bin/env python
import sys
sys.path.insert(0, '/data/project/whois/local/lib/python2.7/site-packages')

from ipwhois import IPWhois
import cgitb
import cgi
import json
import os

if __name__ == '__main__':
        SITE = '//tools.wmflabs.org/whois'
        providers = {
                'ARIN': lambda x: 'http://whois.arin.net/rest/ip/' + x,
                'RIPE': lambda x: 'https://apps.db.ripe.net/search/query.html?searchtext=%s#resultsAnchor' % x,
                'APNIC': lambda x: 'http://wq.apnic.net/apnic-bin/whois.pl?searchtext=' + x,
                'LACNIC': lambda x: 'http://lacnic.net/cgi-bin/lacnic/whois?lg=EN&amp;query=' + x
        }
        cgitb.enable(display=0, logdir='/data/project/whois/logs')
        form = cgi.FieldStorage()
        ip = form.getfirst('ip', '')
        provider = form.getfirst('provider', '').upper()
        fmt = form.getfirst('format', 'html').lower()
        doLookup = form.getfirst('lookup', 'false').lower() != 'false'

        result = ''
        error = False
        if doLookup:
                try:
                        query = IPWhois(ip)
                        result = query.lookup()
                except ValueError as e:
                        result = {'error': str(e)}
                        error = True
        
        if providers.has_key(provider):
                print 'Location: %s' % providers[provider](ip)
                print ''
                exit()

        if fmt == 'json' and doLookup:
                print 'Content-type: text/plain'
                print ''
                print result
                exit()
                
        print 'Content-type: text/html'
        print ''
        print '''<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8">
<link rel="stylesheet" href="%(site)s/css/bootstrap.min.css">
<link rel="stylesheet" href="%(site)s/css/bootstrap-theme.min.css">
<!-- <script src="%(site)s/js/bootstrap.min.js"></script> -->
<title>Whois Gateway</title>
</head>
<body>
<div class="container">
<header><h1>Whois Gateway</h1></header>

<div class="alert alert-warning" role="alert"><strong>This tool is expereimental.</strong> The URL and functionalities are not stable.</div>

<div class="row">
<div class="col-sm-9">
''' % {'site': SITE}
        print '''
<form action="%(site)s/index.py">
<input type="hidden" name="lookup" value="true"/>
<div class="row form-group %(error)s">
<div class="col-sm-10"><input type="text" name="ip" value="%(ip)s" class="form-control" %(af)s/></div>
<div class="col-sm-2"><input type="submit" value="Lookup" class="btn btn-default btn-block"/></div>
</div>
</form>
''' % ({'site': SITE, 'ip': ip, 'error': 'has-error' if error else '', 'af': 'autofocus onFocus="this.select();"' if not doLookup or error else ''})
        if doLookup:
                print '<pre>%s</pre>' % json.dumps(result, indent=4)
        print '''
</div>
<div class="col-sm-3">
<h2>External links</h2>
<ul class="list-unstyled">
'''
        for (name,q) in sorted(providers.items()):
                print '<li><a href="%s"><strong>%s</strong>@%s</a></li>' % (q(ip), ip, name)
        print '</ul>'

print '''
</div>
</div>
<h2>Usage</h2>
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
</div>
<footer><div class="container">
<hr>
<p class="text-center text-muted"><a href="https://tools.wmflabs.org/?tool=whois">Whois Gateway</a> on <a href="https://tools.wmflabs.org">Tool Labs</a></p></div></footer>
</body></html>
''' % {'site': SITE}
