#! /usr/bin/env python

import cgitb
import cgi

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
        provider = form.getfirst("provider", "")
        if providers.has_key(provider):
                print "Location: %s" % providers[provider](ip)
                print ""
                exit()
        print "Content-type: text/html"
        print ""
        print '''
<style type="text/css">
li a { display: inline-block; padding: .2em 0; font: normal normal 120%sans-serif; }
</style>
<title>Whois Gateway</title>
<body><h1>Whois Gateway</h1>
<ul>
'''
        for (name,q) in sorted(providers.items()):
                print '<li><a href="%s"><em>%s</em>@%s</li>' % (q(ip), ip, name)
        print "</ul></body>"
