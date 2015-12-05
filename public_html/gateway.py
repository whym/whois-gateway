#! /usr/bin/env python
import sys
sys.path.insert(0, '/data/project/whois/local/lib/python2.7/site-packages')

import six
from ipwhois import IPWhois, WhoisLookupError
import cgitb
import os
from six.moves import urllib
import cgi
import json
import socket

SITE = '//tools.wmflabs.org/whois'

LOGDIR = '/data/project/whois/logs'

PROVIDERS = {
    'ARIN': lambda x: 'http://whois.arin.net/rest/ip/' + urllib.parse.quote(x),
    'RIPENCC': lambda x: 'https://apps.db.ripe.net/search/query.html?searchtext=%s#resultsAnchor' % urllib.parse.quote(x),
    'AFRINIC': lambda x: 'http://afrinic.net/cgi-bin/whois?searchtext=' + urllib.parse.quote(x),
    'APNIC': lambda x: 'http://wq.apnic.net/apnic-bin/whois.pl?searchtext=' + urllib.parse.quote(x),
    'LACNIC': lambda x: 'http://lacnic.net/cgi-bin/lacnic/whois?lg=EN&amp;query=' + urllib.parse.quote(x)
}

TOOLS = {
    'Stalktoy': lambda x: 'https://tools.wmflabs.org/meta/stalktoy/' + x,
    'GlobalContribs': lambda x: 'https://tools.wmflabs.org/guc/index.php?user=%s&amp;blocks=true' % x,
}


def order_keys(x):
    keys = dict((y, x) for (x, y) in enumerate([
        'asn_registry', 'asn_country_code', 'asn_cidr', 'query',
        'nets', 'asn', 'asn_date',
        'name', 'description', 'address',
        'city', 'state', 'country', 'postal_code',
        'cidr', 'range', 'created', 'updated', 'handle', 'parent_handle',
        'ip_version', 'start_address', 'end_address',
        'abuse_emails', 'tech_emails', 'misc_emails']))
    if x in keys:
        return '0_%04d' % keys[x]
    else:
        return '1_%s' % x


def format_new_lines(s):
    return s.replace('\n', '<br/>')


def format_table(dct, target):
    if isinstance(dct, six.string_types):
        return format_new_lines(dct)
    if isinstance(dct, list):
        return '\n'.join(format_table(x, target) for x in dct)
    ret = '<div class="table-responsive"><table class="table table-condensed"><tbody>'
    for (k, v) in sorted(dct.items(), key=lambda x: order_keys(x[0])):
        if v is None or len(v) == 0 or v == 'NA' or v == 'None':
            ret += '<tr class="text-muted"><th>%s</th><td>%s</td></tr>' % (k, v)
        elif isinstance(v, six.string_types):
            if k == 'asn_registry' and v.upper() in PROVIDERS:
                ret += '<tr><th>%s</th><td><a href="%s"><span class="glyphicon glyphicon-link"></span>%s</a></td></tr>' % (
                    k, PROVIDERS[v.upper()](target), v.upper()
                )
            else:
                ret += '<tr><th>%s</th><td>%s</td></tr>' % (
                    k, format_new_lines(v)
                )
        else:
            ret += '<tr><th>%s</th><td>%s</td></tr>' % (k, format_table(v, target))
    ret += '</tbody></table></div>'
    return ret


def format_result(result, target):
    return '<div class="panel panel-default">%s</div>' % format_table(result, target)


def format_link_list(header, ls):
    ret = '''
<div class="panel panel-default">
<div class="panel-heading">%s</div>
<div class="list-group">
''' % header

    for (link, title, anchor, cls) in ls:
        ret += '<a class="%s" href="%s" title="%s">%s</a>\n' % (
            ' '.join(cls+['list-group-item']),
            link, title, anchor
        )
    ret += '</div></div>'
    return ret


def lookup(ip, rdap=False):
    obj = IPWhois(ip)
    if rdap:
        # TODO: RDAP output includes less relevant info, needs a dedicated formatter
        return obj.lookup_rdap()
    else:
        return obj.lookup()


if __name__ == '__main__':

    if os.path.exists(LOGDIR):
        cgitb.enable(display=0, logdir=LOGDIR)
    form = cgi.FieldStorage()
    ip = form.getfirst('ip', '')
    provider = form.getfirst('provider', '').upper()
    fmt = form.getfirst('format', 'html').lower()
    do_lookup = form.getfirst('lookup', 'false').lower() != 'false'
    use_rdap = form.getfirst('rdap', 'false').lower() != 'false'
    css = '''
.el { display: flex; flex-direction: row; align-items: baseline; }
.el-ip { flex: 0?; max-width: 70%%; overflow: hidden; text-overflow: ellipsis; padding-right: .2em; }
.el-prov { flex: 1 8em; }
th { font-size: small; }
.link-result { -moz-user-select: all; -webkit-user-select: all; -ms-user-select: all; user-select: all; }
'''

    result = {}
    error = False
    if do_lookup:
        try:
            result = lookup(ip, use_rdap)
        except Exception as e:
            result = {'error': repr(e)}
            error = True

    if provider in PROVIDERS:
        print('Location: %s' % PROVIDERS[provider](ip))
        print('')
        exit()

    if fmt == 'json' and do_lookup:
        print('Content-type: text/plain')
        print('')
        print(json.dumps(result))
        exit()

    print('''Content-type: text/html

<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8">
<link rel="stylesheet" href="//tools-static.wmflabs.org/cdnjs/ajax/libs/twitter-bootstrap/3.2.0/css/bootstrap.min.css">
<link rel="stylesheet" href="//tools-static.wmflabs.org/cdnjs/ajax/libs/twitter-bootstrap/3.2.0/css/bootstrap-theme.min.css">
<title>Whois Gateway</title>
<style type="text/css">
{css}
</style>
</head>
<body>
<div class="container">
<div class="row">
<div class="col-sm-5">
<header><h1>Whois Gateway</h1></header>
</div>
<div class="col-sm-7"><div class="alert alert-warning" role="alert">
<strong>This tool is experimental.</strong> The URL and functionalities might change.
</div></div>
</div>

<div class="row">
<div class="col-sm-9">

<form action="{site}/gateway.py" role="form">
<input type="hidden" name="lookup" value="true"/>
<div class="row form-group {error}">
<div class="col-md-10"><div class="input-group">
<label class="input-group-addon" for="ipaddress-input">IP address</label>
<input type="text" name="ip" value="{ip}" id="ipaddress-input" class="form-control" {af}/>
</div></div>
<div class="col-md-2"><input type="submit" value="Lookup" class="btn btn-default btn-block"/></div>
</div>
</form>
'''.format(site=SITE,
           css=css,
           ip=ip,
           error= 'has-error' if error else '',
           af= 'autofocus onFocus="this.select();"' if (not do_lookup or error) else ''))

    if do_lookup:
        link = 'https://tools.wmflabs.org/whois/%s/lookup' % ip
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except IOError:
            pass
        print('''
<div class="panel panel-default"><div class="panel-heading">{hostname}</div>
<div class="panel-body">{table}</div></div>

<div class="row form-group">
<div class="col-md-12"><div class="input-group">
<label class="input-group-addon"><a href="{link}">Link this result</a></label>
<output class="form-control link-result">{link}</output>
</div></div>
</div>
'''.format(hostname='<strong>%s</strong>' % hostname if hostname else '<em>(No corresponding host name retrieved)</em>',
           table=format_table(result, ip),
           link=link))

    print('''</div>
<div class="col-sm-3">
''')
    print(format_link_list(
        'Other tools',
        [(q(ip),
          'Look up %s at %s' % (ip, name),
          '<small class="el-ip">%s</small><span class="el-prov"> @%s</span>' % (ip, name),
          ['el'])
         for (name, q) in sorted(TOOLS.items())]
    ))

    print(format_link_list(
        'Sources',
        [(q(ip),
          'Look up %s at %s' % (ip, name),
          '<small class="el-ip">%s</small><span class="el-prov"> @%s</span>' % (ip, name),
          ['el', 'active'] if result.get('asn_registry', '').upper() == name else ['el'])
         for (name, q) in sorted(PROVIDERS.items())]
    ))

    print('''
</div>
</div>

<footer><div class="container">
<hr>
<p class="text-center text-muted">
<a href="https://tools.wmflabs.org/whois/">Whois Gateway</a>
<small>(<a href="https://github.com/whym/whois-gateway">source code</a>,
        <a href="https://github.com/whym/whois-gateway#api">API</a>)</small>
        on <a href="https://tools.wmflabs.org">Tool Labs</a> /
<a href="https://github.com/whym/whois-gateway/issues">Issues?</a>
</p>
</div></footer>
</div>
</body></html>''' % {'site': SITE})
