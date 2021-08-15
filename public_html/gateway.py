#! /usr/bin/env python
# -*- mode: python -*-
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
import re

SITE = '//whois.toolforge.org'

LOGDIR = '/data/project/whois/logs'

PROVIDERS = {
    'ARIN': 'https://whois.arin.net/rest/ip/{0}',
    'RIPENCC': 'https://apps.db.ripe.net/db-web-ui/query?searchtext={0}',
    'AFRINIC': 'https://rdap.afrinic.net/rdap/ip/{0}',
    'APNIC': 'https://wq.apnic.net/apnic-bin/whois.pl?searchtext={0}',
    'LACNIC': 'http://lacnic.net/cgi-bin/lacnic/whois?lg=EN&query={0}'
}

TOOLS = {
    'GlobalContribs': 'https://guc.toolforge.org/index.php?user={0}&blocks=true',
    'Proxy Checker': 'https://ipcheck.toolforge.org/index.php?ip={0}',
    'Stalktoy': 'https://meta.toolforge.org/stalktoy/{0}'
}

TOOL_URL = 'https://whois.toolforge.org/w/{0}/lookup'

SUBTITLE = "Find details about an IP address's owner"


def order_keys(x):
    keys = dict((y, x) for (x, y) in enumerate([
        'warning', 'asn_registry', 'asn_country_code', 'asn_cidr', 'query',
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


def lookup(ip, rdap=False):
    obj = IPWhois(ip)
    if rdap:
        # TODO: RDAP output includes less relevant info, needs a dedicated formatter
        return obj.lookup_rdap()
    else:
        ret = obj.lookup_whois()
        # remove some fields that clutter
        for x in []:
            ret.pop(x, None)
        return ret


def format_new_lines(s):
    return s.replace('\n', '<br/>')


def format_table(dct, target):
    if isinstance(dct, six.string_types):
        return format_new_lines(dct)
    if isinstance(dct, list):
        return '\n'.join(format_table(x, target) for x in dct)
    ret = '<table class="table table-sm"><tbody>'
    for (k, v) in sorted(dct.items(), key=lambda x: order_keys(x[0])):
        if v is None or len(v) == 0 or v == 'NA' or v == 'None':
            ret += '<tr class="text-muted"><th>%s</th><td>%s</td></tr>' % (k, v)
        elif isinstance(v, six.string_types):
            if k == 'asn_registry' and v.upper() in PROVIDERS:
                ret += '<tr><th>%s</th><td><a href="%s"><i class="fas fa-home"></i>%s</a></td></tr>' % (
                    k, PROVIDERS[v.upper()].format(target), v.upper()
                )
            elif k == 'warning':
                ret += '<tr><th class="bg-warning">%s</th><td>%s</td></tr>' % (
                    k, format_new_lines(v)
                )
            elif k == 'error':
                ret += '<tr><th class="text-white bg-danger">%s</th><td>%s</td></tr>' % (
                    k, format_new_lines(v)
                )
            else:
                ret += '<tr><th>%s</th><td>%s</td></tr>' % (
                    k, format_new_lines(v)
                )
        else:
            ret += '<tr><th>%s</th><td>%s</td></tr>' % (k, format_table(v, target))
    ret += '</tbody></table>'
    return ret


def format_result(result, target):
    return '<div class="card">%s</div>' % format_table(result, target)


def format_link_list(header, ls):
    ret = '''
<div class="card mb-2">
<div class="card-header list-group-flush">%s</div>
<div class="list-group list-group-flush">
''' % header

    for (link, title, anchor, cls) in ls:
        ret += '<a class="%s" href="%s" title="%s">%s</a>\n' % (
            ' '.join(cls+['list-group-item', 'list-group-item-action']),
            link, title, anchor
        )
    ret += '</div></div>'
    return ret


def split_prefixed_ip_address(ip):
    if ip.find('/') > 0:
        return tuple(ip.split('/', 1))
    else:
        return (ip, None)


def sanitize_ip(s):
    return re.sub(r'[^0-9a-fA-F\.\:/]', 'X', s)


def sanitize_atoz(s):
    return re.sub(r'[^a-zA-Z]', 'X', s)


def format_page(form):
    ip = sanitize_ip(form.getfirst('ip', ''))
    provider = sanitize_atoz(form.getfirst('provider', '')).upper()
    fmt = sanitize_atoz(form.getfirst('format', 'html')).lower()
    do_lookup = form.getfirst('lookup', 'false').lower() != 'false'
    use_rdap = form.getfirst('rdap', 'false').lower() != 'false'
    css = '''
.el { display: flex; flex-direction: row; align-items: baseline; }
.el-ip { flex: 0?; max-width: 60%; }
.el-prov { flex: 1 8em; }
th { font-size: smaller; }
.link-result { -moz-user-select: all; -webkit-user-select: all; -ms-user-select: all; user-select: all; }
'''.strip()

    # remove spaces, the zero-width space and left-to-right mark
    if six.PY2:
        ip = ip.decode('utf-8')
    ip = ip.strip(u' \u200b\u200e')

    (ipn, rest) = split_prefixed_ip_address(ip)

    result = {}
    error = False
    if do_lookup:
        try:
            result = lookup(ipn, use_rdap)
        except Exception as e:
            result = {'error': repr(e)}
            error = True
    if rest:
        result['warning'] = 'prefixed addresses are not supported; "{}" is ignored'.format(rest)

    if provider in PROVIDERS:
        return 'Location: {}\n\n'.format(PROVIDERS[provider].format(ip))

    if fmt == 'json':
        return 'Content-type: text/plain\n\n{}\n'.format(json.dumps(result))

    ret = '''Content-type: text/html

<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8">
<link rel="stylesheet" href="//tools-static.wmflabs.org/cdnjs/ajax/libs/twitter-bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" href="//tools-static.wmflabs.org/cdnjs/ajax/libs/font-awesome/5.15.0/css/all.min.css">
<title>Whois Gateway - {subtitle}</title>
<style type="text/css">
{css}
</style>
</head>
<body>
<div class="container">
<div class="row">
<div class="col-md">
<header><h1>Whois Gateway</h1></header>
</div>
</div>

  <div class="alert alert-warning" role="alert">
		This tool is <a class="alert-link" href="https://github.com/whym/whois-gateway/issues/21">experiencing a problem</a> &mdash; <a class="alert-link" href="https://whois-dev.toolforge.org/">a new beta version</a> is available for testing.
  </div>

<div class="row">
<div class="col-md-9">

<form action="{site}/gateway.py" role="form">
<input type="hidden" name="lookup" value="true"/>
<div class="form-row form-group {error}">
<div class="col-md"><div class="input-group-prepend">
<label class="input-group-text" for="ipaddress-input">IP address</label>
<input type="text" name="ip" value="{ip}" id="ipaddress-input" class="form-control" placeholder="{placeholder}" {af}/>
</div></div>
<div class="col-md-2"><input type="submit" value="Lookup" class="btn btn-secondary btn-block"/></div>
</div>
</form>
'''.format(site=SITE,
           css=css,
           subtitle=ip if ip != '' else SUBTITLE,
           ip=ip,
           placeholder='e.g. ' + socket.gethostbyname(socket.gethostname()),
           error='has-danger' if error else '',
           af='autofocus onFocus="this.select();"' if (not do_lookup or error) else '')

    if do_lookup:
        link = TOOL_URL.format(ip)
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ipn)[0]
        except IOError:
            pass
        ret += '''
<div class="card mb-3"><div class="card-header">{hostname}</div>
<div class="card-body">{table}</div></div>

<div class="form-row form-group">
<div class="col-12"><div class="input-group-prepend">
<label class="input-group-text"><a href="{link}">Link this result</a></label>
<output class="form-control link-result">{link}</output>
</div></div>
</div>
'''.format(hostname='<strong>%s</strong>' % hostname if hostname else '<em>(No corresponding host name retrieved)</em>',
           table=format_table(result, ip),
           link=link)

    ret += '''</div>
<div class="col-md-3">
'''
    ret += format_link_list(
        'Other tools',
        [(fmt.format(ip),
          'Look up %s at %s' % (ip, name),
          '<small class="el-ip text-truncate">%s</small><span class="el-prov"> @%s</span>' % (ip, name),
          ['el'])
         for (name, fmt) in sorted(TOOLS.items())]
    )

    ret += format_link_list(
        'Sources',
        [(fmt.format(ip),
          'Look up %s at %s' % (ip, name),
          '<small class="el-ip text-truncate">%s</small><span class="el-prov"> @%s</span>' % (ip, name),
          ['el', 'active'] if result.get('asn_registry', '').upper() == name else ['el'])
         for (name, fmt) in sorted(PROVIDERS.items())]
    )

    ret += '''
</div>
</div>

<footer><div class="container">
<hr>
<p class="text-center text-muted">
<a href="{site}">Whois Gateway</a>
<small>(<a href="https://github.com/whym/whois-gateway">source code</a>,
        <a href="https://github.com/whym/whois-gateway#api">API</a>)</small>
        on <a href="https://admin.toolforge.org">Toolforge</a> /
<a href="https://github.com/whym/whois-gateway/issues">Issues?</a>
</p>
</div></footer>
</div>
</body></html>'''.format(site=SITE)

    return ret


if __name__ == '__main__':

    if os.path.exists(LOGDIR):
        cgitb.enable(display=0, logdir=LOGDIR)
    print(format_page(cgi.FieldStorage()))
