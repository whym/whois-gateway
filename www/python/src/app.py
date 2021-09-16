#! /usr/bin/env python
# -*- mode: python -*-

import socket
import yaml
import os
import re
from collections import namedtuple
import six
import flask
import flask_cors
from flask_limiter import Limiter
import logging
from ipwhois import IPWhois, WhoisLookupError
import stopit

WhoisResult = namedtuple('WhoisResult', ['values', 'error'])

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

SUBTITLE = "Find details about an IP address's owner"


def ord_key(x):
    keys = dict((y, x) for (x, y) in enumerate([
        'warning', 'asn_registry', 'asn_country_code', 'asn_cidr', 'query',
        'nets', 'asn', 'asn_date',
        'name', 'description', 'address',
        'city', 'state', 'country', 'postal_code',
        'cidr', 'range', 'created', 'updated', 'handle', 'parent_handle',
        'ip_version', 'start_address', 'end_address',
        'abuse_emails', 'tech_emails', 'misc_emails']))
    if x in keys:
        return '00_%04d' % keys[x]
    return '99_%s' % x


def lookup(ip, rdap=False):
    obj = IPWhois(ip)
    if rdap:
        # TODO: RDAP output includes less relevant info, needs a dedicated formatter
        return obj.lookup_rdap()
    else:
        ret = obj.lookup_whois(get_recursive=False)
        return ret


@stopit.threading_timeoutable()
def lookup2(ip):
    result = {}
    error = None
    try:
        result2 = lookup(ip)
        if result2 is not None:
            result.update(result2)
    except Exception as e:
        app.logger.error(repr(e))
        result['error'] = repr(e)
        error = e
    return WhoisResult(result, error)


def format_new_lines(s):
    return s.replace('\n', '<br/>')


def format_table(dct, target):
    if isinstance(dct, six.string_types):
        return format_new_lines(dct)
    if isinstance(dct, list):
        return '\n'.join(format_table(x, target) for x in dct)
    ret = '<table class="table table-sm"><tbody>'
    for (k, v) in sorted(dct.items(), key=lambda x: ord_key(x[0])):
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


def sanitize_ip(string):
    return re.sub(r'[^0-9a-fA-F\.\:/]', ' ', string)


def sanitize_atoz(string):
    return re.sub(r'[^a-zA-Z]', ' ', string)


def is_ip_like_string(string):
    return re.match(r'[0-9:]', string) is not None and re.match(r'^([0-9A-Fa-f\:\.]|%3[aA])+$', string) is not None


def get_hostname(ip):
    hostname = None
    if ip is not None:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except IOError:
            pass
        except UnicodeError:
            pass

    return hostname


def render_result(ip, do_lookup):
    # remove spaces, the zero-width space and left-to-right mark
    if six.PY2:
        ip = ip.decode('utf-8')
    ip = ip.strip(u' \u200b\u200c\u200d\u200e\u200f')

    (ipn, rest) = split_prefixed_ip_address(ip)

    result = {}
    status = 200
    app.logger.info('ipn="{}", ip="{}"'.format(ipn, ip))
    if len(ip) > 0 and not is_ip_like_string(ip):
        app.logger.warning('"{}" is not IP-like'.format(ipn))
        result['error'] = '"{}" does not look like an IP address'.format(ipn)
        status = 400
    elif do_lookup:
        res = lookup2(ipn, timeout=app.config['timeout'])
        result = res.values
        if res.error:
            app.logger.warning('error: {}'.format(res.error))
            if isinstance(res.error, stopit.TimeoutException):
                status = 408
            else:
                status = 502

    if rest:
        result['warning'] = 'prefixed addresses are not supported; "{}" is ignored'.format(rest)

    link_list = format_link_list(
        'Other tools',
        [(fmt.format(ip),
          'Look up %s at %s' % (ip, name),
          '<small class="el-ip text-truncate">%s</small><span class="el-prov"> @%s</span>' % (ip, name),
          ['el'])
         for (name, fmt) in sorted(TOOLS.items())]
    )

    link_list += format_link_list(
        'Sources',
        [(fmt.format(ip),
          'Look up %s at %s' % (ip, name),
          '<small class="el-ip text-truncate">%s</small><span class="el-prov"> @%s</span>' % (ip, name),
          ['el', 'active'] if result.get('asn_registry', '').upper() == name else ['el'])
         for (name, fmt) in sorted(PROVIDERS.items())]
    )

    render = flask.render_template(
        'main.html',
        subtitle=ip if ip != '' else SUBTITLE,
        ip=ip,
        placeholder='e.g. ' + socket.gethostbyname(socket.gethostname()),
        error_present=(status != 200),
        do_lookup=do_lookup,
        hostname=get_hostname(ipn),
        table=format_table(result, ip),
        link_list=link_list
    )

    return render, status


app = flask.Flask(__name__, )
cors = flask_cors.CORS(app, resources={r'/w/.*/.*/json': {'origins': '*'}})
# Load configuration from YAML file(s).
__dir__ = os.path.dirname(__file__)
app.config.update(
    yaml.safe_load(open(os.path.join(__dir__, 'default_config.yaml'))))
try:
    app.config.update(
        yaml.safe_load(open(os.path.join(__dir__, 'config.yaml'))))
except IOError:
    # It is ok if there is no local config file
    pass
limiter = Limiter(
    app,
    key_func=lambda: flask.request.user_agent.string,
)

if 'log_level' in app.config and app.config['log_level'] in dir(logging):
    app.logger.setLevel(logging.__dict__[app.config['log_level']])
app.logger.debug('config: {}'.format(app.config))

@app.route('/w/', defaults={'ip': '', 'action': '', 'action2': ''})
@app.route('/w/<ip>', defaults={'action': '', 'action2': ''})
@app.route('/w/<ip>/<action>', defaults={'action2': ''})
@app.route('/w/<ip>/<action>/<action2>', )
def main_route(ip, action, action2):
    """application's main routine"""
    app.logger.info('main_route: {}'.format([ip, action, action2]))
    app.logger.info('user_agent="{}"'.format(flask.request.user_agent))
    app.logger.info('referrer="{}"'.format(flask.request.referrer))
    ip = sanitize_ip(ip)
    fmt = sanitize_atoz(action2)

    if action == 'lookup':
        if fmt == 'json':
            res = lookup2(ip, timeout=app.config['timeout'])
            if res.error is None:
                return flask.jsonify(res.values)
            if isinstance(res.error, stopit.TimeoutException):
                return flask.jsonify({'error': 'timeout'}), 408
            return flask.jsonify({'error': '?'}), 502
        else:
            return render_result(ip, True)
    elif action == 'redirect':
        return flask.redirect(PROVIDERS[action2].format(ip))
    else:
        return render_result(ip, False)


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all_route(path):
    app.logger.info('catch_all_route')
    segments = path.split('/', 3)
    segments = segments + [''] * (4 - len(segments))
    p, ip, action, action2 = segments
    app.logger.info(segments)

    if p not in ('', 'w', 'whois'):
        return flask.render_template('notfound.html'), 404

    return flask.redirect(flask.url_for('main_route', ip=ip, action=action, action2=action2))


@app.route('/gateway.py')
def legacy_route():
    """redirects for backward compatibility"""
    app.logger.info('legacy_route')
    ip = sanitize_ip(flask.request.args.get('ip', ''))
    do_lookup = flask.request.args.get('lookup', 'false').lower() != 'false'
    fmt = sanitize_atoz(flask.request.args.get('format', 'html')).lower()
    provider = sanitize_atoz(flask.request.args.get('provider', '')).upper()

    action = ''
    action2 = ''
    if do_lookup:
        action = 'lookup'
    if fmt == 'json':
        action2 = 'json'
    if provider != '':
        action = 'redirect'
        action2 = provider

    return flask.redirect(flask.url_for('main_route', ip=ip, action=action, action2=action2))


@app.route('/robots.txt')
@app.route('/toolinfo.json')
def static_from_root():
    "route to serve static files"
    return flask.send_from_directory(app.static_folder, flask.request.path[1:])


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
    print('''For more flexible debugging try this instead:
    env FLASK_DEBUG=1 FLASK_APP={} flask run --port=5001'''.format(__file__))
