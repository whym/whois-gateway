#! /usr/bin/env python

import sys
sys.path.insert(0, './public_html')

import unittest
import cgi
import gateway
import six
import mock
from six.moves import urllib

def get_html(ip, url_quote=True):
    if url_quote:
        ip = urllib.parse.quote(ip)
    form = cgi.FieldStorage(environ={
        'REQUEST_METHOD': 'GET',
        'QUERY_STRING': 'ip=%s' % ip})
    return gateway.format_page(form)

class TestGateway(unittest.TestCase):

    def test_arin(self):
        self.assertEquals(gateway.PROVIDERS['ARIN']('11.22.33.44'), 'http://whois.arin.net/rest/ip/11.22.33.44')

    @mock.patch('gateway.IPWhois')
    def test_lookup(self, MockClass):
        instance = MockClass.return_value
        instance.lookup_whois.return_value = {'I am': 'nowhere', 'raw': 'foobar'}
        self.assertIn('nowhere', str(gateway.lookup('8.8.8.8')).lower())
        self.assertNotIn('foobar', str(gateway.lookup('8.8.8.8')).lower())

    def test_ipv6(self):
        self.assertIn('>0:f:0:0:f:f:0:0<', get_html('0:f:0:0:f:f:0:0'))

    def test_ip_with_space(self):
        ip = u'\u200e1.2.3.4\u200b '
        if six.PY2:
            ip = ip.encode('utf-8')
        self.assertIn(u'>1.2.3.4<', get_html(ip))

if __name__ == '__main__':
    unittest.main()
