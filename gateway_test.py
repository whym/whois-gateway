#! /usr/bin/env python

import sys
sys.path.insert(0, './public_html')

import unittest
import cgi
import gateway
import mock

class TestGateway(unittest.TestCase):

    def test_arin(self):
        self.assertEquals(gateway.PROVIDERS['ARIN']('11.22.33.44'), 'http://whois.arin.net/rest/ip/11.22.33.44')

    @mock.patch('gateway.IPWhois')
    def test_lookup(self, MockClass):
        instance = MockClass.return_value
        instance.lookup_whois.return_value = {'I am': 'nowhere', 'raw': 'foobar'}
        self.assertIn('nowhere', str(gateway.lookup('8.8.8.8')).lower())
        self.assertNotIn('foobar', str(gateway.lookup('8.8.8.8')).lower())

if __name__ == '__main__':
    unittest.main()
