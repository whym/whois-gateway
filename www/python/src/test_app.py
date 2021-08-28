import os
import tempfile
import pytest
import time
from app import app, limiter, is_ip_like_string


def fake_lookup(ip, rdap=False):
    return {}


def slow_lookup(ip, rdap=False):
    for x in range(0, 20):
        time.sleep(0.5)
    return {}


@pytest.fixture(name='client')
def fixture_client():
    db_fd, app.config['DATABASE'] = tempfile.mkstemp()
    app.config['TESTING'] = True
    app.config['timeout'] = 2.5
    app.debug = True

    with app.test_client() as client:
        with app.app_context():
            None
        yield client

    os.close(db_fd)
    os.unlink(app.config['DATABASE'])
    limiter.enabled = False


def test_error_for_non_existent_path(client):
    """404 for non-existent path."""

    assert client.get('/non-existent-path').status_code == 404
    assert client.get('/x/').status_code == 404


def test_error_for_invalid_ip(client):
    """400 for invalid IP addresses."""

    assert client.get('/w/x.x.x.x').status_code == 400
    assert b'does not look like an IP address' in client.get('/w/x.x.x.x/lookup').data


def test_respond_to_entry_path_ipv4(client):
    """200 for simple paths"""

    assert client.get('/w/8.8.8.8').status_code == 200
    assert client.get('/', follow_redirects=True).status_code == 200
    assert client.get('/whois/8.8.8.8',
                      follow_redirects=True).status_code == 200


def test_respond_to_static_path(client):
    """200 for static paths"""

    assert client.get('/robots.txt').status_code == 200
    assert client.get('/toolinfo.json').status_code == 200


def test_respond_to_standard_path_ipv6(client):
    """200 for simple paths (IPv6)."""

    assert client.get('/w/2606:4700:4700::1111').status_code == 200
    assert client.get('/w/:::').status_code == 200
    assert client.get('/w/:::1/', follow_redirects=True).status_code == 200
    assert client.get('/w/1%3A%3A1').status_code == 200


def test_respond_to_rest_queries(client, mocker):
    """200 for REST queries."""

    m = mocker.patch('app.lookup', autospec=True)
    assert client.get('/w/2606:4700:4700::1111/lookup').status_code == 200
    m.assert_called_once_with('2606:4700:4700::1111')
    assert client.get('/w/8.8.8.8/lookup').status_code == 200
    assert client.get('/w/8.8.8.8/redirect/APNIC').status_code == 302
    mocker.patch('app.lookup', fake_lookup)
    assert client.get('/w/2606:4700:4700::1111/lookup/json').status_code == 200


def test_respond_to_legacy_queries(client):
    """200 for legacy queries."""

    with client.get('/gateway.py?ip=8.8.8.8&lookup=true') as res:
        assert res.headers['location'].endswith('8.8.8.8/lookup')
    with client.get('/gateway.py?ip=::1&lookup=true&format=json') as res:
        assert res.headers['location'].endswith('::1/lookup/json')
    with client.get('/gateway.py?ip=8.8.8.8&provider=APNIC') as res:
        assert res.headers['location'].endswith('8.8.8.8/redirect/APNIC')


def test_error_for_abuse(client):
    """400 for paths that obviously do not ask about IPs"""

    assert client.get('/w/../../admin').status_code == 400


def test_error_for_too_many_requests(client):
    """429 for too many requests"""

    limiter.enabled = True
    try:
        for i in range(0, 60):
            assert client.get('/w/1.1.1.{}'.format(i)).status_code == 200
        assert client.get('/w/9.9.9.9').status_code == 429
        client.user_agent = 'test'
        env = {'HTTP_USER_AGENT': 'Chrome'}
        assert client.get('/w/9.9.9.9', environ_base=env).status_code == 200
    finally:
        limiter.enabled = False


def test_timeout_for_slow_lookup(client, mocker):
    """408 for slow response"""

    mocker.patch('app.lookup', slow_lookup)
    with client.get('/w/8.8.8.8/lookup/json') as res:
        assert res.status_code == 408
        assert b'timeout' in res.data
    with client.get('/w/8.8.8.8/lookup') as res:
        assert res.status_code == 408
        assert b'Timeout' in res.data


def test_tolerance_to_whitespace(client):
    """200 for paths that include different kinds of whitespace."""

    assert client.get('/w/%208.8.8.8').status_code == 200
    assert client.get('/w/8.8.8. ').status_code == 200
    assert client.get('/w/ 8.8.8.8').status_code == 200


def test_ip_like_string():
    """Detect strings obviously different from valid IPs"""
    assert is_ip_like_string('1.1.1.1')
    assert not is_ip_like_string('1.1.1.X')


if __name__ == '__main__':
    pytest.main()
