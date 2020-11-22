import os
import tempfile

import pytest

from app import app


@pytest.fixture
def client():
    db_fd, app.config['DATABASE'] = tempfile.mkstemp()
    app.config['TESTING'] = True

    with app.test_client() as client:
        with app.app_context():
            None
        yield client

    os.close(db_fd)
    os.unlink(app.config['DATABASE'])


def test_404_for_non_existent_path(client):
    """404 for non-existent path."""

    rv = client.get('/non-existent-path')
    assert 404 == rv.status_code


def test_respond(client):
    """200 for existent paths."""

    rv = client.get('/w/8.8.8.8')
    assert 200 == rv.status_code

    rv = client.get('/')
    assert 200 == rv.status_code

    rv = client.get('/whois/8.8.8.8')
    assert 200 == rv.status_code

    rv = client.get('/gateway.py?')
    assert 200 == rv.status_code

    rv = client.get('/robots.txt')
    assert 200 == rv.status_code
