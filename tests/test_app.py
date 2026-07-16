import json
import pytest
from sentryglobe import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_index_serves_page(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'SENTRYGLOBE' in response.data


def test_trace_ip_requires_target(client):
    response = client.post('/api/trace_ip', json={})
    assert response.status_code == 400


def test_recon_username_requires_username(client):
    response = client.post('/api/recon_username', json={})
    assert response.status_code == 400
