import sqlite3
import pytest
from fastapi.testclient import TestClient
from aegis.app import Settings, create_app
from aegis.policies import authorize
from aegis.identity import issue_token

TOKENS = {r: 'test-' + r + 'x' * 40 for r in ('support', 'finance', 'it_admin')}
SIGNING_KEY = 'test-signing-key-' + 's' * 40
CASES = [('GET', '/tickets/ticket-001', None, 'support'), ('GET', '/financial-reports/report-001', None, 'finance'), ('GET', '/system/status', None, 'it_admin'), ('PATCH', '/accounts/account-001', {'disabled': True}, None)]

@pytest.fixture
def gateway(tmp_path):
    settings = Settings(TOKENS, tmp_path / 'test.sqlite3', SIGNING_KEY)
    with TestClient(create_app(settings)) as client:
        yield client, settings

def headers(role):
    from aegis.policies import PERMISSIONS
    token = issue_token({'agent_id': 'agent-' + role, 'token_version': 0}, SIGNING_KEY, 300, list(PERMISSIONS[role]))
    return {'Authorization': 'Bearer ' + token}

@pytest.mark.parametrize('role', TOKENS)
@pytest.mark.parametrize('method,path,payload,allowed', CASES)
def test_permission_matrix(gateway, role, method, path, payload, allowed):
    client, settings = gateway
    response = client.request(method, path, json=payload, headers=headers(role))
    assert response.status_code == (200 if role == allowed else 403)
    with sqlite3.connect(settings.database) as db:
        event = db.execute('SELECT agent_id, role, status, request_id FROM audit ORDER BY id DESC LIMIT 1').fetchone()
    assert event == ('agent-' + role, role, response.status_code, response.headers['X-Request-ID'])

@pytest.mark.parametrize('method,path,payload,allowed', CASES)
@pytest.mark.parametrize('authorization', [None, 'Bearer invalid', 'Basic abc', 'Bearer'])
def test_invalid_credentials(gateway, method, path, payload, allowed, authorization):
    client, settings = gateway
    response = client.request(method, path, json=payload, headers={'Authorization': authorization} if authorization else {})
    assert response.status_code == 401
    assert response.headers['WWW-Authenticate'] == 'Bearer'
    with sqlite3.connect(settings.database) as db:
        assert db.execute('SELECT agent_id, decision FROM audit').fetchone() == (None, 'denied')

def test_identity_spoofing(gateway):
    client, _ = gateway
    response = client.get('/financial-reports/report-001?role=finance', headers={**headers('support'), 'X-Agent-ID': 'agent-finance', 'X-Role': 'finance'})
    assert response.status_code == 403

def test_self_approval(gateway):
    client, _ = gateway
    response = client.patch('/accounts/account-001', json={'disabled': True, 'approved': True}, headers=headers('it_admin'))
    assert response.status_code == 403
    assert 'human approval' in response.json()['detail']

def test_resource_existence(gateway):
    client, _ = gateway
    # Task scope is checked before existence, including for unknown IDs.
    assert client.get('/tickets/unknown', headers=headers('support')).status_code == 403
    assert client.get('/tickets/unknown', headers=headers('finance')).status_code == 403

def test_audit_persistence_redaction(gateway):
    client, settings = gateway
    client.get('/tickets/ticket-001?secret=private-query', headers=headers('support'))
    client.get('/private-path')
    with TestClient(create_app(settings)) as restarted:
        assert restarted.get('/health').status_code == 200
    with sqlite3.connect(settings.database) as db:
        events = db.execute('SELECT * FROM audit').fetchall()
    assert len(events) == 3
    for secret in [*TOKENS.values(), 'private-query', 'private-path', 'Synthetic Customer']:
        assert secret not in str(events)

def test_audit_failure(gateway):
    client, settings = gateway
    with sqlite3.connect(settings.database) as db:
        db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(FAIL, 'unavailable'); END")
    response = client.get('/tickets/ticket-001', headers=headers('support'))
    assert response.status_code == 503
    assert 'Synthetic Customer' not in response.text

def test_database_connection_failure(gateway, monkeypatch):
    client, _ = gateway
    def unavailable(*args, **kwargs):
        raise sqlite3.OperationalError('unavailable')
    monkeypatch.setattr(sqlite3, 'connect', unavailable)
    response = client.get('/tickets/ticket-001', headers=headers('support'))
    assert response.status_code == 503
    assert response.headers['X-Request-ID']
    assert 'Synthetic Customer' not in response.text

@pytest.mark.parametrize('tokens', [{}, {r: 'short' for r in TOKENS}, {r: 'x' * 40 for r in TOKENS}])
def test_invalid_configuration(tokens):
    with pytest.raises(ValueError):
        Settings(tokens)

@pytest.mark.parametrize('role,action', [('unknown', 'read_ticket'), ('support', 'unknown'), ('it_admin', 'modify_account')])
def test_default_deny(role, action):
    assert not authorize(role, action)

def test_unhandled_failure(gateway):
    client, settings = gateway
    @client.app.get('/test-failure')
    async def failure():
        raise RuntimeError('sensitive error detail')
    response = client.get('/test-failure')
    assert response.status_code == 500
    assert 'sensitive' not in response.text
    with sqlite3.connect(settings.database) as db:
        assert db.execute('SELECT status, decision FROM audit').fetchone() == (500, 'error')
