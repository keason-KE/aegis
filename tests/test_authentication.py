import sqlite3
import time
import subprocess
import sys

import jwt
import pytest
from fastapi.testclient import TestClient

from aegis.admin import manage_agent
from aegis.app import Settings, create_app
from aegis.identity import ALGORITHM, AUDIENCE, ISSUER
from test_gateway import TOKENS, SIGNING_KEY, gateway


def login(client, role="support", **overrides):
    return client.post("/auth/token", json={
        "agent_id": f"agent-{role}", "client_secret": TOKENS[role], **overrides,
    })


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def signed(**overrides):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "agent-support",
              "iat": now, "nbf": now, "exp": now + 300, "jti": "test-jti",
              "ver": 0, "scope": ["read_ticket"], "token_use": "access"}
    claims.update(overrides)
    return jwt.encode(claims, SIGNING_KEY, algorithm=ALGORITHM)


@pytest.mark.parametrize("role,path", [("support", "/tickets/ticket-001"), ("finance", "/financial-reports/report-001"), ("it_admin", "/system/status")])
def test_authentication_round_trip(gateway, role, path):
    client, settings = gateway
    response = login(client, role)
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    token = response.json()["access_token"]
    claims = jwt.decode(token, SIGNING_KEY, algorithms=[ALGORITHM], audience=AUDIENCE, issuer=ISSUER)
    assert claims["sub"] == f"agent-{role}"
    assert claims["exp"] - claims["iat"] == response.json()["expires_in"] == 300
    assert client.get(path, headers=bearer(token)).status_code == 200
    with sqlite3.connect(settings.database) as db:
        events = db.execute("SELECT agent_id, permission, decision FROM audit ORDER BY id").fetchall()
        registry = str(db.execute("SELECT * FROM agents").fetchall())
    assert events[0] == (f"agent-{role}", "authenticate", "allowed")
    assert TOKENS[role] not in registry
    assert token not in str(events)


@pytest.mark.parametrize("changes", [{"agent_id": "unknown"}, {"client_secret": "wrong"}, {"agent_id": "agent-finance"}])
def test_invalid_login(gateway, changes):
    client, settings = gateway
    response = login(client, **changes)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid agent credentials"}
    with sqlite3.connect(settings.database) as db:
        assert db.execute("SELECT agent_id, decision FROM audit").fetchone() == (None, "denied")


@pytest.mark.parametrize("changes", [
    {"exp": 1}, {"iss": "wrong"}, {"aud": "wrong"}, {"aud": [AUDIENCE, "other"]},
    {"sub": "unknown"}, {"sub": ""}, {"ver": 1}, {"ver": True}, {"token_use": "refresh"},
    {"scope": "read_ticket"}, {"scope": ["read_financial_report"]}, {"scope": [1]},
    {"iat": 9999999999}, {"nbf": 9999999999}, {"jti": ""}, {"exp": "9999999999"},
    {"exp": []}, {"iat": {}}, {"nbf": []}, {"sub": {}}, {"jti": 42},
])
def test_invalid_claims(gateway, changes):
    client, _ = gateway
    assert client.get("/tickets/ticket-001", headers=bearer(signed(**changes))).status_code == 401


@pytest.mark.parametrize("missing", ["iss", "aud", "sub", "iat", "nbf", "exp", "jti", "ver", "scope", "token_use"])
def test_required_claims(gateway, missing):
    client, _ = gateway
    claims = jwt.decode(signed(), options={"verify_signature": False})
    del claims[missing]
    token = jwt.encode(claims, SIGNING_KEY, algorithm=ALGORITHM)
    assert client.get("/tickets/ticket-001", headers=bearer(token)).status_code == 401


@pytest.mark.parametrize("algorithm,key", [("HS256", "wrong-key-" * 8), ("HS384", SIGNING_KEY), ("none", "")])
def test_forged_or_disallowed_signature(gateway, algorithm, key):
    client, _ = gateway
    claims = jwt.decode(signed(), options={"verify_signature": False})
    token = jwt.encode(claims, key, algorithm=algorithm)
    assert client.get("/tickets/ticket-001", headers=bearer(token)).status_code == 401


def test_scope_restrictions(gateway):
    client, _ = gateway
    assert login(client, scopes=["read_financial_report"]).status_code == 403
    token = login(client, scopes=[]).json()["access_token"]
    assert client.get("/tickets/ticket-001", headers=bearer(token)).status_code == 403
    assert client.get("/tickets/ticket-001", headers=bearer(TOKENS["support"])).status_code == 401


def test_disable_and_reenable_do_not_restore_tokens(gateway):
    client, settings = gateway
    token = login(client).json()["access_token"]
    manage_agent(settings.database, "agent-support", "disable")
    assert login(client).status_code == 401
    assert client.get("/tickets/ticket-001", headers=bearer(token)).status_code == 401
    with TestClient(create_app(settings)) as restarted:
        assert login(restarted).status_code == 401
    manage_agent(settings.database, "agent-support", "enable")
    assert client.get("/tickets/ticket-001", headers=bearer(token)).status_code == 401
    fresh = login(client).json()["access_token"]
    assert client.get("/tickets/ticket-001", headers=bearer(fresh)).status_code == 200


@pytest.mark.parametrize("action", ["revoke", "rotate"])
def test_revocation_and_rotation(gateway, action):
    client, settings = gateway
    token = login(client).json()["access_token"]
    replacement = "new-secret-" * 5
    manage_agent(settings.database, "agent-support", action, replacement if action == "rotate" else None)
    assert client.get("/tickets/ticket-001", headers=bearer(token)).status_code == 401
    with TestClient(create_app(settings)) as restarted:
        if action == "rotate":
            assert login(restarted).status_code == 401
        fresh = login(restarted, client_secret=replacement if action == "rotate" else TOKENS["support"])
        assert fresh.status_code == 200
        assert restarted.get("/tickets/ticket-001", headers=bearer(fresh.json()["access_token"])).status_code == 200


def test_registry_role_is_authoritative(gateway):
    client, settings = gateway
    token = signed(role="finance")
    assert client.get("/financial-reports/report-001", headers=bearer(token)).status_code == 403
    with sqlite3.connect(settings.database) as db:
        db.execute("UPDATE agents SET role='finance' WHERE agent_id='agent-support'")
        db.execute("UPDATE tasks SET agent_id='agent-support' WHERE task_id='task-finance'")
    assert client.get("/tickets/ticket-001", headers=bearer(token)).status_code == 401
    fresh = login(client).json()["access_token"]
    assert client.get("/financial-reports/report-001", headers=bearer(fresh)).status_code == 200


def test_authentication_and_admin_fail_closed_on_audit_failure(gateway):
    client, settings = gateway
    with sqlite3.connect(settings.database) as db:
        db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(FAIL, 'unavailable'); END")
    response = login(client)
    assert response.status_code == 503
    assert "access_token" not in response.text
    with pytest.raises(sqlite3.Error):
        manage_agent(settings.database, "agent-support", "disable")
    with sqlite3.connect(settings.database) as db:
        assert db.execute("SELECT active, token_version FROM agents WHERE agent_id='agent-support'").fetchone() == (1, 0)


def test_validation_does_not_echo_credentials(gateway):
    client, _ = gateway
    response = login(client, role_claim="administrator")
    assert response.status_code == 422
    assert TOKENS["support"] not in response.text


@pytest.mark.parametrize("ttl", [0, -1, 901, True])
def test_invalid_ttl(ttl):
    with pytest.raises(ValueError):
        Settings(TOKENS, signing_key=SIGNING_KEY, token_ttl_seconds=ttl)


def test_signing_key_is_required_and_separate():
    with pytest.raises(ValueError):
        Settings(TOKENS)
    with pytest.raises(ValueError):
        Settings(TOKENS, signing_key=TOKENS["support"])


def test_operator_cli_and_audit(gateway):
    client, settings = gateway
    result = subprocess.run(
        [sys.executable, "-m", "aegis.admin", "disable", "agent-support", "--database", str(settings.database)],
        capture_output=True, text=True, check=True,
    )
    assert "previous tokens invalidated" in result.stdout
    assert login(client).status_code == 401
    assert login(client, "finance").status_code == 200
    with sqlite3.connect(settings.database) as db:
        assert db.execute("SELECT agent_id, permission, role FROM audit WHERE method='LOCAL'").fetchone() == ("agent-support", "identity:disable", "local_operator")


def test_admin_unknown_agent_is_rejected(gateway):
    _, settings = gateway
    with pytest.raises(ValueError, match="Unknown agent"):
        manage_agent(settings.database, "missing", "disable")
    with sqlite3.connect(settings.database) as db:
        assert db.execute("SELECT count(*) FROM agents WHERE active=1").fetchone()[0] == 3


def test_existing_milestone_one_audit_is_preserved(tmp_path):
    from aegis.app import Settings
    settings = Settings(TOKENS, tmp_path / "legacy.sqlite3", SIGNING_KEY)
    with TestClient(create_app(settings)) as client:
        client.get("/health")
    with sqlite3.connect(settings.database) as db:
        db.execute("DROP TABLE agents")
    with TestClient(create_app(settings)) as client:
        assert login(client).status_code == 200
    with sqlite3.connect(settings.database) as db:
        assert db.execute("SELECT count(*) FROM audit WHERE route='/health'").fetchone()[0] == 1
