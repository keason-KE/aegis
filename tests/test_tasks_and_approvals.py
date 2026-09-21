import sqlite3
import time

import pytest

from aegis.admin import manage_agent
from aegis.resources import review_approval
from test_authentication import login, bearer
from test_gateway import gateway


def request_change(client):
    token = login(client, "it_admin").json()["access_token"]
    headers = bearer(token)
    response = client.post("/account-requests", headers=headers, json={"account_id": "account-001", "disabled": True})
    assert response.status_code == 202
    return response.json()["approval_id"], headers


def account(settings):
    with sqlite3.connect(settings.database) as db:
        return db.execute("SELECT disabled,version FROM accounts WHERE account_id='account-001'").fetchone()


def test_horizontal_access_and_task_ownership(gateway):
    client, _ = gateway
    token = login(client).json()["access_token"]
    assert client.get("/tickets/ticket-002", headers=bearer(token)).status_code == 403
    assert login(client, task_id="task-finance").status_code == 403
    assert client.get("/tickets/ticket-002?task_id=task-finance", headers={**bearer(token), "X-Task-ID": "task-finance"}).status_code == 403


@pytest.mark.parametrize("update", ["active=0", "expires_at=1"])
def test_task_termination_blocks_existing_tokens(gateway, update):
    client, settings = gateway
    token = login(client).json()["access_token"]
    with sqlite3.connect(settings.database) as db:
        db.execute(f"UPDATE tasks SET {update} WHERE task_id='task-support'")
    assert client.get("/tickets/ticket-001", headers=bearer(token)).status_code == 403
    assert login(client).status_code == 403


def test_approval_workflow_is_bound_and_single_use(gateway):
    client, settings = gateway
    approval_id, headers = request_change(client)
    path = f"/account-requests/{approval_id}/execute"
    assert account(settings) == (0, 0)
    assert client.post(path, headers=headers).status_code == 403
    assert client.post(f"/api/approvals/{approval_id}/review", headers=headers, json={"decision": "approved"}).status_code == 404
    review_approval(settings.database, approval_id, "approved")
    assert account(settings) == (0, 0)
    assert client.post(path, headers=headers).status_code == 200
    assert account(settings) == (1, 1)
    assert client.post(path, headers=headers).status_code == 403
    assert account(settings) == (1, 1)


@pytest.mark.parametrize("condition", ["rejected", "expired", "revoked", "completed", "grant_removed", "account_changed"])
def test_stale_or_rejected_approval_cannot_execute(gateway, condition):
    client, settings = gateway
    approval_id, headers = request_change(client)
    review_approval(settings.database, approval_id, "rejected" if condition == "rejected" else "approved")
    with sqlite3.connect(settings.database) as db:
        if condition == "expired":
            db.execute("UPDATE approvals SET expires_at=1")
        elif condition == "completed":
            db.execute("UPDATE tasks SET active=0 WHERE task_id='task-it_admin'")
        elif condition == "grant_removed":
            db.execute("DELETE FROM grants WHERE action='request_account_change'")
        elif condition == "account_changed":
            db.execute("UPDATE accounts SET version=1")
    if condition == "revoked":
        manage_agent(settings.database, "agent-it_admin", "revoke")
        headers = bearer(login(client, "it_admin").json()["access_token"])
    response = client.post(f"/account-requests/{approval_id}/execute", headers=headers)
    assert response.status_code == (409 if condition == "account_changed" else 403)
    assert account(settings)[0] == 0


def test_agent_cannot_self_approve_or_change_payload(gateway):
    client, settings = gateway
    headers = bearer(login(client, "it_admin").json()["access_token"])
    response = client.post("/account-requests", headers=headers, json={"account_id": "account-001", "disabled": True, "approved": True})
    assert response.status_code == 422
    response = client.post("/account-requests", headers=headers, json={"account_id": "account-002", "disabled": True})
    assert response.status_code == 403
    assert account(settings) == (0, 0)


def test_audit_failure_rolls_back_approval_execution(gateway):
    client, settings = gateway
    approval_id, headers = request_change(client)
    review_approval(settings.database, approval_id, "approved")
    with sqlite3.connect(settings.database) as db:
        db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(FAIL,'unavailable'); END")
    response = client.post(f"/account-requests/{approval_id}/execute", headers=headers)
    assert response.status_code == 503
    assert account(settings) == (0, 0)
    with sqlite3.connect(settings.database) as db:
        assert db.execute("SELECT state FROM approvals").fetchone()[0] == "approved"


def test_review_failure_rolls_back_and_cannot_be_repeated(gateway):
    client, settings = gateway
    approval_id, _ = request_change(client)
    with sqlite3.connect(settings.database) as db:
        db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(FAIL,'unavailable'); END")
    with pytest.raises(sqlite3.Error):
        review_approval(settings.database, approval_id, "approved")
    with sqlite3.connect(settings.database) as db:
        assert db.execute("SELECT state FROM approvals").fetchone()[0] == "pending"


def test_audit_has_resource_and_task_but_no_injected_content(gateway):
    client, settings = gateway
    token = login(client).json()["access_token"]
    client.get("/tickets/ticket-injection", headers=bearer(token))
    with sqlite3.connect(settings.database) as db:
        rows = db.execute("SELECT * FROM audit").fetchall()
        assert db.execute("SELECT task_id,resource_id FROM audit ORDER BY id DESC LIMIT 1").fetchone() == ("task-support", "ticket-injection")
    assert "SYSTEM OVERRIDE" not in str(rows)
    assert token not in str(rows)
