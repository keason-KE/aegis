import asyncio
import json
import sqlite3

import httpx
import pytest
from fastapi.testclient import TestClient

from aegis.agent import run_ollama, execute_tool
from aegis.app import create_app
from aegis.console import create_console
from aegis.evaluation import evaluate
from test_gateway import gateway, TOKENS
from test_authentication import login

KEY = "operator-test-key-" + "x" * 40
CONSOLE_HEADERS = {"X-Aegis-Console": "1"}


@pytest.fixture
def console(gateway):
    client, settings = gateway
    app = create_console(settings, KEY, gateway_transport=httpx.ASGITransport(app=client.app))
    with TestClient(app, headers=CONSOLE_HEADERS) as operator:
        yield operator, client, settings


def sign_in(client):
    assert client.post("/api/session", json={"key": KEY}).status_code == 200


def test_console_requires_separate_operator_session(console):
    operator, client, _ = console
    token = login(client).json()["access_token"]
    assert operator.get("/").status_code == 200
    assert operator.get("/api/state", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert operator.post("/api/session", json={"key": TOKENS["support"]}).status_code == 401
    sign_in(operator)
    response = operator.get("/api/state")
    assert response.status_code == 200
    assert "credential_hash" not in response.text
    assert KEY not in response.text
    assert operator.cookies.get("aegis_operator")
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert operator.delete("/api/session").status_code == 200
    assert operator.get("/api/state").status_code == 401


def test_csrf_and_host_protection(console):
    operator, _, _ = console
    sign_in(operator)
    assert operator.post("/api/evaluate", headers={"Origin": "https://attacker.example"}).status_code == 403
    assert operator.post("/api/evaluate", headers={"X-Aegis-Console": ""}).status_code == 403
    assert operator.get("/", headers={"Host": "attacker.example"}).status_code == 400


@pytest.mark.parametrize("scenario,role,statuses", [("authorized","support",[200]),("authorized","finance",[200]),("authorized","it_admin",[200]),("cross_role","support",[403]),("horizontal","support",[403]),("injection","support",[200,403]),("approval","it_admin",[202])])
def test_console_scenarios_hit_real_gateway(console, scenario, role, statuses):
    operator, _, settings = console
    sign_in(operator)
    response = operator.post("/api/run", json={"role": role, "scenario": scenario})
    assert response.status_code == 200
    trace = response.json()["trace"]
    assert [step["status"] for step in trace] == statuses
    with sqlite3.connect(settings.database) as db:
        for step in trace:
            assert db.execute("SELECT status FROM audit WHERE request_id=?", (step["request_id"],)).fetchone()[0] == step["status"]
        stored = db.execute("SELECT body FROM console_runs").fetchone()[0]
        assert "Synthetic Customer" not in stored
        assert "SYSTEM OVERRIDE" not in stored


def test_console_approval_and_task_flow(console):
    operator, client, settings = console
    sign_in(operator)
    response = operator.post("/api/run", json={"role":"it_admin","scenario":"approval"})
    approval_id = response.json()["trace"][0]["result"]["approval_id"]
    assert operator.post(f"/api/approvals/{approval_id}/review", json={"decision":"approved"}).status_code == 200
    assert operator.post(f"/api/approvals/{approval_id}/execute").status_code == 200
    assert operator.get("/api/state").json()["accounts"][0]["disabled"] == 1
    token = login(client).json()["access_token"]
    assert operator.post("/api/tasks/task-support", json={"active":False}).status_code == 200
    assert operator.post("/api/tasks/task-support", json={"active":True}).status_code == 200
    assert client.get("/tickets/ticket-001", headers={"Authorization":f"Bearer {token}"}).status_code == 401


def test_evaluation_all_expected_decisions():
    result = asyncio.run(evaluate())
    assert result["passed"] == result["total"] == 16
    assert all(r["request_id"] for r in result["results"])


def test_ollama_tool_loop_enforces_gateway(gateway):
    client, _ = gateway
    token = login(client).json()["access_token"]
    requests = []
    def model(request):
        body = json.loads(request.content)
        requests.append(body)
        assert body["think"] is False
        assert body["options"]["num_predict"] == 512
        assert body["options"]["num_ctx"] == 4096
        if len(requests) == 1:
            return httpx.Response(200, json={"message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"read_financial_report","arguments":{"report_id":"report-001"}}}]}})
        assert body["messages"][-1]["role"] == "tool"
        assert "Permission denied" in body["messages"][-1]["content"]
        return httpx.Response(200, json={"message":{"role":"assistant","content":"Access denied by policy."}})
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=client.app),base_url="http://gateway") as gateway_client:
            return await run_ollama(gateway_client, token, "Read finance", "test-model", model_transport=httpx.MockTransport(model))
    result = asyncio.run(run())
    assert result["trace"][0]["status"] == 403
    assert len(requests) == 2
    assert token not in json.dumps(requests)


def test_unknown_tool_never_executes(gateway):
    client, _ = gateway
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=client.app),base_url="http://gateway") as gateway_client:
            return await execute_tool(gateway_client, "unused", "shell", {"command":"read database"})
    result = asyncio.run(run())
    assert result["status"] == 403
    assert "request_id" not in result


def test_truncated_model_response_is_not_presented_as_completed(gateway):
    client, _ = gateway
    def model(request):
        return httpx.Response(200, json={"done_reason": "length", "message": {"role": "assistant", "content": "Unfinished reasoning", "tool_calls": [{"function": {"name": "read_ticket", "arguments": {"ticket_id": "ticket-001"}}}]}})
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=client.app), base_url="http://gateway") as gateway_client:
            return await run_ollama(gateway_client, "unused", "Read a ticket", "test-model", model_transport=httpx.MockTransport(model))
    result = asyncio.run(run())
    assert "response-length limit" in result["summary"]
    assert "Unfinished reasoning" not in result["summary"]
    assert result["trace"] == []
