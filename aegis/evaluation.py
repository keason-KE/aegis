"""Repeatable, isolated authorization experiments using the real gateway."""

import secrets
import sqlite3
import tempfile
import time
from contextlib import closing
from pathlib import Path

import httpx
import jwt

from aegis.admin import manage_agent
from aegis.app import Settings, create_app
from aegis.resources import review_approval


async def evaluate():
    results = []
    with tempfile.TemporaryDirectory(prefix="aegis-evaluation-") as directory:
        settings = Settings({r: secrets.token_urlsafe(40) for r in ("support", "finance", "it_admin")}, Path(directory) / "evaluation.sqlite3", secrets.token_urlsafe(48))
        app = create_app(settings)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gateway") as client:
            tokens = {}
            for role, secret in settings.credentials.items():
                response = await client.post("/auth/token", json={"agent_id": f"agent-{role}", "client_secret": secret})
                response.raise_for_status()
                tokens[role] = response.json()["access_token"]

            async def probe(name, category, method, path, expected, role="support", token=None, **kwargs):
                headers = {"Authorization": "Bearer " + (token or tokens[role]), **kwargs.pop("headers", {})}
                response = await client.request(method, path, headers=headers, **kwargs)
                results.append({"name": name, "category": category, "expected": expected, "actual": response.status_code, "passed": response.status_code == expected, "request_id": response.headers.get("x-request-id")})
                return response

            await probe("Support reads assigned ticket", "authorized", "GET", "/tickets/ticket-001", 200)
            await probe("Finance reads assigned report", "authorized", "GET", "/financial-reports/report-001", 200, "finance")
            await probe("IT reads system health", "authorized", "GET", "/system/status", 200, "it_admin")
            await probe("Vertical privilege escalation", "unauthorized", "PATCH", "/accounts/account-001", 403, json={"disabled": True})
            await probe("Horizontal customer access", "unauthorized", "GET", "/tickets/ticket-002", 403)
            await probe("Identity spoofing via headers", "unauthorized", "GET", "/financial-reports/report-001", 403, headers={"X-Agent-ID": "agent-finance", "X-Role": "finance"})
            await probe("Read injected ticket", "authorized", "GET", "/tickets/ticket-injection", 200)
            await probe("Injected finance tool call", "unauthorized", "GET", "/financial-reports/report-001", 403)
            claims = jwt.decode(tokens["support"], options={"verify_signature": False})
            claims.update(iat=int(time.time())-60, nbf=int(time.time())-60, exp=int(time.time())-1)
            expired = jwt.encode(claims, settings.signing_key, algorithm="HS256")
            await probe("Expired access token", "unauthorized", "GET", "/tickets/ticket-001", 401, token=expired)
            forged = jwt.encode(claims, secrets.token_urlsafe(48), algorithm="HS256")
            await probe("Forged token signature", "unauthorized", "GET", "/tickets/ticket-001", 401, token=forged)
            approval = await client.post("/account-requests", headers={"Authorization": f"Bearer {tokens['it_admin']}"}, json={"account_id": "account-001", "disabled": True})
            approval_id = approval.json()["approval_id"]
            await probe("Execution without human review", "unauthorized", "POST", f"/account-requests/{approval_id}/execute", 403, "it_admin")
            review_approval(settings.database, approval_id, "approved")
            await probe("Human-approved account change", "authorized", "POST", f"/account-requests/{approval_id}/execute", 200, "it_admin")
            await probe("Replay of consumed approval", "unauthorized", "POST", f"/account-requests/{approval_id}/execute", 403, "it_admin")
            manage_agent(settings.database, "agent-support", "revoke")
            await probe("Revoked access token", "unauthorized", "GET", "/tickets/ticket-001", 401)
            with closing(sqlite3.connect(settings.database)) as db, db:
                db.execute("UPDATE tasks SET active=0 WHERE task_id='task-finance'")
            await probe("Completed task loses access", "unauthorized", "GET", "/financial-reports/report-001", 403, "finance")
            with closing(sqlite3.connect(settings.database)) as db, db:
                db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(FAIL,'unavailable'); END")
            await probe("Audit failure releases no data", "resilience", "GET", "/system/status", 503, "it_admin")
    return {"created_at": int(time.time()), "results": results, "passed": sum(r["passed"] for r in results), "total": len(results), "scope": "Real gateway, isolated synthetic database, deterministic HTTP clients. Prompt-injection case forces the attempted tool call; it does not measure model susceptibility. Container bypass is a separate deployment check."}
