"""Human operator console. Never mounted on the agent gateway."""

import asyncio
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from starlette.middleware.trustedhost import TrustedHostMiddleware

from aegis.admin import manage_agent
from aegis.agent import execute_tool, run_ollama
from aegis.evaluation import evaluate
from aegis.policies import PERMISSIONS
from aegis.resources import operator_event, review_approval

STATIC = Path(__file__).parent / "static"


class Login(BaseModel):
    key: SecretStr = Field(max_length=200)


class Run(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["support", "finance", "it_admin"] = "support"
    scenario: Literal["authorized", "cross_role", "horizontal", "injection", "approval", "ollama"] = "authorized"
    prompt: str = Field(default="Summarize ticket-001 and suggest a response.", max_length=4000)
    model: str = Field(default="", max_length=100)
    disabled: bool = True


class Review(BaseModel):
    decision: Literal["approved", "rejected"]


class AgentAction(BaseModel):
    action: Literal["disable", "enable", "revoke"]


class TaskAction(BaseModel):
    active: bool


def create_console(settings, operator_key, gateway_url="http://127.0.0.1:8766", gateway_transport=None):
    app = FastAPI(title="Aegis operator console", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])
    sessions = {}
    login_attempts = []
    run_lock = asyncio.Lock()
    with closing(sqlite3.connect(settings.database)) as db, db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS console_runs (id INTEGER PRIMARY KEY, created_at INTEGER NOT NULL, role TEXT NOT NULL, scenario TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evaluations (id INTEGER PRIMARY KEY, body TEXT NOT NULL);
        """)

    @app.middleware("http")
    async def security_headers(request, call_next):
        if request.method not in ("GET", "HEAD"):
            origin = request.headers.get("origin")
            if request.headers.get("x-aegis-console") != "1" or (origin and origin != str(request.base_url).rstrip("/")):
                return JSONResponse({"detail": "Same-origin console request required"}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        return response

    @app.exception_handler(sqlite3.Error)
    async def storage_error(request, exc):
        return JSONResponse({"detail": "Storage unavailable; operation not confirmed"}, status_code=503)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        return JSONResponse({"detail": "Invalid request"}, status_code=422)

    @app.exception_handler(httpx.HTTPError)
    async def upstream_error(request, exc):
        return JSONResponse({"detail": "Gateway or local model unavailable. Check the service and try again."}, status_code=503)

    def operator(request: Request):
        session = request.cookies.get("aegis_operator", "")
        if sessions.get(session, 0) <= time.time():
            sessions.pop(session, None)
            raise HTTPException(401, "Open the launch link or enter your local operator key")

    @contextmanager
    def connect():
        with closing(sqlite3.connect(settings.database)) as db, db:
            db.row_factory = sqlite3.Row
            yield db

    def gateway():
        return httpx.AsyncClient(base_url=gateway_url, transport=gateway_transport, timeout=20, trust_env=False)

    async def authenticate_agent(client, role):
        response = await client.post("/auth/token", json={"agent_id": f"agent-{role}", "client_secret": settings.credentials[role]})
        if response.status_code != 200:
            raise HTTPException(response.status_code, response.json().get("detail", "Authentication failed"))
        return response.json()["access_token"]

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.post("/api/session")
    async def login(payload: Login):
        now = time.time()
        login_attempts[:] = [t for t in login_attempts if t > now - 60]
        if len(login_attempts) >= 10:
            raise HTTPException(429, "Too many login attempts; wait one minute")
        if not hmac.compare_digest(payload.key.get_secret_value().encode(), operator_key.encode()):
            login_attempts.append(now)
            raise HTTPException(401, "Invalid operator key")
        for key in [key for key, expiry in sessions.items() if expiry <= now]:
            del sessions[key]
        session = secrets.token_urlsafe(48)
        sessions[session] = now + 28800
        response = JSONResponse({"authenticated": True})
        response.set_cookie("aegis_operator", session, httponly=True, samesite="strict", max_age=28800)
        return response

    @app.delete("/api/session")
    async def logout(request: Request):
        sessions.pop(request.cookies.get("aegis_operator", ""), None)
        response = JSONResponse({"authenticated": False})
        response.delete_cookie("aegis_operator")
        return response

    @app.get("/api/state", dependencies=[Depends(operator)])
    async def state():
        with connect() as db:
            agents = [dict(r) for r in db.execute("SELECT agent_id,role,active,token_version FROM agents ORDER BY agent_id")]
            tasks = [dict(r) for r in db.execute("SELECT * FROM tasks ORDER BY task_id")]
            for task in tasks:
                task["grants"] = [dict(r) for r in db.execute("SELECT action,resource_id FROM grants WHERE task_id=?", (task["task_id"],))]
            approvals = [dict(r) for r in db.execute("SELECT * FROM approvals ORDER BY created_at DESC LIMIT 100")]
            for approval in approvals:
                if approval["state"] in ("pending", "approved") and approval["expires_at"] <= time.time():
                    approval["state"] = "expired"
            counts = dict(db.execute("SELECT decision,count(*) FROM audit WHERE method != 'LOCAL' AND permission IS NOT NULL AND permission != 'authenticate' GROUP BY decision").fetchall())
            runs = [{"id": r["id"], "created_at": r["created_at"], "role": r["role"], "scenario": r["scenario"], **json.loads(r["body"])} for r in db.execute("SELECT * FROM console_runs ORDER BY id DESC LIMIT 20")]
            evaluation = db.execute("SELECT body FROM evaluations ORDER BY id DESC LIMIT 1").fetchone()
            accounts = [dict(r) for r in db.execute("SELECT * FROM accounts")]
        return {"agents": agents, "tasks": tasks, "approvals": approvals, "accounts": accounts, "counts": counts, "runs": runs, "evaluation": json.loads(evaluation[0]) if evaluation else None, "permissions": {k: sorted(v) for k, v in PERMISSIONS.items()}, "mode": "local lab"}

    @app.get("/api/events", dependencies=[Depends(operator)])
    async def events():
        with connect() as db:
            rows = [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200")]
        return {"events": rows}

    @app.get("/api/models", dependencies=[Depends(operator)])
    async def models():
        try:
            async with httpx.AsyncClient(timeout=2, trust_env=False) as client:
                response = await client.get(os.environ.get("AEGIS_OLLAMA_URL", "http://127.0.0.1:11434") + "/api/tags")
                response.raise_for_status()
                return {"available": True, "models": [m["name"] for m in response.json().get("models", [])]}
        except (httpx.HTTPError, ValueError, KeyError):
            return {"available": False, "models": []}

    @app.post("/api/run", dependencies=[Depends(operator)])
    async def run(payload: Run):
        if run_lock.locked():
            raise HTTPException(409, "Another run is in progress")
        async with run_lock, gateway() as client:
            token = await authenticate_agent(client, payload.role)
            trace = []
            if payload.scenario == "ollama":
                if not payload.model:
                    raise HTTPException(422, "Select an installed Ollama model")
                try:
                    result = await run_ollama(client, token, payload.prompt, payload.model, os.environ.get("AEGIS_OLLAMA_URL", "http://127.0.0.1:11434"))
                except (ValueError, KeyError, TypeError, AttributeError):
                    raise HTTPException(502, "The model returned an invalid tool-call response")
            elif payload.scenario == "approval":
                response = await client.post("/account-requests", headers={"Authorization": f"Bearer {token}"}, json={"account_id": "account-001", "disabled": payload.disabled})
                trace.append({"tool": "request_account_change", "status": response.status_code, "result": response.json(), "request_id": response.headers.get("x-request-id")})
                result = {"mode": "deterministic", "summary": "Account change requested. Review the gateway decision below; successful requests await a separate human decision in Approvals.", "trace": trace}
            else:
                if payload.scenario == "injection":
                    trace.append(await execute_tool(client, token, "read_ticket", {"ticket_id": "ticket-injection"}))
                    calls = [("read_financial_report", {"report_id": "report-001"})]
                    summary = "The scripted client attempted the instruction embedded in the ticket. The gateway evaluated it against the authenticated role. This tests enforcement, not model behavior."
                elif payload.scenario == "cross_role":
                    calls = [("read_ticket", {"ticket_id": "ticket-001"})] if payload.role != "support" else [("read_financial_report", {"report_id": "report-001"})]
                    summary = "Attempted an operation outside this agent's role. Inspect the policy decision and matching audit event."
                elif payload.scenario == "horizontal":
                    calls = [("read_ticket", {"ticket_id": "ticket-002"})] if payload.role != "finance" else [("read_financial_report", {"report_id": "report-002"})]
                    summary = "Attempted to access a record outside the assigned task. Role permissions alone do not grant access to every record."
                else:
                    calls = {"support": [("read_ticket", {"ticket_id": "ticket-001"})], "finance": [("read_financial_report", {"report_id": "report-001"})], "it_admin": [("read_system_status", {})]}[payload.role]
                    summary = "Executed the agent's assigned tool request through the identity and authorization gateway."
                for name, arguments in calls:
                    trace.append(await execute_tool(client, token, name, arguments))
                result = {"mode": "deterministic", "summary": summary, "trace": trace}
            # Store gateway outcomes, not user prompts or model-generated text/resource contents.
            stored = {"mode": result["mode"], "summary": "Run completed. Audit events contain the authorization evidence.", "trace": [{k: v for k, v in item.items() if k != "result"} for item in result["trace"]]}
            with connect() as db:
                db.execute("INSERT INTO console_runs(created_at,role,scenario,body) VALUES (?,?,?,?)", (int(time.time()), payload.role, payload.scenario, json.dumps(stored)))
            return result

    @app.post("/api/agents/{agent_id}", dependencies=[Depends(operator)])
    async def agent_action(agent_id: str, payload: AgentAction):
        try:
            manage_agent(settings.database, agent_id, payload.action)
        except ValueError as exc:
            raise HTTPException(404, str(exc))
        return {"updated": True}

    @app.post("/api/tasks/{task_id}", dependencies=[Depends(operator)])
    async def task_action(task_id: str, payload: TaskAction):
        with connect() as db:
            db.execute("BEGIN IMMEDIATE")
            task = db.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not task:
                raise HTTPException(404, "Task not found")
            db.execute("UPDATE tasks SET active=? WHERE task_id=?", (int(payload.active), task_id))
            # Reopening a task must not resurrect tokens issued before it was closed.
            db.execute("UPDATE agents SET token_version=token_version+1 WHERE agent_id=?", (task["agent_id"],))
            operator_event(db, "task:activate" if payload.active else "task:complete", task["agent_id"], task_id)
        return {"updated": True}

    @app.post("/api/approvals/{approval_id}/review", dependencies=[Depends(operator)])
    async def review(approval_id: str, payload: Review):
        review_approval(settings.database, approval_id, payload.decision)
        return {"state": payload.decision}

    @app.post("/api/approvals/{approval_id}/execute", dependencies=[Depends(operator)])
    async def execute(approval_id: str):
        async with gateway() as client:
            token = await authenticate_agent(client, "it_admin")
            response = await client.post(f"/account-requests/{approval_id}/execute", headers={"Authorization": f"Bearer {token}"})
        return JSONResponse(response.json(), status_code=response.status_code)

    @app.post("/api/evaluate", dependencies=[Depends(operator)])
    async def evaluation():
        if run_lock.locked():
            raise HTTPException(409, "Another run is in progress")
        async with run_lock:
            result = await evaluate()
            with connect() as db:
                db.execute("INSERT INTO evaluations(body) VALUES (?)", (json.dumps(result),))
        return result

    @app.get("/api/report", dependencies=[Depends(operator)])
    async def report():
        with connect() as db:
            row = db.execute("SELECT body FROM evaluations ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            raise HTTPException(404, "Run the evaluation first")
        return JSONResponse(json.loads(row[0]), headers={"Content-Disposition": 'attachment; filename="aegis-security-evaluation.json"'})

    return app
