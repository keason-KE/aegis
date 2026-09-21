"""Small, deny-by-default gateway with transactional local operations and audit."""

import os
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import jwt

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from aegis.policies import PERMISSIONS, authorize
from aegis.identity import authenticate, initialize_registry, issue_token, validate_token
from aegis.resources import initialize_resources, check_task, read_resource


@dataclass(frozen=True)
class Settings:
    credentials: dict[str, str] = field(repr=False)
    database: Path = Path("aegis.sqlite3")
    signing_key: str = field(default="", repr=False)
    token_ttl_seconds: int = 300

    def __post_init__(self):
        if set(self.credentials) != set(PERMISSIONS):
            raise ValueError("Exactly support, finance and it_admin credentials are required")
        secrets = [*self.credentials.values(), self.signing_key]
        if any(not 32 <= len(secret) <= 1024 or not secret.isascii() or any(c.isspace() for c in secret) for secret in secrets):
            raise ValueError("Credentials and signing key must be at least 32 ASCII characters without whitespace")
        if len(set(secrets)) != 4:
            raise ValueError("Agent credentials and signing key must be distinct")
        if type(self.token_ttl_seconds) is not int or not 30 <= self.token_ttl_seconds <= 900:
            raise ValueError("Token lifetime must be between 30 and 900 seconds")

    @classmethod
    def from_env(cls):
        return cls(
            {role: os.environ.get(f"AEGIS_{role.upper()}_SECRET", "") for role in PERMISSIONS},
            Path(os.environ.get("AEGIS_DATABASE", "aegis.sqlite3")),
            os.environ.get("AEGIS_SIGNING_KEY", ""),
            int(os.environ.get("AEGIS_TOKEN_TTL_SECONDS", "300")),
        )


class AccountChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    disabled: bool


class TokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    agent_id: str = Field(min_length=1, max_length=100)
    client_secret: SecretStr = Field(min_length=1, max_length=1024)
    scopes: list[str] | None = Field(default=None, max_length=10)
    task_id: str | None = Field(default=None, min_length=1, max_length=100)


class ChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    account_id: str = Field(min_length=1, max_length=100)
    disabled: bool


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    with closing(sqlite3.connect(settings.database)) as db, db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, request_id TEXT NOT NULL,
                agent_id TEXT, role TEXT, permission TEXT, method TEXT NOT NULL,
                route TEXT NOT NULL, status INTEGER NOT NULL, decision TEXT NOT NULL
            );
        """)
        initialize_registry(db, settings.credentials)
        initialize_resources(db)

    app = FastAPI(title="Aegis authorization gateway", version="1.0.0")
    bearer = HTTPBearer(auto_error=False)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        # Pydantic's default errors may echo raw credential input back to clients.
        return JSONResponse({"detail": "Invalid request"}, status_code=422)

    @app.middleware("http")
    async def audit_request(request: Request, call_next):
        request_id = str(uuid4())
        request.state.agent_id = None
        request.state.role = None
        request.state.permission = None
        request.state.task_id = None
        request.state.resource_id = None
        request.state.reason = None
        try:
            db = sqlite3.connect(settings.database)
        except sqlite3.Error:
            return JSONResponse(
                {"detail": "Audit storage unavailable"}, status_code=503,
                headers={"X-Request-ID": request_id},
            )
        db.row_factory = sqlite3.Row
        request.state.db = db
        try:
            try:
                response = await call_next(request)
            except Exception:
                db.rollback()
                response = JSONResponse({"detail": "Internal server error"}, status_code=500)
            if response.status_code >= 400:
                db.rollback()
            route = request.scope.get("route")
            db.execute(
                "INSERT INTO audit(timestamp, request_id, agent_id, role, permission, method, route, status, decision, task_id, resource_id, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), request_id, request.state.agent_id,
                 request.state.role, request.state.permission, request.method,
                 getattr(route, "path", "<unmatched>"), response.status_code,
                 "denied" if response.status_code in (401, 403) else "error" if response.status_code >= 400 else "allowed",
                 request.state.task_id, request.state.resource_id, request.state.reason),
            )
            # Local state changes and their audit outcome commit together.
            db.commit()
        except sqlite3.Error:
            db.rollback()
            response = JSONResponse({"detail": "Audit storage unavailable"}, status_code=503)
        finally:
            db.close()
        response.headers["X-Request-ID"] = request_id
        return response

    def require(permission: str):
        async def authenticate_and_authorize(request: Request, auth: HTTPAuthorizationCredentials | None = Depends(bearer)):
            request.state.permission = permission
            try:
                if auth is None:
                    raise jwt.InvalidTokenError("Missing bearer token")
                agent, scopes, task_id = validate_token(request.state.db, auth.credentials, settings.signing_key)
            except jwt.InvalidTokenError:
                request.state.reason = "Invalid, expired, disabled or revoked identity"
                raise HTTPException(401, "Invalid or missing bearer token", headers={"WWW-Authenticate": "Bearer"})
            role = agent["role"]
            request.state.role = role
            request.state.agent_id = agent["agent_id"]
            request.state.task_id = task_id
            if not authorize(role, permission):
                if role == "it_admin" and permission == "modify_account":
                    raise HTTPException(403, "Separate human approval required; submit an account change request")
                request.state.reason = "Role does not permit this operation"
                raise HTTPException(403, "Permission denied")
            if permission not in scopes:
                request.state.reason = "Token scope does not permit this operation"
                raise HTTPException(403, "Token scope does not permit this operation")
            resource_id = next((request.path_params[k] for k in ("ticket_id", "report_id", "account_id") if k in request.path_params), "system" if permission == "read_system_status" else None)
            # Store only known synthetic identifiers; attacker-controlled paths are redacted.
            if resource_id and (resource_id == "system" or request.state.db.execute("SELECT 1 FROM resources WHERE resource_id=?", (resource_id,)).fetchone()):
                request.state.resource_id = resource_id
            try:
                check_task(request.state.db, task_id, agent["agent_id"], permission, resource_id)
            except HTTPException as exc:
                request.state.reason = exc.detail
                raise
            request.state.reason = "Identity, role, token and task scope verified"
            return agent["agent_id"]
        return authenticate_and_authorize

    @app.post("/auth/token")
    async def token(payload: TokenRequest, request: Request):
        request.state.permission = "authenticate"
        agent = authenticate(request.state.db, payload.agent_id, payload.client_secret.get_secret_value())
        if agent is None:
            raise HTTPException(401, "Invalid agent credentials")
        request.state.agent_id = agent["agent_id"]
        request.state.role = agent["role"]
        allowed = PERMISSIONS.get(agent["role"], frozenset())
        scopes = sorted(allowed) if payload.scopes is None else payload.scopes
        if not set(scopes).issubset(allowed):
            raise HTTPException(403, "Requested scope exceeds role permissions")
        task_id = payload.task_id or f"task-{agent['role']}"
        check_task(request.state.db, task_id, agent["agent_id"])
        request.state.task_id = task_id
        access_token = issue_token(agent, settings.signing_key, settings.token_ttl_seconds, scopes, task_id)
        return JSONResponse(
            {"access_token": access_token, "token_type": "bearer", "expires_in": settings.token_ttl_seconds, "scope": scopes},
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/tickets/{ticket_id}", dependencies=[Depends(require("read_ticket"))])
    async def read_ticket(ticket_id: str, request: Request):
        return read_resource(request.state.db, ticket_id)

    @app.get("/financial-reports/{report_id}", dependencies=[Depends(require("read_financial_report"))])
    async def read_financial_report(report_id: str, request: Request):
        return read_resource(request.state.db, report_id)

    @app.get("/system/status", dependencies=[Depends(require("read_system_status"))])
    async def read_system_status():
        return {"environment": "mock", "status": "operational"}

    @app.patch("/accounts/{account_id}", dependencies=[Depends(require("modify_account"))])
    async def modify_account(account_id: str, payload: AccountChange):
        # Defense in depth: no account mutation exists until human approval is implemented.
        raise HTTPException(403, "Separate human approval required; submit an account change request")

    @app.post("/account-requests", dependencies=[Depends(require("request_account_change"))], status_code=202)
    async def request_change(payload: ChangeRequest, request: Request):
        db = request.state.db
        db.execute("BEGIN IMMEDIATE")
        check_task(db, request.state.task_id, request.state.agent_id, "request_account_change", payload.account_id)
        account = db.execute("SELECT * FROM accounts WHERE account_id=?", (payload.account_id,)).fetchone()
        if not account:
            raise HTTPException(404, "Account not found")
        agent = db.execute("SELECT * FROM agents WHERE agent_id=?", (request.state.agent_id,)).fetchone()
        approval_id = str(uuid4())
        now = int(time.time())
        db.execute("INSERT INTO approvals(approval_id,agent_id,task_id,account_id,disabled,account_version,token_version,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
                   (approval_id, agent["agent_id"], request.state.task_id, payload.account_id, int(payload.disabled), account["version"], agent["token_version"], now, now + 600))
        request.state.resource_id = payload.account_id
        request.state.reason = "Change queued; separate human approval required"
        return {"approval_id": approval_id, "state": "pending", "expires_at": now + 600, "detail": "No account change has occurred"}

    @app.post("/account-requests/{approval_id}/execute", dependencies=[Depends(require("request_account_change"))])
    async def execute_change(approval_id: str, request: Request):
        db = request.state.db
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM approvals WHERE approval_id=? AND agent_id=? AND task_id=?", (approval_id, request.state.agent_id, request.state.task_id)).fetchone()
        if not row:
            raise HTTPException(404, "Approval request not found")
        check_task(db, row["task_id"], row["agent_id"], "request_account_change", row["account_id"])
        version = db.execute("SELECT token_version FROM agents WHERE agent_id=?", (row["agent_id"],)).fetchone()[0]
        if row["state"] != "approved" or row["expires_at"] <= int(time.time()) or row["token_version"] != version:
            raise HTTPException(403, "A current, unused human approval is required")
        updated = db.execute("UPDATE accounts SET disabled=?,version=version+1 WHERE account_id=? AND version=?", (row["disabled"], row["account_id"], row["account_version"]))
        if not updated.rowcount:
            raise HTTPException(409, "Account changed since this request; submit a new request")
        db.execute("UPDATE approvals SET state='executed',executed_at=? WHERE approval_id=?", (int(time.time()), approval_id))
        request.state.resource_id = row["account_id"]
        request.state.reason = "Human-approved change executed once"
        return {"account_id": row["account_id"], "disabled": bool(row["disabled"]), "state": "executed"}

    return app
