"""Persistent machine identities and access-token validation."""

import hashlib
import hmac
import secrets
import sqlite3
import time
from uuid import uuid4

import jwt

from aegis.policies import PERMISSIONS

ISSUER = "aegis-identity"
AUDIENCE = "aegis-gateway"
ALGORITHM = "HS256"


def hash_credential(credential: str, salt: str) -> str:
    return hashlib.scrypt(credential.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


def initialize_registry(db: sqlite3.Connection, credentials: dict[str, str]) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS agents (
        agent_id TEXT PRIMARY KEY,
        role TEXT NOT NULL CHECK(role IN ('support', 'finance', 'it_admin')),
        credential_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
        token_version INTEGER NOT NULL DEFAULT 0 CHECK(token_version >= 0)
    )""")
    for role, credential in credentials.items():
        agent_id = f"agent-{role}"
        if db.execute("SELECT 1 FROM agents WHERE agent_id=?", (agent_id,)).fetchone():
            continue
        salt = secrets.token_hex(16)
        db.execute(
            "INSERT OR IGNORE INTO agents(agent_id, role, credential_hash, salt) VALUES (?, ?, ?, ?)",
            (agent_id, role, hash_credential(credential, salt), salt),
        )


def authenticate(db: sqlite3.Connection, agent_id: str, credential: str):
    agent = db.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
    # Perform the same expensive hash for unknown identities, too.
    salt = agent["salt"] if agent else "00" * 16
    actual = hash_credential(credential, salt)
    expected = agent["credential_hash"] if agent else "00" * 64
    matches = hmac.compare_digest(actual, expected)
    return agent if matches and agent and agent["active"] else None


def issue_token(agent, key: str, ttl: int, scopes: list[str], task_id: str | None = None) -> str:
    now = int(time.time())
    return jwt.encode({
        "iss": ISSUER, "aud": AUDIENCE, "sub": agent["agent_id"],
        "iat": now, "nbf": now, "exp": now + ttl, "jti": str(uuid4()),
        "ver": agent["token_version"], "scope": sorted(scopes), "token_use": "access",
        "task_id": task_id or f"task-{agent['agent_id'].removeprefix('agent-')}",
    }, key, algorithm=ALGORITHM)


def validate_token(db: sqlite3.Connection, token: str, key: str):
    try:
        claims = jwt.decode(
            token, key, algorithms=[ALGORITHM], issuer=ISSUER, audience=AUDIENCE,
            options={"require": ["iss", "aud", "sub", "iat", "nbf", "exp", "jti", "ver", "scope", "token_use"], "strict_aud": True},
        )
    except (TypeError, ValueError) as exc:
        raise jwt.InvalidTokenError("Malformed token claims") from exc
    if (claims["token_use"] != "access" or type(claims["ver"]) is not int
            or not claims["sub"] or not claims["jti"]
            or any(type(claims[c]) is not int for c in ("iat", "nbf", "exp"))
            or claims["exp"] <= claims["iat"]
            or not isinstance(claims["scope"], list)
            or any(not isinstance(s, str) for s in claims["scope"])):
        raise jwt.InvalidTokenError("Invalid access token claims")
    agent = db.execute("SELECT * FROM agents WHERE agent_id=?", (claims["sub"],)).fetchone()
    if (not agent or not agent["active"] or agent["token_version"] != claims["ver"]
            or agent["role"] not in PERMISSIONS):
        raise jwt.InvalidTokenError("Inactive, unknown or revoked identity")
    if not set(claims["scope"]).issubset(PERMISSIONS[agent["role"]]):
        raise jwt.InvalidTokenError("Token scope exceeds current permissions")
    task_id = claims.get("task_id", f"task-{agent['agent_id'].removeprefix('agent-')}")
    if not isinstance(task_id, str) or not task_id:
        raise jwt.InvalidTokenError("Invalid task claim")
    return agent, frozenset(claims["scope"]), task_id
