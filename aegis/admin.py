"""Local operator commands. Never exposed to an agent over HTTP."""

import argparse
import getpass
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from aegis.identity import hash_credential


def manage_agent(database: Path, agent_id: str, action: str, credential: str | None = None) -> None:
    if action not in {"disable", "enable", "revoke", "rotate"}:
        raise ValueError("Unknown administrative action")
    if action == "rotate" and (
        credential is None or len(credential) < 32 or len(credential) > 1024
        or not credential.isascii() or any(c.isspace() for c in credential)
    ):
        raise ValueError("Credential must be 32–1024 ASCII characters without whitespace")
    # Do not accidentally create a new database when the operator mistypes a path.
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=rw", uri=True)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        if not db.execute("SELECT 1 FROM agents WHERE agent_id=?", (agent_id,)).fetchone():
            raise ValueError("Unknown agent")
        if action in {"disable", "enable"}:
            db.execute("UPDATE agents SET active=?, token_version=token_version+1 WHERE agent_id=?", (int(action == "enable"), agent_id))
        elif action == "revoke":
            db.execute("UPDATE agents SET token_version=token_version+1 WHERE agent_id=?", (agent_id,))
        else:
            salt = secrets.token_hex(16)
            db.execute("UPDATE agents SET credential_hash=?, salt=?, token_version=token_version+1 WHERE agent_id=?", (hash_credential(credential, salt), salt, agent_id))
        db.execute(
            "INSERT INTO audit(timestamp, request_id, agent_id, role, permission, method, route, status, decision) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), str(uuid4()), agent_id, "local_operator",
             f"identity:{action}", "LOCAL", "identity-registry", 200, "allowed"),
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["disable", "enable", "revoke", "rotate"])
    parser.add_argument("agent_id")
    parser.add_argument("--database", type=Path, default=Path("aegis.sqlite3"))
    args = parser.parse_args()
    credential = getpass.getpass("New agent secret: ") if args.action == "rotate" else None
    try:
        manage_agent(args.database, args.agent_id, args.action, credential)
    except (ValueError, sqlite3.Error) as exc:
        parser.exit(1, f"Identity update failed: {exc}\n")
    print(f"{args.action}: {args.agent_id}; previous tokens invalidated")


if __name__ == "__main__":
    main()
