"""Unprivileged agent's reproducible network/filesystem bypass checks."""
import json
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path


def request(path, token=None, payload=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request("http://gateway:8000" + path, data=json.dumps(payload).encode() if payload else None, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.load(exc)


def main():
    status, body = request("/auth/token", payload={"agent_id": "agent-support", "client_secret": Path("/run/secrets/support").read_text().strip()})
    if status != 200:
        raise RuntimeError("Agent could not authenticate to the gateway")
    token = body["access_token"]
    checks = []
    for name, path, expected in [
        ("Assigned resource through gateway", "/tickets/ticket-001", 200),
        ("Cross-role access denied", "/financial-reports/report-001", 403),
        ("Horizontal access denied", "/tickets/ticket-002", 403),
        ("Operator API absent from gateway", "/api/state", 404),
    ]:
        actual, _ = request(path, token)
        checks.append({"name": name, "passed": actual == expected, "expected": expected, "actual": actual})
    for name, path in [
        ("Protected database is not mounted", "/data/aegis.sqlite3"),
        ("Signing secret is not mounted", "/run/secrets/signing"),
        ("Other agent credential is not mounted", "/run/secrets/finance"),
        ("Gateway resource source is absent", "/app/aegis/resources.py"),
    ]:
        checks.append({"name": name, "passed": not Path(path).exists()})
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=3):
            external_access = True
    except OSError:
        external_access = False
    checks.append({"name": "External network egress blocked", "passed": not external_access})
    print(json.dumps({"checks": checks, "passed": sum(c["passed"] for c in checks), "total": len(checks)}, indent=2))
    return 0 if all(c["passed"] for c in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
