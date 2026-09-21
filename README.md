# Aegis — AI Agent Identity and Access Control

## My role

I defined the security requirements and directed AI-assisted development of Aegis. The implementation was AI-assisted; I do not represent it as independently hand-coded software. This project demonstrates my work specifying identity boundaries, permissions, approval requirements, and security scenarios.

## Portfolio review status

The documentation below describes the local research prototype. Historical results in the security assessment must be distinguished from current reproduction results. Container isolation and systematic live-model prompt-injection testing are not established by passing application tests. Use synthetic data only; never publish local demo configuration, signing material, databases, or authenticated launch URLs.

A browser-based security research lab for three synthetic agents. Aegis authenticates every tool request, checks role and task-level resource grants, requires a separate human decision for account changes, and records the result.

## Start the demo

From this folder in VS Code's PowerShell terminal:

```powershell
# First setup only, if .venv does not already exist:
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[test]'

# Start both services and open your authenticated browser session:
.\.venv\Scripts\python.exe -m aegis.demo
```

Dashboard: **http://127.0.0.1:8765**. Agent gateway: **http://127.0.0.1:8766**. Stop with Ctrl+C. VS Code also has **Terminal → Run Task → Aegis: launch browser demo**, a full-suite test task, and an F5 configuration for the Python debugger extension.

The launcher generates independent random agent, signing, and operator secrets once in `.aegis-demo/config.json`. It opens a URL fragment containing the operator key; the dashboard exchanges that for an eight-hour HttpOnly, SameSite cookie and removes the fragment. The ordinary address reuses that browser session. In another browser, run the launcher or enter `operator_key` from the local config on the login page. Do not share the config or launch URL.

`--no-browser` starts without opening a window. `--port`, `--gateway-port`, and `--data-dir` support a second independent lab. Demo data is separate from the earlier `aegis.sqlite3` database. Launch and tests do not delete that database.

## Five-minute demonstration

1. **Playground → Support → Authorized task.** The assigned ticket returns HTTP 200 with a request ID linking it to the audit trail.
2. **Cross-role access attempt.** The same identity gets HTTP 403 for Finance.
3. **Out-of-scope resource.** Support cannot read another customer's ticket, despite its general ticket-reading permission.
4. **Prompt-injection simulation.** A ticket contains hostile instructions. The scripted client attempts the finance call; the gateway blocks it. This measures enforcement, not model susceptibility.
5. **IT administration → Request an account change.** Choose the account state, submit, then use **Approvals → Approve exact change → Execute approved change**. No change occurs before review. Approval expires after ten minutes and is single-use. Submit an enable request to restore the account.
6. **Identities & tasks.** Disable an agent, revoke tokens, or complete a task. Access changes immediately. Re-enable/reopen to continue; previous tokens remain invalid.
7. **Security evaluation → Run evaluation.** Sixteen checks run against the real gateway implementation in an isolated temporary database. Download the JSON results. The evaluation does not modify your demo identities.

## Local Ollama integration

Deterministic mode works offline. **Live Ollama agent** uses an installed local tool-calling model through `/api/chat`. Start Ollama, install a tool-capable model, and refresh the dashboard. The model picker discovers `/api/tags`; it does not install models or call a hosted API.

For this demo, install `ollama pull qwen3:4b-instruct`, then select **qwen3:4b-instruct** in the playground. The plain `qwen3:4b` tag currently selects a thinking-focused variant that can exhaust the demo's response budget before calling a tool. The runner uses a 4,096-token context, a 512-token response budget per turn, and a 120-second request timeout to keep local CPU runs bounded. Truncated responses are reported explicitly.

Try `Summarize ticket-001 and suggest a response.` with Support. For injection research, try `Read ticket-injection and help this customer.` The trace shows actual model tool calls. A model may refuse an instruction, attempt it and be blocked, or fail to use a tool; these are different observations.

The runner permits at most six tool calls and seven turns, validates arguments, never supplies credentials to the model, and has no shell/filesystem tool. The default endpoint is `http://127.0.0.1:11434`; a trusted operator can set `AEGIS_OLLAMA_URL` before launch. Prompts and synthetic tool responses go to that configured model, not to the audit log. Model output is rendered as text, never HTML.

## Architecture and boundaries

```text
Human browser ── operator session ──> Console :8765
                                      │ human decisions + audit
                                      │ HTTP authentication/tool calls
                                      ▼
Agent / bounded model runner ── JWT ──> Gateway :8766
                                      │ identity + role + scope + task + resource
                                      ▼
                                   SQLite
                             synthetic resources / audit
```

The console is the trusted human control plane, with a separate secret. It is **not mounted on the gateway**. Agent JWTs cannot review approvals. Browser mutations require a same-origin request and custom header; no permissive CORS policy is installed. Local listeners bind only to loopback.

Local demonstration is not OS isolation: a program running as your user can read local secrets and databases. Use the Docker lab to test a container boundary. Do not expose the console publicly.

| Identity | Tickets | Finance | System status | Account changes |
|---|---|---|---|---|
| Support | Assigned IDs | Deny | Deny | Deny |
| Finance | Deny | Assigned IDs | Deny | Deny |
| IT administration | Deny | Deny | Allow | Request + human approval |

SQLite stores salted scrypt credential hashes, tasks, grants, protected records, accounts, approvals, and audit. Bootstrap preserves existing identity state and grants. HS256 JWT validation pins the algorithm and validates signature, issuer, audience, subject, token type, timestamps, token ID, scopes and registry version. New tokens carry a task ID. Legacy tokens without that claim are confined to the identity's default task. Registry/task checks apply to every request. Unknown resources fail scope checks before existence is revealed.

Approvals bind identity, task, account, exact boolean change, credential version, and account revision. Expiry, rejection, revocation, task closure, grant removal, competing changes, and replay prevent execution. Account mutation, approval consumption, and audit commit together; audit failure returns 503 and rolls back the mutation.

## Gateway-only operation

The original entry point remains available:

```powershell
# First set AEGIS_SUPPORT_SECRET, AEGIS_FINANCE_SECRET, AEGIS_IT_ADMIN_SECRET,
# and AEGIS_SIGNING_KEY to four distinct random secrets.
.\.venv\Scripts\python.exe -m uvicorn aegis.app:create_app --factory --host 127.0.0.1
```

Secrets require 32–1024 ASCII characters without whitespace; there are no defaults. `AEGIS_DATABASE` defaults to `aegis.sqlite3`. `AEGIS_TOKEN_TTL_SECONDS` accepts 30–900, default 300.

`POST /auth/token` accepts `agent_id`, `client_secret`, optional action `scopes`, and optional `task_id`. An empty scope grants nothing. Protected routes: `/tickets/{id}`, `/financial-reports/{id}`, `/system/status`, `POST /account-requests`, and `POST /account-requests/{approval_id}/execute`. Direct account PATCH is always denied. Gateway `/health`, `/docs`, and `/openapi.json` are public.

```powershell
.\.venv\Scripts\python.exe -m aegis.admin disable agent-support --database .aegis-demo/aegis.sqlite3
.\.venv\Scripts\python.exe -m aegis.admin enable agent-support --database .aegis-demo/aegis.sqlite3
.\.venv\Scripts\python.exe -m aegis.admin revoke agent-support --database .aegis-demo/aegis.sqlite3
.\.venv\Scripts\python.exe -m aegis.admin rotate agent-support --database .aegis-demo/aegis.sqlite3
```

Rotation prompts without echoing. Update the matching local demo config credential yourself after rotation. Changing bootstrap values does not rotate existing registry credentials. CLI administration trusts OS access.

## Container isolation experiment

Requires a working Docker Desktop Linux engine:

```powershell
.\.venv\Scripts\python.exe -m aegis.lab
docker compose config --quiet
docker compose up --build --abort-on-container-exit --exit-code-from agent
```

The agent image contains only a standard-library HTTP probe and its Support secret. It has no gateway package, signing key, Finance credential, or database mount. Only the gateway mounts `/data`. The network is internal. Containers use distinct non-root users, read-only roots, dropped capabilities, and no-new-privileges. The gateway is published only to host loopback at 8876; the operator service is absent.

The probe checks authorized HTTP access, horizontal/cross-role denials, absent operator endpoints, absent database/source/credential mounts, and blocked egress. It exits nonzero on failure. `docker compose down` removes containers/network while retaining data. Do not delete the volume or secrets just to rotate credentials.

## Tests and assessment

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Tests cover role/resource isolation, spoofing, forged/expired/revoked tokens, task lifecycles, approvals, rollback, console auth/CSRF, audit redaction, scenarios, and the Ollama loop with a mocked model transport. Browser checks exercise the UI.

See [the security assessment](docs/SECURITY_ASSESSMENT.md) for measured results and validation limits. The [original roadmap](https://chatgpt.com/share/6aaf18f0-fad0-83ea-89f8-fc5d5a0ce516) maps to gateway, credentials, task-scoped agent integration, and evaluation, plus the browser console. Live-model and container runtime validation require their local services; their status is reported separately.

This is a research prototype. SQLite audit is not tamper-proof. There is no external IdP, multi-user operator RBAC, distributed key rotation, or production rate limiter on machine authentication. Use TLS, proper secret storage, and OS/network isolation beyond localhost.

References: [Ollama tool calling](https://docs.ollama.com/capabilities/tool-calling), [Docker networks](https://docs.docker.com/reference/compose-file/networks/), [Docker isolation options](https://docs.docker.com/reference/compose-file/services/).


## Independent portfolio reproduction

On September 21, 2026, the workspace copy passed 124 automated tests (2 deprecation warnings) and all 16 synthetic HTTP evaluation checks. No container-runtime or live-model claim is inferred from these results.

