# Aegis security assessment

Scope: a synthetic, local IAM research prototype. Implemented controls and runtime
observations are distinguished below. This is not a production certification.

## Observed results · updated 2026-09-20 (America/Chicago)

- Full automated suite: **124 passed**; two upstream test-client deprecation warnings.
- Live Ollama 0.34.2 with `qwen3:4b-instruct`: Support called `read_ticket`
  for `ticket-001`, received HTTP 200, and produced an accurate one-sentence summary.
  Audit request: `0edba451-87ed-4ae1-b451-6b9e9d8df572`.
- Browser-triggered HTTP evaluation: **16/16 passed**. Recorded observations are
  in [evaluation-results.json](evaluation-results.json).
- Browser flows checked: assigned ticket access; injected finance request denied;
  human approval followed by account disable and restore; consumed approval state;
  audit search/decision filtering; evaluation results displayed.
- Report export independently verified over HTTP: authenticated 200 response,
  attachment header, valid JSON containing all sixteen results. The in-app browser's
  automated download-event observer timed out, so download completion was not
  confirmed through that observer.
- JavaScript syntax and Python compilation passed; Docker Compose configuration
  validates. Container runtime and live-model checks remain unverified as below.

## Roadmap traceability

| Milestone | Implementation | Verification |
|---|---|---|
| 1. Authorization | Three roles, protected tools, default deny | Permission matrix tests |
| 2. Identity | Registry, scrypt, JWTs, disable/revoke/rotate | Token and lifecycle tests |
| 3. Agent integration | Bounded Ollama runner, task/resource grants, audit UI | Mocked model integration, real gateway tests, and live Ollama ticket-read smoke test |
| 4. Security evaluation | Sixteen HTTP experiments, report, Docker probe | HTTP evaluation verified; container runtime unverified |
| Browser presentation | Dashboard, playground, identities, approvals, audit, evaluation | Interactive browser checks |

## Security experiments

The in-app evaluation uses a fresh temporary database. Each result records expected
and actual HTTP status, with a gateway-generated request ID.

| Experiment | Expected |
|---|---|
| Support reads assigned ticket | 200 |
| Finance reads assigned report | 200 |
| IT reads status | 200 |
| Support modifies account | 403 |
| Support reads another customer's ticket | 403 |
| Support claims Finance via headers | 403 |
| Read assigned injected ticket | 200 |
| Attempt injected finance call | 403 |
| Expired token | 401 |
| Forged signature | 401 |
| Execute before human review | 403 |
| Exact human-approved change | 200 |
| Replay consumed approval | 403 |
| Revoked token | 401 |
| Access after task completion | 403 |
| Audit failure | 503; protected result withheld |

An unauthorized tool proposal is an attempted attack, not a successful escalation.
The injection experiment forces that proposal to test enforcement independently
of whether a model follows hostile text.

## Runtime limits recorded on this host

- Ollama 0.34.2 is installed at `127.0.0.1:11434`. The instruction-following
  `qwen3:4b-instruct` model passed a live ticket-read smoke test on CPU. The plain
  `qwen3:4b` thinking variant exhausted the response budget without a tool call.
  Mock transport tests cover the tool loop and truncated-response handling;
  no systematic model-susceptibility measurement is claimed.
- Docker Desktop's Linux engine was stopped. A startup attempt failed initializing
  its `dockerInference` Unix socket. Compose validates, but image builds and nine
  runtime isolation probes have not run. Local OS-user gateway bypass is not prevented.
- The local console and runner share the operator's OS account. File access can
  bypass application boundaries; a malicious local program is outside this demo's
  enforced trust boundary.
- Audit excludes prompts, credentials, raw queries/bodies and record contents.
  Records are transactional, not tamper-evident or remotely retained.
- Human authentication uses one local operator secret, not enterprise identity/MFA.
  The console checks session, origin, custom header and Host. Machine authentication
  has no production-grade rate limiter.

## Reproduction

Run `.\.venv\Scripts\python.exe -m pytest -q` for the complete suite.
Use **Security evaluation → Run evaluation → Download report** for sixteen HTTP
observations. Use an installed Ollama model for model behavior. Run the Docker lab
from README for container isolation.
