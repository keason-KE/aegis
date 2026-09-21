# Aegis case study

## Problem and contribution

An AI agent that can propose a tool call should not automatically receive access to every record or administrative action. Aegis explores an application boundary that checks identity, role, task, and resource permissions before returning a result.

Kobe Eason defined requirements and directed AI-assisted development. Implementation was AI-assisted. The design observations below describe the source; they are not a retrospective claim about who personally wrote a component or why a historical decision was made.

## Design and tradeoffs visible in the implementation

| Mechanism | Purpose | Tradeoff or limit |
|---|---|---|
| Separate operator console and agent gateway | Keep human approvals outside agent-accessible routes | Both still trust the local OS user |
| Role and task-scoped grants | Constrain both permitted actions and permitted records | Correct grants and task lifecycle state remain essential |
| Short-lived JWTs plus registry checks | Validate credentials and make revocation effective | Adds a database dependency to request authorization |
| Exact, single-use approvals | Bind account changes to one reviewed operation | Does not replace enterprise human identity or MFA |
| Transactional audit writes | Withhold a result or roll back a change if audit persistence fails | SQLite audit is not tamper-evident storage |
| Scripted injection scenario | Reproduce an unauthorized tool proposal deterministically | Measures enforcement, not how often a model follows malicious text |

## Evidence to inspect

- `aegis/app.py`, `identity.py`, and `policies.py`: gateway and identity decisions.
- `aegis/console.py`: operator session and review boundary.
- `tests/`: permission, token, task, approval, console, and agent-loop tests.
- `aegis/evaluation.py`: sixteen synthetic HTTP checks against the application.
- [Security assessment](SECURITY_ASSESSMENT.md): historical runtime observations and limits.
- [Live CI results](https://github.com/keason-KE/aegis/actions/workflows/tests.yml): fresh installation, tests, and HTTP evaluation.

Passing tests provide evidence for covered scenarios. They do not establish production readiness, container isolation, or universal prompt-injection resistance.
