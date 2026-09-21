# Reproduce Aegis locally

Use Python 3.12 or newer. The automated workflow tests Python 3.12 and 3.13 on Linux. Run these commands from a fresh clone; use a virtual environment to avoid unrelated installed packages.

```powershell
git clone https://github.com/keason-KE/aegis.git
cd aegis
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[test]'
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m aegis.demo
```

On macOS/Linux, replace `.\.venv\Scripts\python.exe` with `.venv/bin/python`.

The launcher starts loopback services on 8765 and 8766 and opens an authenticated console. It generates local secrets in `.aegis-demo/config.json`. Do not commit that file, its database, or an authenticated launch URL. `--no-browser` is useful for headless startup; `--port`, `--gateway-port`, and `--data-dir` allow an independent lab.

The deterministic demo requires no API key, Ollama model, or Docker service. Ollama and Docker are optional experiments, documented separately in the README; passing CI does not mean those integrations ran.

## What to demonstrate

1. Support reads its assigned ticket: allow.
2. Support requests Finance data: deny.
3. Support requests another customer's ticket: deny.
4. IT requests an account change: pending human review.
5. Approve the exact change and execute it: allow once; replay is denied.
6. Run the sixteen-check evaluation and inspect expected versus observed results.

Use only the built-in synthetic records. Screenshots should show the decision and explanation, never configuration secrets or browser session credentials.
