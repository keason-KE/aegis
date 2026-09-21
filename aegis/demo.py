"""Launch the local Aegis gateway and authenticated operator dashboard."""

import argparse
import json
import secrets
import threading
import webbrowser
from pathlib import Path

import uvicorn

from aegis.app import Settings, create_app
from aegis.console import create_console


def load_demo(directory):
    directory.mkdir(parents=True, exist_ok=True)
    config_path = directory / "config.json"
    if not config_path.exists():
        config = {"credentials": {role: secrets.token_urlsafe(40) for role in ("support", "finance", "it_admin")}, "signing_key": secrets.token_urlsafe(48), "operator_key": secrets.token_urlsafe(48)}
        with config_path.open("x", encoding="utf-8") as file:
            json.dump(config, file)
        config_path.chmod(0o600)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    settings = Settings(config["credentials"], directory / "aegis.sqlite3", config["signing_key"])
    return settings, config["operator_key"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--gateway-port", type=int, default=8766)
    parser.add_argument("--data-dir", type=Path, default=Path(".aegis-demo"))
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    settings, operator_key = load_demo(args.data_dir.resolve())
    gateway = create_app(settings)
    console = create_console(settings, operator_key, f"http://127.0.0.1:{args.gateway_port}")
    gateway_server = uvicorn.Server(uvicorn.Config(gateway, host="127.0.0.1", port=args.gateway_port, log_level="warning"))
    thread = threading.Thread(target=gateway_server.run, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{args.port}/#key={operator_key}"
    print(f"Aegis console: http://127.0.0.1:{args.port}", flush=True)
    print("Local credentials are stored in .aegis-demo/config.json. Do not share that file.", flush=True)
    if not args.no_browser:
        # The fragment is exchanged for an HttpOnly session, then removed from the URL.
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    try:
        uvicorn.run(console, host="127.0.0.1", port=args.port, log_level="warning")
    finally:
        gateway_server.should_exit = True
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
