"""Container entry point; signing material is never mounted in the agent."""
from pathlib import Path

import uvicorn

from aegis.app import Settings, create_app


def main():
    root = Path("/run/secrets")
    settings = Settings({role: (root / role).read_text().strip() for role in ("support", "finance", "it_admin")}, Path("/data/aegis.sqlite3"), (root / "signing").read_text().strip())
    uvicorn.run(create_app(settings), host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
