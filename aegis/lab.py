"""Create persistent local secrets for the optional isolated Docker lab."""
import secrets
from pathlib import Path


def main():
    directory = Path(".aegis-lab")
    directory.mkdir(exist_ok=True)
    for name in ("support", "finance", "it_admin", "signing"):
        path = directory / name
        if not path.exists():
            with path.open("x") as file:
                file.write(secrets.token_urlsafe(48))
    print("Docker lab secrets are ready. Run: docker compose up --build --abort-on-container-exit --exit-code-from agent")


if __name__ == "__main__":
    main()
