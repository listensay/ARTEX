"""Create stable local credentials before Compose starts the dependent services."""
import os
from pathlib import Path
import secrets
import stat


def initialize(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink():
        raise ValueError("secret directory must not be a symlink")
    root.chmod(0o700)
    login = root / "login"
    login.mkdir(exist_ok=True, mode=0o700)
    if login.is_symlink():
        raise ValueError("login directory must not be a symlink")
    login.chmod(0o700)
    for name in ("mongo-password", "redis-password", "api-key", "login/PASSWORD"):
        path = root / name
        value = ("ssk_" + secrets.token_hex(20) if name == "api-key"
                 else "" if name == "login/PASSWORD" else secrets.token_hex(32))
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("secret must be a regular file: " + name)
            if name != "login/PASSWORD" and len(path.read_text().strip()) < 32:
                raise ValueError("existing secret is empty or invalid: " + name)
            path.chmod(0o600)
        else:
            with os.fdopen(fd, "w") as handle:
                handle.write(value)
    print("[scopesentry] credentials ready; existing credentials preserved")


if __name__ == "__main__":
    initialize(Path(os.environ.get("SCOPESENTRY_SECRET_DIR", "/run/scopesentry-secrets")))
