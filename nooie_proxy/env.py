"""process environment: dotenv, persistent identity, credentials, logging."""

import os
import re
import shlex
import sys
import uuid
from contextlib import suppress
from pathlib import Path

APP_NAME = "nooie-proxy"


def log(message: str) -> None:
    """progress belongs on stderr; stdout may be carrying the stream."""
    print(message, file=sys.stderr, flush=True)


def state_dir() -> Path:
    """where the dotenv and the install identity live."""
    if sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(
            os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
        )
    return root / APP_NAME


def load_dotenv(path: Path) -> None:
    """read a shell-style dotenv without exposing its values on argv."""
    if not path.is_file():
        return
    for number, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip().removeprefix("export ").lstrip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not re.fullmatch(r"[A-Za-z_]\w*", key):
            raise SystemExit(f"{path}:{number}: expected KEY=VALUE")
        try:
            parts = shlex.split(value, comments=True, posix=True)
        except ValueError as error:
            raise SystemExit(f"{path}:{number}: {error}") from error
        os.environ.setdefault(key, " ".join(parts))


def load_environment() -> None:
    """a dotenv in the working directory wins over the per-user one."""
    load_dotenv(Path(".env"))
    load_dotenv(state_dir() / ".env")


def canonical_uuid(value: str) -> str:
    try:
        return str(uuid.UUID(value.strip())).upper()
    except (AttributeError, ValueError) as error:
        raise SystemExit(f"{value.strip()!r} is not a UUID") from error


def identity() -> str:
    """one stable uuid naming this install to both nooie and thing."""
    path = state_dir() / "identity"
    if not path.exists():
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with suppress(FileExistsError):
            path.touch(mode=0o600, exist_ok=False)
            path.write_text(str(uuid.uuid4()).upper() + "\n")
    return canonical_uuid(path.read_text())


def credentials() -> tuple[str, str]:
    username = os.environ.get("NOOIE_USERNAME", "")
    password = os.environ.get("NOOIE_PASSWORD", "")
    if not username or not password:
        raise SystemExit(
            "set NOOIE_USERNAME and NOOIE_PASSWORD in the environment "
            f"or in {state_dir() / '.env'}"
        )
    return username, password


def country() -> str:
    return os.environ.get("NOOIE_COUNTRY_CODE", "44")


def output() -> str:
    """the mp4 sink: - for stdout, else any url or path pyav can write."""
    target = os.environ.get("NOOIE_OUTPUT", "-")
    return "pipe:1" if target == "-" else target
