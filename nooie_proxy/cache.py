"""the account session from the last run, so this one need not sign in.

every sign-in is a call on an account layer that counts them, and a camera
that retries is signing in over and over. nooie does not say when a token
expires, so nothing here does either: a stored session is used until it is
refused, and being refused costs one sign-in, which is what signing in
unconditionally costs anyway.

kept beside the identity, at the same permissions: it holds session secrets.
"""

import json
import os
from contextlib import suppress
from pathlib import Path
from typing import Any

from .env import state_dir


def path() -> Path:
    return state_dir() / "sessions.json"


def held() -> dict[str, Any]:
    with suppress(OSError, ValueError):
        stored = json.loads(path().read_text())
        if isinstance(stored, dict):
            return stored
    return {}


def load(name: str) -> dict[str, Any]:
    stored = held().get(name)
    return stored if isinstance(stored, dict) else {}


def save(name: str, session: dict[str, Any]) -> None:
    """replace one entry, through a temporary file, as the identity is."""
    target = path()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fresh = target.with_name(f"{target.name}.{os.getpid()}")
    fresh.touch(mode=0o600)
    fresh.write_text(json.dumps(held() | {name: session}))
    os.replace(fresh, target)


def forget(name: str) -> None:
    save(name, {})
