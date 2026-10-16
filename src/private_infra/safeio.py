"""Small fail-closed filesystem and subprocess primitives."""
from __future__ import annotations
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

class InfraError(ValueError):
    """An actionable operator/configuration error; never contains a secret."""

def no_symlinks(path: Path) -> Path:
    path = path.absolute()
    for part in (path, *path.parents):
        if part.is_symlink():
            raise InfraError(f"Symlinks are not accepted: {part}")
    return path

def private_dir(path: Path) -> Path:
    path = no_symlinks(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path

def atomic_write(path: Path, data: str | bytes, mode: int = 0o600) -> None:
    path = no_symlinks(path)
    if path.exists() and not path.is_file():
        raise InfraError(f"Not a regular file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(data.encode("utf-8") if isinstance(data, str) else data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def secret_read(path: Path) -> str:
    path = no_symlinks(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise InfraError(f"Secret must be a regular file with mode 0600 or 0400: {path}")
    data = path.read_text(encoding="utf-8").rstrip("\r\n")
    if not data or "\n" in data or "\r" in data or "\x00" in data:
        raise InfraError("Secret must contain one nonempty line")
    return data

def run(args: list[str], *, input_data: bytes | None = None,
        timeout: int = 30, quiet_errors: bool = False) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, input=input_data, capture_output=True,
                              check=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise InfraError(f"Missing executable: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise InfraError(f"Command timed out: {args[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = "" if quiet_errors else exc.stderr.decode("utf-8", "replace")[-1200:]
        raise InfraError(f"{args[0]} failed (exit {exc.returncode}). {detail}") from exc

def json_read(path: Path) -> Any:
    return json.loads(no_symlinks(path).read_text(encoding="utf-8"))
