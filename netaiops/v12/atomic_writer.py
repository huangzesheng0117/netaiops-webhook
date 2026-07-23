"""Atomic, concurrent-safe JSON writer for v12 trace artifacts."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import uuid
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterator, Mapping

from .redaction import redact_for_persistence
from .schema_validator import stable_json_dumps


class AtomicWriteError(OSError):
    """Raised when a trace artifact cannot be written safely."""


class AtomicJsonWriter:
    """Write JSON files atomically under one fixed root directory."""

    def __init__(
        self,
        root: str | Path,
        *,
        directory_mode: int = 0o750,
        file_mode: int = 0o640,
        replace_func: Callable[[str | bytes | os.PathLike[str] | os.PathLike[bytes],
                                str | bytes | os.PathLike[str] | os.PathLike[bytes]], None]
        = os.replace,
        lock_root: str | Path = "/tmp/netaiops_v12_trace_locks",
    ) -> None:
        self.root = Path(root)
        self.directory_mode = int(directory_mode)
        self.file_mode = int(file_mode)
        self._replace = replace_func
        self.lock_root = Path(lock_root)

    def write_json(self, relative_path: str, payload: Any) -> Path:
        return self.write_many({relative_path: payload})[relative_path]

    def write_many(self, payloads: Mapping[str, Any]) -> dict[str, Path]:
        if not payloads:
            return {}
        targets = {
            name: self._target_path(name)
            for name in sorted(payloads)
        }
        self._prepare_root()
        with self._lock():
            output: dict[str, Path] = {}
            for name in sorted(payloads):
                output[name] = self._write_locked(
                    targets[name],
                    payloads[name],
                )
            return output

    def read_json(self, relative_path: str) -> Any:
        target = self._target_path(relative_path)
        if target.is_symlink():
            raise AtomicWriteError("refusing to read a symlink artifact")
        try:
            return json.loads(target.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AtomicWriteError(
                f"trace artifact is unreadable: {type(exc).__name__}"
            ) from exc

    def _target_path(self, relative_path: str) -> Path:
        pure = PurePosixPath(relative_path)
        if pure.is_absolute() or not pure.parts:
            raise AtomicWriteError("artifact path must be relative")
        if any(part in {"", ".", ".."} for part in pure.parts):
            raise AtomicWriteError("artifact path contains unsafe components")
        target = self.root.joinpath(*pure.parts)
        try:
            target.relative_to(self.root)
        except ValueError as exc:
            raise AtomicWriteError("artifact path escapes root") from exc
        return target

    def _prepare_root(self) -> None:
        self._ensure_safe_directory(self.root)
        self._ensure_safe_directory(self.lock_root, mode=0o700)

    def _ensure_safe_directory(
        self,
        path: Path,
        *,
        mode: int | None = None,
    ) -> None:
        mode = self.directory_mode if mode is None else mode
        existing = path
        missing: list[Path] = []
        while not existing.exists():
            missing.append(existing)
            if existing.parent == existing:
                break
            existing = existing.parent
        if existing.exists() and existing.is_symlink():
            raise AtomicWriteError(f"directory is a symlink: {existing}")
        for item in reversed(missing):
            item.mkdir(exist_ok=True)
            os.chmod(item, mode)
        current = path
        while current != current.parent:
            if current.exists() and current.is_symlink():
                raise AtomicWriteError(f"directory is a symlink: {current}")
            if current == self.root:
                break
            current = current.parent

    @contextmanager
    def _lock(self) -> Iterator[None]:
        digest = hashlib.sha256(
            str(self.root.absolute()).encode("utf-8")
        ).hexdigest()
        lock_path = self.lock_root / f"{digest}.lock"
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(lock_path, flags, 0o600)
        except OSError as exc:
            raise AtomicWriteError("could not open trace lock") from exc
        try:
            with os.fdopen(descriptor, "r+", encoding="utf-8") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                yield
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            pass

    def _write_locked(self, target: Path, payload: Any) -> Path:
        self._ensure_safe_directory(target.parent)
        if target.is_symlink():
            raise AtomicWriteError("refusing to replace a symlink artifact")

        redacted = redact_for_persistence(payload)
        encoded = (stable_json_dumps(redacted) + "\n").encode("utf-8")
        temporary = target.with_name(
            f".{target.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        descriptor: int | None = None
        try:
            descriptor = os.open(temporary, flags, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, self.file_mode)
            self._replace(temporary, target)
            os.chmod(target, self.file_mode)
            self._fsync_directory(target.parent)
            return target
        except Exception as exc:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            if isinstance(exc, AtomicWriteError):
                raise
            raise AtomicWriteError(
                f"atomic trace write failed: {type(exc).__name__}"
            ) from exc

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
