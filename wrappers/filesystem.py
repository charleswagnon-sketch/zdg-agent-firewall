"""
wrappers/filesystem.py - Governed filesystem wrapper.

Reads are classified into three categories:
  allowed_read:   workspace files, non-sensitive project data
  approval_read:  large exports, bulk directory scans, cross-workspace reads
  blocked_read:   SSH keys, credential stores, browser data, system auth paths

Real execution is limited to explicitly allowed filesystem roots. Resolved-path
checks prevent symlink and traversal escapes from bypassing the wrapper.
"""

from __future__ import annotations

import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wrappers.base import BaseWrapper, WrapperResult


@dataclass
class FsRequest:
    operation: str
    path: str
    destination: str | None = None
    content: str | None = None
    size_bytes: int | None = None


_BLOCKED_READ_PATHS: list[str] = [
    os.path.expanduser("~/.ssh"),
    os.path.expanduser("~/.aws"),
    os.path.expanduser("~/.azure"),
    os.path.expanduser("~/.gnupg"),
    os.path.expanduser("~/.config/gcloud"),
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    os.path.expanduser("~/.bash_profile"),
    os.path.expanduser("~/.bashrc"),
    os.path.expanduser("~/.zshrc"),
    os.path.expanduser("~/.profile"),
    os.path.expanduser("~/.netrc"),
]

_VALID_OPERATIONS = {"read", "write", "delete", "move", "list"}


def _normalize_path(value: str) -> str:
    return os.path.normpath(os.path.expanduser(value))


def _is_blocked_path(path: str) -> bool:
    normalized = _normalize_path(path)
    for blocked in _BLOCKED_READ_PATHS:
        if normalized == blocked or normalized.startswith(blocked + os.sep):
            return True
    return False


def classify_read(path: str, size_bytes: int | None, workspace: str, approval_bytes: int) -> str:
    """Return read category: blocked_read | approval_read | allowed_read."""

    if _is_blocked_path(path):
        return "blocked_read"
    ws = _normalize_path(workspace)
    normalized = _normalize_path(path)
    if not (normalized == ws or normalized.startswith(ws + os.sep)):
        return "approval_read"
    if size_bytes and size_bytes > approval_bytes:
        return "approval_read"
    if os.path.isdir(normalized) or path.endswith("/") or path.endswith("*"):
        return "approval_read"
    return "allowed_read"


def _resolve_path(path: str) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def _path_within_roots(path: Path, roots: tuple[Path, ...]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


class FilesystemWrapper(BaseWrapper):
    """Governed wrapper for filesystem operations."""

    tool_family = "filesystem"

    def normalize(self, args: dict[str, Any]) -> FsRequest:
        operation = str(args.get("operation", "read")).lower().strip()
        if operation not in _VALID_OPERATIONS:
            raise ValueError(f"Unsupported filesystem operation '{operation}'")

        path = str(args.get("path", "")).strip()
        if not path:
            raise ValueError("Filesystem wrapper requires a non-empty 'path'")

        destination = args.get("destination") or args.get("dst") or args.get("target_path")
        if operation == "move" and not destination:
            raise ValueError("Filesystem move requires a 'destination' path")

        content = args.get("content")
        size = args.get("size_bytes")
        return FsRequest(
            operation=operation,
            path=path,
            destination=str(destination).strip() if destination is not None else None,
            content=str(content) if content is not None else None,
            size_bytes=int(size) if size is not None else None,
        )

    def execute(self, request: FsRequest) -> WrapperResult:
        if _is_blocked_path(request.path):
            reason = f"Filesystem operation on blocked sensitive path: {request.path}"
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary=f"Wrapper blocked: {reason}",
                blocked_reason=reason,
            )
        if request.destination and _is_blocked_path(request.destination):
            reason = f"Filesystem move targets blocked sensitive path: {request.destination}"
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary=f"Wrapper blocked: {reason}",
                blocked_reason=reason,
            )

        if request.operation in ("read", "list"):
            category = classify_read(
                request.path,
                request.size_bytes,
                self.context.workspace_root_resolved,
                self.context.fs_read_approval_bytes,
            )
            if category == "blocked_read":
                reason = f"Blocked read of sensitive path: {request.path}"
                return WrapperResult(
                    executed=False,
                    mock=False,
                    output_summary=f"Wrapper blocked: {reason}",
                    blocked_reason=reason,
                )
            if not self.context.is_real_exec_enabled(self.tool_family):
                summary = f"[MOCK] Would {request.operation} {request.path} (category: {category})"
                return WrapperResult(
                    executed=False,
                    mock=True,
                    output_summary=summary,
                    raw_output={
                        "operation": request.operation,
                        "path": request.path,
                        "category": category,
                        "mock": True,
                    },
                )
            return self._execute_real(request)

        if not self.context.is_real_exec_enabled(self.tool_family):
            if request.operation == "move":
                summary = f"[MOCK] Would move {request.path} to {request.destination}"
                raw_output = {
                    "operation": request.operation,
                    "path": request.path,
                    "destination": request.destination,
                    "mock": True,
                }
            else:
                summary = f"[MOCK] Would {request.operation} {request.path}"
                raw_output = {
                    "operation": request.operation,
                    "path": request.path,
                    "mock": True,
                }
            return WrapperResult(
                executed=False,
                mock=True,
                output_summary=summary,
                raw_output=raw_output,
            )

        return self._execute_real(request)

    def _execute_real(self, request: FsRequest) -> WrapperResult:
        roots = tuple(_resolve_path(root) for root in self.context.filesystem_allowed_roots_resolved)

        def blocked(reason: str) -> WrapperResult:
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary=f"Wrapper blocked: {reason}",
                blocked_reason=reason,
            )

        try:
            source_path = _resolve_path(request.path)
            if not _path_within_roots(source_path, roots):
                return blocked(
                    f"Resolved filesystem path is outside allowed roots: {source_path}"
                )

            if request.operation == "read":
                if not source_path.exists():
                    return blocked(f"Filesystem path does not exist: {source_path}")
                if source_path.is_dir():
                    return blocked("Filesystem read requires a file path; use 'list' for directories.")
                data = source_path.read_bytes()
                return WrapperResult(
                    executed=True,
                    mock=False,
                    output_summary=f"Read {len(data)} bytes from {source_path}",
                    raw_output={
                        "operation": "read",
                        "path": str(source_path),
                        "bytes_read": len(data),
                        "preview": data[:256].decode("utf-8", errors="replace"),
                    },
                )

            if request.operation == "list":
                if not source_path.exists():
                    return blocked(f"Filesystem path does not exist: {source_path}")
                if not source_path.is_dir():
                    return blocked("Filesystem list requires a directory path.")
                entries = sorted(child.name for child in source_path.iterdir())
                return WrapperResult(
                    executed=True,
                    mock=False,
                    output_summary=f"Listed {len(entries)} entries in {source_path}",
                    raw_output={
                        "operation": "list",
                        "path": str(source_path),
                        "entries": entries[:100],
                        "entry_count": len(entries),
                    },
                )

            if request.operation == "write":
                source_path.parent.mkdir(parents=True, exist_ok=True)
                if source_path.exists() and source_path.is_dir():
                    return blocked("Filesystem write target is a directory, not a file.")
                content = request.content or ""
                temp_path = source_path.parent / f".zdg-write-{uuid.uuid4().hex}.tmp"
                temp_path.write_text(content, encoding="utf-8")
                os.replace(temp_path, source_path)
                return WrapperResult(
                    executed=True,
                    mock=False,
                    output_summary=f"Wrote {len(content.encode('utf-8'))} bytes to {source_path}",
                    raw_output={
                        "operation": "write",
                        "path": str(source_path),
                        "bytes_written": len(content.encode("utf-8")),
                    },
                )

            if request.operation == "delete":
                if not source_path.exists() and not source_path.is_symlink():
                    return blocked(f"Filesystem path does not exist: {source_path}")
                if source_path.is_dir() and not source_path.is_symlink():
                    if any(source_path.iterdir()):
                        return blocked("Refusing to delete a non-empty directory via real execution.")
                    source_path.rmdir()
                else:
                    source_path.unlink()
                return WrapperResult(
                    executed=True,
                    mock=False,
                    output_summary=f"Deleted {source_path}",
                    raw_output={
                        "operation": "delete",
                        "path": str(source_path),
                    },
                )

            if request.operation == "move":
                destination = _resolve_path(request.destination or "")
                if not _path_within_roots(destination, roots):
                    return blocked(
                        f"Resolved move destination is outside allowed roots: {destination}"
                    )
                if not source_path.exists() and not source_path.is_symlink():
                    return blocked(f"Filesystem path does not exist: {source_path}")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(source_path), str(destination))
                return WrapperResult(
                    executed=True,
                    mock=False,
                    output_summary=f"Moved {source_path} to {destination}",
                    raw_output={
                        "operation": "move",
                        "path": str(source_path),
                        "destination": str(destination),
                    },
                )
        except OSError as exc:
            return blocked(f"Filesystem execution failed: {exc}")

        return blocked(f"Unsupported filesystem operation '{request.operation}'")