"""wrappers/shell.py - Governed shell command wrapper."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from wrappers.base import BaseWrapper, WrapperResult


@dataclass
class ShellRequest:
    command: str
    working_dir: str | None = None
    env_vars: dict[str, str] = field(default_factory=dict)
    timeout: int | None = None


_WRAPPER_BLOCKLIST: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"curl\s+.+\|\s*(ba)?sh", re.IGNORECASE), "Remote script execution via curl|bash is prohibited"),
    (re.compile(r"wget\s+.+\|\s*(ba)?sh", re.IGNORECASE), "Remote script execution via wget|bash is prohibited"),
    (re.compile(r"rm\s+-[rf]{1,2}\s+/", re.IGNORECASE), "Destructive delete of root-relative path is prohibited"),
    (re.compile(r"mkfs\.", re.IGNORECASE), "Filesystem formatting command is prohibited"),
    (re.compile(r">\s*/etc/(passwd|shadow|sudoers)", re.IGNORECASE), "Write to critical system auth file is prohibited"),
    (re.compile(r":\(\)\{:\|:&\};:", re.IGNORECASE), "Fork bomb pattern detected"),
]

_UNSAFE_SHELL_META_RE = re.compile(r"(\|\||&&|[|;<>`]|\$\()")


class ShellWrapper(BaseWrapper):
    """Governed wrapper for shell command execution."""

    tool_family = "shell"

    def normalize(self, args: dict[str, Any]) -> ShellRequest:
        command = args.get("command", "")
        if not command or not isinstance(command, str):
            raise ValueError("Shell wrapper requires a non-empty 'command' string")

        working_dir = args.get("working_dir") or args.get("cwd")
        if working_dir:
            working_dir = os.path.normpath(os.path.expanduser(str(working_dir)))

        env_vars: dict[str, str] = {}
        if isinstance(args.get("env"), dict):
            env_vars = {str(k): str(v) for k, v in args["env"].items()}

        timeout = args.get("timeout")
        if timeout is not None:
            try:
                timeout = int(timeout)
            except (TypeError, ValueError):
                timeout = None

        return ShellRequest(
            command=command.strip(),
            working_dir=working_dir,
            env_vars=env_vars,
            timeout=timeout,
        )

    def execute(self, request: ShellRequest) -> WrapperResult:
        for pattern, reason in _WRAPPER_BLOCKLIST:
            if pattern.search(request.command):
                return WrapperResult(
                    executed=False,
                    mock=False,
                    output_summary=f"Wrapper blocked: {reason}",
                    blocked_reason=reason,
                )

        if not self.context.is_real_exec_enabled(self.tool_family):
            summary = f"[MOCK] Would execute: {request.command!r} in {request.working_dir or os.getcwd()}"
            return WrapperResult(
                executed=False,
                mock=True,
                output_summary=summary,
                raw_output={
                    "command": request.command,
                    "working_dir": request.working_dir,
                    "mock": True,
                    "exit_code": 0,
                    "stdout": "[mock output]",
                    "stderr": "",
                },
            )

        if _UNSAFE_SHELL_META_RE.search(request.command):
            reason = "Real shell execution only supports argv-style commands without shell metacharacters"
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary=f"Wrapper blocked: {reason}",
                blocked_reason=reason,
            )

        try:
            argv = shlex.split(request.command, posix=True)
        except ValueError as exc:
            reason = f"Shell command could not be parsed safely: {exc}"
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary=f"Wrapper blocked: {reason}",
                blocked_reason=reason,
            )

        if not argv:
            reason = "Shell command could not be reduced to an executable argv list"
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary=f"Wrapper blocked: {reason}",
                blocked_reason=reason,
            )

        cwd = Path(request.working_dir or self.context.workspace_root_resolved).expanduser().resolve(strict=False)
        allowed_roots = tuple(
            Path(root).expanduser().resolve(strict=False)
            for root in self.context.filesystem_allowed_roots_resolved
        )
        if not any(_is_within_root(cwd, root) for root in allowed_roots):
            reason = f"Shell working directory is outside allowed roots: {cwd}"
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary=f"Wrapper blocked: {reason}",
                blocked_reason=reason,
            )

        cwd.mkdir(parents=True, exist_ok=True)
        env = _build_env(request.env_vars, tuple(self.context.shell_allowed_env))
        timeout = request.timeout or self.context.shell_timeout_seconds

        try:
            completed = subprocess.run(
                argv,
                cwd=str(cwd),
                env=env,
                capture_output=True,
                text=False,
                timeout=timeout,
                shell=False,
                check=False,
            )
        except FileNotFoundError as exc:
            reason = f"Shell executable not found: {exc}"
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary=f"Wrapper blocked: {reason}",
                blocked_reason=reason,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = _decode_output(exc.stdout or b"", self.context.shell_max_output_bytes)
            stderr = _decode_output(exc.stderr or b"", self.context.shell_max_output_bytes)
            reason = f"Shell command exceeded timeout ({timeout}s)"
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary=f"Wrapper blocked: {reason}",
                raw_output={
                    "command": request.command,
                    "argv": argv,
                    "working_dir": str(cwd),
                    "stdout": stdout,
                    "stderr": stderr,
                    "timed_out": True,
                },
                blocked_reason=reason,
            )
        except OSError as exc:
            reason = f"Shell execution failed: {exc}"
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary=f"Wrapper blocked: {reason}",
                blocked_reason=reason,
            )

        stdout = _decode_output(completed.stdout, self.context.shell_max_output_bytes)
        stderr = _decode_output(completed.stderr, self.context.shell_max_output_bytes)
        summary = f"Executed {argv[0]!r} in {cwd} (exit_code={completed.returncode})"
        return WrapperResult(
            executed=True,
            mock=False,
            output_summary=summary,
            raw_output={
                "command": request.command,
                "argv": argv,
                "working_dir": str(cwd),
                "exit_code": completed.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "timed_out": False,
            },
        )


def _is_within_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _build_env(request_env: dict[str, str], allowed_env: tuple[str, ...]) -> dict[str, str]:
    names = allowed_env or ("PATH", "HOME", "TMP", "TEMP", "TMPDIR", "LANG", "LC_ALL")
    env = {name: os.environ[name] for name in names if name in os.environ}
    for key, value in request_env.items():
        if key in names:
            env[key] = value
    return env


def _decode_output(data: bytes, max_bytes: int) -> str:
    clipped = data[:max_bytes]
    text = clipped.decode("utf-8", errors="replace")
    if len(data) > max_bytes:
        text += "\n[truncated]"
    return text