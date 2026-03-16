"""
wrappers/messaging.py - Governed outbound messaging wrapper.

Captures email/messaging requests. When real execution is enabled, messages are
written to a local maildir so operators can inspect the exact payload without
sending it to a real SMTP service.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from wrappers.base import BaseWrapper, WrapperResult


@dataclass
class MessagingRequest:
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    subject: str | None = None
    body: str | None = None
    has_attachment: bool = False
    bulk_threshold: int = 5


class MessagingWrapper(BaseWrapper):
    """Governed wrapper for outbound email / messaging."""

    tool_family = "messaging"

    def normalize(self, args: dict[str, Any]) -> MessagingRequest:
        to = [str(r).strip().lower() for r in (args.get("to") or [])]
        cc = [str(r).strip().lower() for r in (args.get("cc") or [])]
        return MessagingRequest(
            to=to,
            cc=cc,
            subject=args.get("subject"),
            body=args.get("body"),
            has_attachment=bool(args.get("has_attachment", False)),
            bulk_threshold=self.context.bulk_send_threshold,
        )

    def execute(self, request: MessagingRequest) -> WrapperResult:
        total = len(request.to) + len(request.cc)

        real_exec_enabled = self.context.is_real_exec_enabled(self.tool_family)
        if total > request.bulk_threshold and real_exec_enabled:
            reason = (
                f"Bulk send blocked: {total} recipients exceeds threshold "
                f"({request.bulk_threshold})"
            )
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary=f"Wrapper blocked: {reason}",
                blocked_reason=reason,
            )

        if not real_exec_enabled:
            summary = f"[MOCK] Would send to {total} recipients (subject: {request.subject!r})"
            return WrapperResult(
                executed=False,
                mock=True,
                output_summary=summary,
                raw_output={
                    "to": request.to,
                    "cc": request.cc,
                    "subject": request.subject,
                    "mock_sent": True,
                },
            )

        maildir_root = Path(self.context.maildir_path_resolved)
        tmp_dir = maildir_root / "tmp"
        new_dir = maildir_root / "new"
        cur_dir = maildir_root / "cur"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        new_dir.mkdir(parents=True, exist_ok=True)
        cur_dir.mkdir(parents=True, exist_ok=True)

        message = EmailMessage()
        if request.to:
            message["To"] = ", ".join(request.to)
        if request.cc:
            message["Cc"] = ", ".join(request.cc)
        if request.subject:
            message["Subject"] = str(request.subject)
        message["X-ZDG-Trace-Id"] = self.context.trace_id or ""
        message["X-ZDG-Agent-Id"] = self.context.agent_id or ""
        message["X-ZDG-Tool-Family"] = self.tool_family
        message.set_content(request.body or "")

        filename = f"{int(time.time() * 1000000)}.{uuid.uuid4().hex}.eml"
        tmp_path = tmp_dir / filename
        final_path = new_dir / filename
        tmp_path.write_text(message.as_string(), encoding="utf-8")
        tmp_path.replace(final_path)

        summary = f"Wrote message for {total} recipients to maildir {final_path}"
        return WrapperResult(
            executed=True,
            mock=False,
            output_summary=summary,
            raw_output={
                "maildir_path": str(final_path),
                "recipient_count": total,
                "subject": request.subject,
            },
        )