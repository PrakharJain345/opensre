"""JSONL audit logger for guardrail events."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_AUDIT_PATH = Path.home() / ".opensre" / "guardrail_audit.jsonl"


class AuditLogger:
    """Append-only JSONL audit log for guardrail matches."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _DEFAULT_AUDIT_PATH

    def log(
        self,
        *,
        rule_name: str,
        action: str,
        matched_text_preview: str,
        context: str = "",
    ) -> None:
        """Append one audit entry. Never raises on write failure."""
        preview = matched_text_preview
        if action in {"redact", "block"}:
            preview = _mask_preview(preview)

        if len(preview) > 40:
            preview = preview[:40]

        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "rule_name": rule_name,
            "action": action,
            "matched_text_preview": preview,
            "context": context,
        }
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            logger.warning("Failed to write guardrail audit log to %s", self._path)

    def read_entries(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Read the most recent audit entries."""
        if not self._path.exists():
            return []
        try:
            lines = self._path.read_text(encoding="utf-8").strip().splitlines()
        except OSError:
            return []
        entries: list[dict[str, Any]] = []
        for line in lines[-limit:]:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries


def _mask_preview(text: str) -> str:
    """Mask the middle of a string to prevent full secret leakage.

    Shows first 4 and last 4 characters if long enough, otherwise just asterisks.
    """
    if not text:
        return ""
    if len(text) <= 8:
        return "****"
    return f"{text[:4]}****{text[-4:]}"
