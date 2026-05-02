from __future__ import annotations

import json
from pathlib import Path

from app.guardrails.audit import AuditLogger


class TestAuditSecurity:
    def test_redacted_secrets_are_masked_in_audit_log(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=log_path)

        secret = "AKIA1234567890EXAMPLE"

        # Log a redaction event
        logger.log(rule_name="aws_key", action="redact", matched_text_preview=secret)

        # Read the entry back
        entry = json.loads(log_path.read_text(encoding="utf-8").strip())

        # This SHOULD fail currently because the logger saves the raw secret
        # We want it to be masked, e.g., "AKIA...PLE" or similar
        assert secret not in entry["matched_text_preview"], (
            f"Secret leaked in audit log: {entry['matched_text_preview']}"
        )
        assert "****" in entry["matched_text_preview"]

    def test_blocked_secrets_are_masked_in_audit_log(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=log_path)

        secret = "my-super-secret-password"

        # Log a block event
        logger.log(rule_name="password", action="block", matched_text_preview=secret)

        # Read the entry back
        entry = json.loads(log_path.read_text(encoding="utf-8").strip())

        # This SHOULD also fail currently
        assert secret not in entry["matched_text_preview"], (
            f"Secret leaked in audit log: {entry['matched_text_preview']}"
        )
        assert "****" in entry["matched_text_preview"]
