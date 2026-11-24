"""
Outbound Data Loss Prevention (DLP) & Sanitization Engine for AegisGateway.
Detects and redacts credentials, secrets, PII, and leaked system canaries.
"""

from dataclasses import dataclass, field
from aegis.core.config import AegisConfig


@dataclass
class OutboundVerdict:
    allowed: bool
    was_redacted: bool = False
    sanitized_text: str = ""
    violations: list[str] = field(default_factory=list)
    reason: str | None = None


class OutboundGuardrail:
    def __init__(self, config: AegisConfig):
        self.config = config

    def inspect_and_sanitize(
        self,
        text: str,
        session_canary: str | None = None,
    ) -> OutboundVerdict:
        """
        Inspects output text for canary leakage, sensitive secrets, and PII.
        Applies redactions or blocks output according to configured policy.
        """
        if not text:
            return OutboundVerdict(allowed=True, sanitized_text="")

        current_text = text
        violations: list[str] = []
        was_redacted = False

        # 1. Canary Leakage Detection
        if session_canary and session_canary in current_text:
            violations.append("SYSTEM_CANARY_LEAK")
            if self.config.canary_leakage_action == "block":
                return OutboundVerdict(
                    allowed=False,
                    was_redacted=False,
                    sanitized_text="",
                    violations=violations,
                    reason="Model response blocked: Internal system canary token was leaked.",
                )
            else:
                current_text = current_text.replace(session_canary, "[REDACTED_CANARY]")
                was_redacted = True

        # 2. Secret & Credential Scanning
        if self.config.secrets.enabled:
            for pattern in self.config.secrets.patterns:
                matches = pattern.findall(current_text)
                if matches:
                    violations.append(f"SECRET_DETECTED:{pattern.pattern}")
                    if self.config.secrets.action == "block":
                        return OutboundVerdict(
                            allowed=False,
                            was_redacted=False,
                            sanitized_text="",
                            violations=violations,
                            reason="Model response blocked: Sensitive secret/credential detected in output.",
                        )
                    else:
                        current_text = pattern.sub(self.config.secrets.mask_replacement, current_text)
                        was_redacted = True

        # 3. PII Scanning
        if self.config.pii.enabled:
            for pattern in self.config.pii.patterns:
                matches = pattern.findall(current_text)
                if matches:
                    violations.append(f"PII_DETECTED:{pattern.pattern}")
                    if self.config.pii.action == "block":
                        return OutboundVerdict(
                            allowed=False,
                            was_redacted=False,
                            sanitized_text="",
                            violations=violations,
                            reason="Model response blocked: Sensitive PII detected in output.",
                        )
                    else:
                        current_text = pattern.sub(self.config.pii.mask_replacement, current_text)
                        was_redacted = True

        return OutboundVerdict(
            allowed=True,
            was_redacted=was_redacted,
            sanitized_text=current_text,
            violations=violations,
        )
