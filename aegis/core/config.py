"""
Configuration and Policy Management for AegisGateway.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Any
import yaml


@dataclass
class PolicyRule:
    enabled: bool = True
    action: str = "block"  # block, mask, log
    patterns: list[re.Pattern] = field(default_factory=list)
    mask_replacement: str = "[REDACTED]"


@dataclass
class ToolFirewallPolicy:
    enabled: bool = True
    file_deny: list[re.Pattern] = field(default_factory=list)
    cmd_deny: list[re.Pattern] = field(default_factory=list)
    blocked_hosts: list[str] = field(default_factory=list)


@dataclass
class AegisConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    upstream_base_url: str = "https://api.openai.com/v1"
    upstream_api_key: str = ""
    audit_log_path: str = "aegis_audit.jsonl"
    policy_path: str = ""
    mode: str = "enforce"  # enforce | audit

    # Inbound
    prompt_injection: PolicyRule = field(default_factory=PolicyRule)
    jailbreak: PolicyRule = field(default_factory=PolicyRule)
    canary_enabled: bool = True
    canary_prefix: str = "AEGIS_CANARY_"

    # Outbound DLP
    secrets: PolicyRule = field(default_factory=PolicyRule)
    pii: PolicyRule = field(default_factory=PolicyRule)
    canary_leakage_action: str = "block"

    # Tool Firewall
    tool_firewall: ToolFirewallPolicy = field(default_factory=ToolFirewallPolicy)


def _compile_patterns(raw_patterns: list[str]) -> list[re.Pattern]:
    compiled = []
    for p in raw_patterns:
        try:
            compiled.append(re.compile(p))
        except re.error:
            continue
    return compiled


def load_config(policy_file_path: str | None = None) -> AegisConfig:
    """Loads configuration from environment variables and YAML policy."""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    default_policy = os.path.join(base_dir, "config", "default_policy.yaml")

    actual_policy_path = policy_file_path or os.environ.get("AEGIS_POLICY_PATH", default_policy)

    raw_policy: dict[str, Any] = {}
    if os.path.isfile(actual_policy_path):
        with open(actual_policy_path, "r", encoding="utf-8") as f:
            raw_policy = yaml.safe_load(f) or {}

    config = AegisConfig(
        host=os.environ.get("AEGIS_HOST", "0.0.0.0"),
        port=int(os.environ.get("AEGIS_PORT", "8080")),
        upstream_base_url=os.environ.get("UPSTREAM_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
        upstream_api_key=os.environ.get("UPSTREAM_API_KEY", os.environ.get("OPENAI_API_KEY", "")),
        audit_log_path=os.environ.get("AEGIS_AUDIT_LOG", "aegis_audit.jsonl"),
        policy_path=actual_policy_path,
        mode=raw_policy.get("mode", "enforce"),
    )

    # Parse Inbound
    inbound = raw_policy.get("inbound", {})
    pi_conf = inbound.get("prompt_injection", {})
    config.prompt_injection = PolicyRule(
        enabled=pi_conf.get("enabled", True),
        action=pi_conf.get("action", "block"),
        patterns=_compile_patterns(pi_conf.get("patterns", [])),
    )

    jb_conf = inbound.get("jailbreak", {})
    config.jailbreak = PolicyRule(
        enabled=jb_conf.get("enabled", True),
        action=jb_conf.get("action", "block"),
        patterns=_compile_patterns(jb_conf.get("patterns", [])),
    )

    canary_conf = inbound.get("canary", {})
    config.canary_enabled = canary_conf.get("enabled", True)
    config.canary_prefix = canary_conf.get("token_prefix", "AEGIS_CANARY_")

    # Parse Outbound DLP
    outbound = raw_policy.get("outbound", {})
    sec_conf = outbound.get("secrets", {})
    config.secrets = PolicyRule(
        enabled=sec_conf.get("enabled", True),
        action=sec_conf.get("action", "mask"),
        patterns=_compile_patterns(sec_conf.get("patterns", [])),
        mask_replacement=sec_conf.get("mask_replacement", "[REDACTED_SECRET]"),
    )

    pii_conf = outbound.get("pii", {})
    config.pii = PolicyRule(
        enabled=pii_conf.get("enabled", True),
        action=pii_conf.get("action", "mask"),
        patterns=_compile_patterns(pii_conf.get("patterns", [])),
        mask_replacement=pii_conf.get("mask_replacement", "[REDACTED_PII]"),
    )

    canary_leak = outbound.get("canary_leakage", {})
    config.canary_leakage_action = canary_leak.get("action", "block")

    # Parse Tool Firewall
    tf_conf = raw_policy.get("tool_firewall", {})
    config.tool_firewall = ToolFirewallPolicy(
        enabled=tf_conf.get("enabled", True),
        file_deny=_compile_patterns(tf_conf.get("file_access", {}).get("deny_patterns", [])),
        cmd_deny=_compile_patterns(tf_conf.get("command_execution", {}).get("deny_patterns", [])),
        blocked_hosts=tf_conf.get("network_egress", {}).get("blocked_hosts", []),
    )

    return config
