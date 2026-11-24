"""
Autonomous AI Agent Tool Call Firewall for AegisGateway.
Intercepts tool_calls (function calling) before client execution.
"""

import json
from dataclasses import dataclass
from aegis.core.config import AegisConfig


@dataclass
class ToolVerdict:
    allowed: bool
    tool_name: str
    reason: str | None = None
    rule_name: str | None = None


class ToolFirewall:
    def __init__(self, config: AegisConfig):
        self.config = config

    def inspect_tool_calls(self, tool_calls: list[dict]) -> ToolVerdict:
        if not self.config.tool_firewall.enabled or not tool_calls:
            return ToolVerdict(allowed=True, tool_name="")

        for tc in tool_calls:
            func = tc.get("function", {})
            name = func.get("name", "unknown")
            raw_args = func.get("arguments", "{}")

            args_dict = {}
            if isinstance(raw_args, str):
                try:
                    args_dict = json.loads(raw_args)
                except Exception:
                    args_dict = {"raw": raw_args}
            elif isinstance(raw_args, dict):
                args_dict = raw_args

            # Check file access
            for val in args_dict.values():
                val_str = str(val)
                for pattern in self.config.tool_firewall.file_deny:
                    if pattern.search(val_str):
                        return ToolVerdict(
                            allowed=False,
                            tool_name=name,
                            reason=f"Tool '{name}' attempted to access restricted path matching '{pattern.pattern}'.",
                            rule_name=pattern.pattern,
                        )

                # Check command execution
                for pattern in self.config.tool_firewall.cmd_deny:
                    if pattern.search(val_str):
                        return ToolVerdict(
                            allowed=False,
                            tool_name=name,
                            reason=f"Tool '{name}' attempted to execute dangerous command matching '{pattern.pattern}'.",
                            rule_name=pattern.pattern,
                        )

                # Check SSRF / Egress
                for host in self.config.tool_firewall.blocked_hosts:
                    if host in val_str:
                        return ToolVerdict(
                            allowed=False,
                            tool_name=name,
                            reason=f"Tool '{name}' attempted egress to blocked host '{host}'.",
                            rule_name=f"ssrf:{host}",
                        )

        return ToolVerdict(allowed=True, tool_name="")
