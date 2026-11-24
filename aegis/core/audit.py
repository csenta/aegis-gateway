"""
Structured audit logging and Prometheus-compatible metrics for AegisGateway.
"""

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class AuditMetrics:
    total_requests: int = 0
    blocked_inbound: int = 0
    redacted_outbound: int = 0
    blocked_tool_calls: int = 0
    total_tokens_processed: int = 0
    latency_sum_ms: float = 0.0


class AuditLogger:
    def __init__(self, log_path: str = "aegis_audit.jsonl"):
        self.log_path = log_path
        self.metrics = AuditMetrics()

    def record_event(
        self,
        event_type: str,
        client_ip: str = "127.0.0.1",
        model: str = "unknown",
        violation: str | None = None,
        rule_name: str | None = None,
        latency_ms: float = 0.0,
        tokens: int = 0,
        metadata: dict[str, Any] | None = None,
    ):
        # Update metrics counters
        self.metrics.total_requests += 1
        self.metrics.latency_sum_ms += latency_ms
        self.metrics.total_tokens_processed += tokens

        if event_type == "INBOUND_BLOCKED":
            self.metrics.blocked_inbound += 1
        elif event_type == "OUTBOUND_REDACTED":
            self.metrics.redacted_outbound += 1
        elif event_type == "TOOL_BLOCKED":
            self.metrics.blocked_tool_calls += 1

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "client_ip": client_ip,
            "model": model,
            "violation": violation,
            "rule": rule_name,
            "latency_ms": round(latency_ms, 2),
            "tokens": tokens,
            "metadata": metadata or {},
        }

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def export_prometheus_metrics(self) -> str:
        avg_latency = (
            self.metrics.latency_sum_ms / self.metrics.total_requests
            if self.metrics.total_requests > 0
            else 0.0
        )
        lines = [
            "# HELP aegis_requests_total Total requests processed by AegisGateway",
            "# TYPE aegis_requests_total counter",
            f"aegis_requests_total {self.metrics.total_requests}",
            "# HELP aegis_inbound_blocked_total Total inbound requests blocked by guardrails",
            "# TYPE aegis_inbound_blocked_total counter",
            f"aegis_inbound_blocked_total {self.metrics.blocked_inbound}",
            "# HELP aegis_outbound_redacted_total Total outbound responses redacted by DLP",
            "# TYPE aegis_outbound_redacted_total counter",
            f"aegis_outbound_redacted_total {self.metrics.redacted_outbound}",
            "# HELP aegis_tool_calls_blocked_total Total agent tool calls blocked by firewall",
            "# TYPE aegis_tool_calls_blocked_total counter",
            f"aegis_tool_calls_blocked_total {self.metrics.blocked_tool_calls}",
            "# HELP aegis_latency_avg_ms Average request latency in milliseconds",
            "# TYPE aegis_latency_avg_ms gauge",
            f"aegis_latency_avg_ms {avg_latency:.2f}",
        ]
        return "\n".join(lines) + "\n"
