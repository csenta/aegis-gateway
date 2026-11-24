"""
FastAPI Router for AegisGateway.
Implements OpenAI-compatible endpoints, health probes, and Prometheus metrics.
"""

import time
from typing import Any
import httpx
from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse, PlainTextResponse

from aegis.core.config import AegisConfig
from aegis.core.audit import AuditLogger
from aegis.engine.inbound import InboundGuardrail
from aegis.engine.outbound import OutboundGuardrail
from aegis.engine.tools import ToolFirewall


def create_api_router(
    config: AegisConfig,
    audit_logger: AuditLogger,
    http_client: httpx.AsyncClient,
) -> APIRouter:
    router = APIRouter()
    inbound_guard = InboundGuardrail(config)
    outbound_guard = OutboundGuardrail(config)
    tool_firewall = ToolFirewall(config)

    @router.get("/healthz")
    async def health_check():
        return {
            "status": "healthy",
            "gateway": "AegisGateway",
            "version": "1.0.0",
            "mode": config.mode,
            "upstream_base_url": config.upstream_base_url,
        }

    @router.get("/metrics")
    async def metrics():
        return PlainTextResponse(audit_logger.export_prometheus_metrics())

    @router.get("/v1/models")
    async def list_models(request: Request):
        # Proxy model list to upstream or return fallback
        upstream_url = f"{config.upstream_base_url}/models"
        headers = {}
        if config.upstream_api_key:
            headers["Authorization"] = f"Bearer {config.upstream_api_key}"
        elif "Authorization" in request.headers:
            headers["Authorization"] = request.headers["Authorization"]

        try:
            resp = await http_client.get(upstream_url, headers=headers, timeout=10.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            return {
                "object": "list",
                "data": [
                    {"id": "gpt-4o", "object": "model", "owned_by": "openai"},
                    {"id": "llama-3.3-70b-versatile", "object": "model", "owned_by": "groq"},
                ],
            }

    @router.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        start_time = time.time()
        client_ip = request.client.host if request.client else "127.0.0.1"

        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": {"message": "Invalid JSON body", "type": "invalid_request_error"}},
            )

        model = body.get("model", "unknown")
        messages = body.get("messages", [])

        # 1. Inbound Guardrail Inspection
        inbound_verdict = inbound_guard.inspect_messages(messages)
        if not inbound_verdict.allowed:
            latency_ms = (time.time() - start_time) * 1000
            audit_logger.record_event(
                event_type="INBOUND_BLOCKED",
                client_ip=client_ip,
                model=model,
                violation=inbound_verdict.violation_type,
                rule_name=inbound_verdict.rule_name,
                latency_ms=latency_ms,
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": {
                        "message": f"AegisGateway Security Policy Violation: {inbound_verdict.reason}",
                        "type": "security_policy_violation",
                        "code": "inbound_guardrail_trigger",
                        "rule": inbound_verdict.rule_name,
                    }
                },
            )

        # Substitute modified messages (with canary token)
        forward_body = dict(body)
        if inbound_verdict.modified_messages:
            forward_body["messages"] = inbound_verdict.modified_messages

        # 2. Forward to Upstream LLM Provider
        upstream_url = f"{config.upstream_base_url}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if config.upstream_api_key:
            headers["Authorization"] = f"Bearer {config.upstream_api_key}"
        elif "Authorization" in request.headers:
            headers["Authorization"] = request.headers["Authorization"]

        try:
            upstream_resp = await http_client.post(
                upstream_url,
                headers=headers,
                json=forward_body,
                timeout=60.0,
            )
        except Exception as exc:
            latency_ms = (time.time() - start_time) * 1000
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content={"error": {"message": f"Upstream LLM error: {str(exc)}", "type": "bad_gateway"}},
            )

        if upstream_resp.status_code != 200:
            return JSONResponse(status_code=upstream_resp.status_code, content=upstream_resp.json())

        resp_json = upstream_resp.json()
        total_tokens = resp_json.get("usage", {}).get("total_tokens", 0)

        # 3. Outbound Tool Call Firewall & DLP Inspection
        choices = resp_json.get("choices", [])
        response_modified = False

        for choice in choices:
            msg = choice.get("message", {})

            # A. Tool Call Firewall
            tool_calls = msg.get("tool_calls", [])
            if tool_calls:
                tool_verdict = tool_firewall.inspect_tool_calls(tool_calls)
                if not tool_verdict.allowed:
                    latency_ms = (time.time() - start_time) * 1000
                    audit_logger.record_event(
                        event_type="TOOL_BLOCKED",
                        client_ip=client_ip,
                        model=model,
                        violation=f"TOOL_FIREWALL:{tool_verdict.tool_name}",
                        rule_name=tool_verdict.rule_name,
                        latency_ms=latency_ms,
                        tokens=total_tokens,
                    )
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "error": {
                                "message": f"AegisGateway Tool Firewall Violation: {tool_verdict.reason}",
                                "type": "tool_firewall_violation",
                                "code": "tool_call_blocked",
                            }
                        },
                    )

            # B. Outbound Content DLP
            content = msg.get("content")
            if isinstance(content, str) and content:
                outbound_verdict = outbound_guard.inspect_and_sanitize(
                    content,
                    session_canary=inbound_verdict.canary_token,
                )
                if not outbound_verdict.allowed:
                    latency_ms = (time.time() - start_time) * 1000
                    audit_logger.record_event(
                        event_type="OUTBOUND_BLOCKED",
                        client_ip=client_ip,
                        model=model,
                        violation=",".join(outbound_verdict.violations),
                        latency_ms=latency_ms,
                        tokens=total_tokens,
                    )
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "error": {
                                "message": f"AegisGateway DLP Violation: {outbound_verdict.reason}",
                                "type": "dlp_violation",
                                "code": "canary_or_secret_leak",
                            }
                        },
                    )

                if outbound_verdict.was_redacted:
                    msg["content"] = outbound_verdict.sanitized_text
                    response_modified = True
                    latency_ms = (time.time() - start_time) * 1000
                    audit_logger.record_event(
                        event_type="OUTBOUND_REDACTED",
                        client_ip=client_ip,
                        model=model,
                        violation=",".join(outbound_verdict.violations),
                        latency_ms=latency_ms,
                        tokens=total_tokens,
                    )

        latency_ms = (time.time() - start_time) * 1000
        if not response_modified:
            audit_logger.record_event(
                event_type="CLEAN_COMPLETION",
                client_ip=client_ip,
                model=model,
                latency_ms=latency_ms,
                tokens=total_tokens,
            )

        return JSONResponse(content=resp_json)

    return router
