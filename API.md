# AegisGateway API Specification

AegisGateway exposes an **OpenAI-compatible HTTP REST API** allowing zero-code changes in client applications.

---

## 1. Chat Completions
`POST /v1/chat/completions`

Proxies chat completion requests to the configured upstream LLM provider while executing inbound prompt injection guardrails, agent tool firewall rules, and outbound data loss prevention (DLP).

### Request Headers
- `Content-Type: application/json`
- `Authorization: Bearer <CLIENT_TOKEN>` (Optional: if upstream API key is not configured globally)

### Request Body Example
```json
{
  "model": "gpt-4o",
  "messages": [
    {"role": "system", "content": "You are a customer support assistant."},
    {"role": "user", "content": "How do I reset my password?"}
  ],
  "temperature": 0.7
}
```

### Success Response (`200 OK`)
```json
{
  "id": "chatcmpl-aegis-8899",
  "object": "chat.completion",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "To reset your password, visit the settings page."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 15,
    "completion_tokens": 10,
    "total_tokens": 25
  }
}
```

### Security Policy Violation Response (`400 Bad Request`)
Returned when an inbound prompt injection or jailbreak is intercepted:
```json
{
  "error": {
    "message": "AegisGateway Security Policy Violation: Input violates security policy: Prompt Injection detected.",
    "type": "security_policy_violation",
    "code": "inbound_guardrail_trigger",
    "rule": "(?i)ignore\\s+(?:all\\s+)?(?:previous|prior|above)\\s+instructions"
  }
}
```

---

## 2. Health & Diagnostic Probes
`GET /healthz`

Returns gateway operational status and active upstream backend configuration.

### Response (`200 OK`)
```json
{
  "status": "healthy",
  "gateway": "AegisGateway",
  "version": "1.0.0",
  "mode": "enforce",
  "upstream_base_url": "https://api.openai.com/v1"
}
```

---

## 3. Prometheus Metrics Endpoint
`GET /metrics`

Exposes real-time Prometheus telemetry.

### Response (`200 OK`, `text/plain`)
```text
# HELP aegis_requests_total Total requests processed by AegisGateway
# TYPE aegis_requests_total counter
aegis_requests_total 142
# HELP aegis_inbound_blocked_total Total inbound requests blocked by guardrails
# TYPE aegis_inbound_blocked_total counter
aegis_inbound_blocked_total 12
# HELP aegis_outbound_redacted_total Total outbound responses redacted by DLP
# TYPE aegis_outbound_redacted_total counter
aegis_outbound_redacted_total 5
# HELP aegis_latency_avg_ms Average request latency in milliseconds
# TYPE aegis_latency_avg_ms gauge
aegis_latency_avg_ms 11.45
```
