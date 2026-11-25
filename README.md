# AegisGateway

> **Status:** prototype. A personal security-research project, not a production product. Expect rough edges; issues and pull requests are welcome.

**Prototype Autonomous Security Gateway & Data Loss Prevention (DLP) Proxy for LLM Applications and AI Agents.**

[![CI](https://github.com/csenta/aegis-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/csenta/aegis-gateway/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)

AegisGateway is a lightweight, drop-in reverse proxy that sits between your client applications and LLM backends (OpenAI, Anthropic, Groq, Ollama, vLLM). It enforces bi-directional security policies: neutralizing inbound prompt injection attacks, redacting outbound secrets and PII, and firewalling agent tool calls.

---

## Key Capabilities

* 🛡️ **Inbound Guardrails (OWASP LLM01)**: Intercepts direct prompt injections, delimiter overrides (`</system>`), roleplay jailbreaks (DAN), and system prompt extraction attempts.
* 🔒 **Outbound DLP & Secret Redaction (OWASP LLM02)**: Real-time high-speed scanning and masking of AWS access keys, GitHub PATs, JWT tokens, Stripe keys, RSA private keys, and PII (SSNs, emails, credit cards).
* 🐤 **Session Canary Protection (OWASP LLM07)**: Injects unique cryptographic session canaries into system context; instantly blocks any model completion that leaks the internal canary.
* 🧱 **Agent Tool Call Firewall (OWASP LLM06)**: Inspects pre-execution function calls (`tool_calls`) to block path traversal (`/etc/shadow`, `.env`, SSH keys), destructive shell commands (`rm -rf`, reverse shells), and cloud metadata SSRF (`169.254.169.254`).
* 🔌 **Drop-in OpenAI SDK Compatibility**: Zero client-side code refactoring. Simply set `base_url="http://localhost:8080/v1"`.
* 📊 **Observability & Metrics**: Exposes Prometheus-compatible `/metrics`, `/healthz` diagnostic probes, and structured JSONL compliance audit logging.

---

## Architecture Overview

```
Client App (LangChain, LlamaIndex, SDK)
              │
              ▼  POST /v1/chat/completions
     ┌────────────────────────────────────────────────────────┐
     │                      AegisGateway                      │
     │                                                        │
     │  [Inbound Guardrail]                                   │
     │   ├── Prompt Injection Scanner                         │
     │   ├── Roleplay / Jailbreak Filter                      │
     │   └── Canary Token Injector                            │
     │                                                        │
     │  [Upstream Async Client]  ──► Upstream LLM Provider    │
     │                           ◄── (OpenAI / Groq / Ollama) │
     │                                                        │
     │  [Outbound DLP & Tool Firewall]                        │
     │   ├── Secret & Credential Redactor                     │
     │   ├── PII Masking Engine                               │
     │   ├── Canary Leakage Detector                          │
     │   └── Tool Call Argument Firewall                      │
     │                                                        │
     │  [Audit & Observability] ──► JSONL Log & /metrics      │
     └────────────────────────────────────────────────────────┘
              │
              ▼  Sanitized Response
Client App (Safe & Compliant)
```

For comprehensive architectural design, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Quick Start

### 1. Installation
```bash
git clone https://github.com/csenta/aegis-gateway.git
cd aegis-gateway
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
# Point to your upstream LLM provider
export UPSTREAM_BASE_URL="https://api.openai.com/v1"
export UPSTREAM_API_KEY="your-upstream-api-key"

# Optional: bind host and port
export AEGIS_HOST="0.0.0.0"
export AEGIS_PORT="8080"
```

### 3. Launch the Gateway Server
```bash
python3 -m aegis.cli start --host 0.0.0.0 --port 8080
```

### 4. Connect Using Any Standard OpenAI Client
```python
from openai import OpenAI

# Direct your client through AegisGateway:
client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="aegis-proxy-token", # Or pass directly
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "user", "content": "Hello, how can I configure my firewall?"}
    ]
)
print(response.choices[0].message.content)
```

---

## Policy Configuration (`config/default_policy.yaml`)

Policies can be adjusted without code modifications:
```yaml
mode: "enforce" # options: enforce | audit

inbound:
  prompt_injection:
    enabled: true
    action: "block"
  canary:
    enabled: true
    token_prefix: "AEGIS_CANARY_"

outbound:
  secrets:
    enabled: true
    action: "mask" # Replaces secrets with [REDACTED_SECRET]
  pii:
    enabled: true
    action: "mask" # Replaces PII with [REDACTED_PII]
  canary_leakage:
    enabled: true
    action: "block" # Blocks response if canary is extracted

tool_firewall:
  enabled: true
  file_access:
    deny_patterns:
      - "(?:^|/)\\.env"
      - "^/etc/shadow"
```

---

## Docker & Container Deployment

Deploy with Docker Compose:
```bash
docker compose up -d --build
```
Verify the healthcheck:
```bash
curl http://localhost:8080/healthz
```

---

## Automated Testing

AegisGateway includes a test suite covering inbound injection detection, outbound DLP masking, tool call firewalling, and mock upstream proxying:
```bash
python3 -m unittest discover -s tests -v
```

---

## Documentation Index

- [ARCHITECTURE.md](ARCHITECTURE.md) — Detailed system design, component responsibilities, and sequence diagrams.
- [ROADMAP.md](ROADMAP.md) — Engineering roadmap, upcoming features, and milestones.
- [TASKS.md](TASKS.md) — Implementation task checklist and verification criteria.
- [API.md](API.md) — Full API reference for endpoints and error payloads.
- [SECURITY.md](SECURITY.md) — Threat model, OWASP LLM coverage, and vulnerability reporting.
- [CONTRIBUTING.md](CONTRIBUTING.md) — Developer setup and contribution guidelines.

## License

MIT. See [LICENSE](LICENSE).
