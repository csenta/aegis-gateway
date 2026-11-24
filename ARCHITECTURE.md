# AegisGateway System Architecture

## 1. Executive Summary

**AegisGateway** is an enterprise-grade, high-performance security reverse proxy and Data Loss Prevention (DLP) gateway designed for Large Language Model (LLM) applications and autonomous AI agents. 

It drops transparently between AI client applications (SDKs, IDEs, Web UIs) and LLM providers (OpenAI, Anthropic, Groq, Ollama, vLLM), providing bidirectional security enforcement:

1. **Inbound Guardrails**: Neutralizes prompt injections, roleplay jailbreaks, delimiter escapes, and system prompt extraction attacks before they reach the model.
2. **Outbound Guardrails (DLP)**: Inspects model completions for sensitive corporate credentials (AWS, GitHub, JWT, Private Keys), PII (SSN, emails, credit cards), and leaks of internal system canary tokens.
3. **Tool Execution Firewall**: Inspects agent tool calls (`tools/call`) to prevent unauthorized file access, destructive shell executions, and server-side request forgery (SSRF).

---

## 2. End-to-End System Architecture

```mermaid
flowchart TD
    Client["AI Client Application<br/>(LangChain, LlamaIndex, SDK, Browser)"] -->|"POST /v1/chat/completions"| Proxy["AegisGateway ASGI Proxy<br/>(FastAPI / Uvicorn)"]
    
    subgraph Inbound Engine
        Proxy -->|"1. Inbound Pipeline"| InboundGuard["Inbound Guardrail Engine"]
        InboundGuard --> IP1["Prompt Injection Classifier"]
        InboundGuard --> IP2["Jailbreak & Delimiter Scanner"]
        InboundGuard --> IP3["Canary Token Injector"]
    end

    InboundGuard -->|"Blocked"| RejectResponse["400/403 Security Violation Response"]
    InboundGuard -->|"Allowed"| UpstreamClient["Async HTTP Upstream Client"]

    UpstreamClient -->|"Forward Request"| LLM["Upstream LLM Provider<br/>(OpenAI, Anthropic, Groq, Ollama)"]
    LLM -->|"Raw Response Stream / JSON"| UpstreamClient

    subgraph Outbound Engine & DLP
        UpstreamClient -->|"2. Outbound Pipeline"| OutboundGuard["DLP & Content Sanitizer"]
        OutboundGuard --> OP1["Secret & Credential Scanner"]
        OutboundGuard --> OP2["PII Redaction Engine"]
        OutboundGuard --> OP3["Canary Leakage Detector"]
        OutboundGuard --> OP4["Tool Call Policy Firewall"]
    end

    OutboundGuard -->|"Sanitized / Verified"| Client
    
    subgraph Observability
        InboundGuard -.-> Audit["Structured Audit Logger<br/>(JSONL & SQLite)"]
        OutboundGuard -.-> Audit
        Audit -.-> Metrics["Prometheus Metrics (/metrics)"]
    end
```

---

## 3. Request & Response Sequence Flow

```mermaid
sequenceDiagram
    autonumber
    actor User as Client App
    participant Gateway as AegisGateway
    participant Inbound as Inbound Guard
    participant LLM as Upstream LLM
    participant Outbound as Outbound DLP
    participant Audit as Audit Logger

    User->>Gateway: POST /v1/chat/completions
    Gateway->>Inbound: Inspect messages payload
    alt Malicious Injection / Jailbreak Detected
        Inbound-->>Gateway: Verdict: BLOCKED (Rule: prompt_injection)
        Gateway->>Audit: Log Violation Event
        Gateway-->>User: 400 Bad Request (Security Policy Violation)
    else Clean Request
        Inbound-->>Gateway: Verdict: ALLOWED (Canary token inserted)
        Gateway->>LLM: Forward Request with Provider API Key
        LLM-->>Gateway: 200 OK (Model Completion)
        Gateway->>Outbound: Inspect Response Body & Tool Calls
        alt Secret / PII Detected
            Outbound-->>Gateway: Masked / Redacted Response
            Gateway->>Audit: Log DLP Redaction Event
            Gateway-->>User: 200 OK (Safe, Redacted Response)
        else Clean Response
            Outbound-->>Gateway: Verified Clean
            Gateway->>Audit: Log Request Metrics (Tokens, Latency)
            Gateway-->>User: 200 OK (Model Completion)
        end
    end
```

---

## 4. Component Architecture & Responsibilities

| Component | Module | Responsibility |
| :--- | :--- | :--- |
| **Proxy Router** | `aegis.api.router` | Exposes standard OpenAI-compatible endpoints (`/v1/chat/completions`, `/v1/models`, `/healthz`, `/metrics`). |
| **Inbound Engine** | `aegis.engine.inbound` | Analyzes prompt messages for delimiter attacks, roleplay jailbreaks, refusal suppression, and injects session canaries. |
| **Outbound Engine** | `aegis.engine.outbound` | Scans completions for API keys, private keys, PII, and applies redaction/masking policies. |
| **Tool Firewall** | `aegis.engine.tools` | Inspects agent function calls (`tool_calls`) for path traversal (`/etc/passwd`, `.env`), destructive bash commands (`rm -rf`), and network SSRF. |
| **Policy Engine** | `aegis.core.policy` | Loads, compiles, and evaluates YAML security policies with hot-reloading support. |
| **Audit & Metrics** | `aegis.core.audit` | Records structured JSONL security audit events and exports Prometheus metrics. |

---

## 5. Security & Trust Boundaries

1. **Client Boundary**: Untrusted input received over HTTP/TLS. Rate limited and strictly validated using Pydantic models.
2. **Gateway Core**: Memory-safe parsing. Zero shell execution, zero dynamic evaluation. Regex patterns are pre-compiled with timeout protections.
3. **Upstream LLM Boundary**: Gateway manages upstream provider API credentials in memory. Client never needs direct access to upstream master keys.
4. **Audit Trail**: Sensitive payloads are hashed or masked in audit logs to prevent secondary data exposure.
