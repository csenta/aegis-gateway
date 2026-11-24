# AegisGateway Engineering Roadmap

## Milestones & Release Phases

### Milestone 1: Core Proxy & Bi-Directional Guardrails (v1.0 - Current)
- [x] Standard OpenAI-compatible proxy routing (`/v1/chat/completions`, `/v1/models`).
- [x] Inbound Prompt Injection & Jailbreak detection engine.
- [x] System Canary token generation and leakage detection.
- [x] Outbound Data Loss Prevention (DLP) secret and PII redaction engine.
- [x] Agent Tool Call firewall (path traversal, dangerous commands, SSRF).
- [x] Configurable YAML policy engine with enforcement/audit modes.
- [x] Structured JSONL audit logging and `/metrics` endpoint.
- [x] Full automated test suite (Unit, Integration, and Mock Upstream tests).
- [x] Containerization via Dockerfile and docker-compose.
- [x] GitHub Actions CI workflow for automated linting and testing.

### Milestone 2: Enterprise Enhancements (v1.1)
- [ ] Redis-backed token bucket distributed rate limiting.
- [ ] Streaming SSE (Server-Sent Events) token-by-token DLP scanner.
- [ ] Dynamic Vector Embedding Classifier for semantic prompt injection detection.
- [ ] Multi-tenant API key management and role-based access control (RBAC).

### Milestone 3: Web Management Console & SIEM Export (v2.0)
- [ ] React/Tailwind management dashboard for real-time threat monitoring.
- [ ] Syslog / Splunk / Datadog integration for streaming security events.
- [ ] Automatic attack replay and fine-tuning dataset generation.
