# AegisGateway Task Execution Checklist

## Phase 1: Foundation & Policy
- [x] Define YAML policy schema in `config/default_policy.yaml`
- [x] Implement `aegis.core.config` (environment variables, YAML parsing)
- [x] Implement `aegis.core.audit` (structured security event recorder)

## Phase 2: Inbound Guardrail Engine
- [x] Implement `PromptInjectionScanner` in `aegis.engine.inbound`
- [x] Implement `JailbreakScanner` (DAN roleplay, refusal suppression, delimiter confusion)
- [x] Implement `CanaryManager` (session token generation & embedding)

## Phase 3: Outbound DLP Engine
- [x] Implement `SecretScanner` (AWS, GitHub tokens, JWT, RSA/SSH private keys)
- [x] Implement `PIIScanner` (Emails, SSNs, Credit Cards)
- [x] Implement redaction & masking transformers (`[REDACTED_SECRET]`, `[REDACTED_PII]`)

## Phase 4: Agent Tool Firewall
- [x] Implement `ToolFirewall` in `aegis.engine.tools`
- [x] Path traversal rules (`.env`, `id_rsa`, `/etc/shadow`)
- [x] Dangerous command patterns (`rm -rf`, reverse shells, fork bombs)
- [x] SSRF metadata protection (`169.254.169.254`)

## Phase 5: Proxy API & Integration
- [x] Implement FastAPI application in `aegis.api.app`
- [x] Implement `/v1/chat/completions` reverse proxy endpoint
- [x] Implement `/healthz` and `/metrics` endpoints
- [x] CLI entry point in `aegis.cli`

## Phase 6: QA, Test Automation & CI/CD
- [x] Unit tests for Inbound Engine (`tests/test_inbound.py`)
- [x] Unit tests for Outbound DLP Engine (`tests/test_outbound.py`)
- [x] Unit tests for Tool Firewall (`tests/test_tools.py`)
- [x] Integration tests with Mock Upstream API (`tests/test_proxy.py`)
- [x] Dockerfile and `docker-compose.yml`
- [x] GitHub Actions workflow (`.github/workflows/ci.yml`)
