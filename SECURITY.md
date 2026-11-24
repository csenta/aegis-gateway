# Security Policy & Threat Model for AegisGateway

## 1. Threat Model & Security Posture

AegisGateway is specifically engineered as a defensive boundary protecting against the **OWASP Top 10 for Large Language Model Applications**:

| OWASP Vulnerability | Threat Vector | AegisGateway Mitigation |
| :--- | :--- | :--- |
| **LLM01: Prompt Injection** | Direct / Indirect injection manipulating model execution | Multi-layered regex heuristics, delimiter escape neutralization, and canary token validation. |
| **LLM02: Sensitive Information Disclosure** | Accidental regurgitation of training data, private keys, API secrets, or PII | Inline high-performance Outbound Data Loss Prevention (DLP) engine applying automated regex masking. |
| **LLM06: Excessive Agency / Unchecked Tools** | Autonomous agents executing dangerous bash commands or reading sensitive files | Pre-execution Tool Call Firewall enforcing path traversal blocks, shell denylists, and SSRF egress fences. |
| **LLM07: System Prompt Leakage** | Attackers prompting the model to echo confidential business logic or system prompts | Cryptographic session canary injection and outbound leakage blocking. |

---

## 2. Secure Defaults & Design Controls

1. **No Hardcoded Credentials**: All upstream API keys and policy settings are injected strictly via environment variables or validated YAML configuration files.
2. **Safe Fallbacks & Timeouts**: Upstream HTTP requests are bound to strict asynchronous timeouts (default: 60s) to prevent thread exhaustion or denial-of-service.
3. **Audit Log Privacy**: PII and sensitive credentials captured during security violations are sanitized before being committed to persistent JSONL audit files.
4. **Memory-Safe Architecture**: Written purely in modern Python with type annotations and static analysis compliance.

---

## 3. Reporting a Vulnerability

If you discover a security vulnerability in AegisGateway:
1. Please do **NOT** open a public issue.
2. Email security details directly to the repository maintainer (`csenta`).
3. Include reproduction steps and sample HTTP payload.
