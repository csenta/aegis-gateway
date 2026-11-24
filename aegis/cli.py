#!/usr/bin/env python3
"""
CLI entry point for AegisGateway.
"""

import argparse
import sys
import uvicorn
from aegis.core.config import load_config
from aegis.engine.outbound import OutboundGuardrail
from aegis.engine.inbound import InboundGuardrail


def main():
    parser = argparse.ArgumentParser(
        description="AegisGateway: Enterprise LLM Security Gateway & DLP Proxy"
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Subcommand: start
    start_parser = subparsers.add_parser("start", help="Start the AegisGateway proxy server")
    start_parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    start_parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    start_parser.add_argument("--policy", help="Path to custom policy YAML")
    start_parser.add_argument("--upstream", help="Upstream LLM base URL (default: https://api.openai.com/v1)")
    start_parser.add_argument("--workers", type=int, default=1, help="Uvicorn worker count")

    # Subcommand: test-dlp
    dlp_parser = subparsers.add_parser("test-dlp", help="Test outbound DLP redaction on sample text")
    dlp_parser.add_argument("text", help="Sample completion text to test")
    dlp_parser.add_argument("--policy", help="Path to custom policy YAML")

    # Subcommand: test-inbound
    in_parser = subparsers.add_parser("test-inbound", help="Test inbound prompt injection guardrail on sample prompt")
    in_parser.add_argument("prompt", help="Prompt text to test")
    in_parser.add_argument("--policy", help="Path to custom policy YAML")

    args = parser.parse_args()

    if args.subcommand == "start":
        config = load_config(args.policy)
        if args.upstream:
            config.upstream_base_url = args.upstream.rstrip("/")
        config.host = args.host
        config.port = args.port

        from aegis.api.app import create_app
        app = create_app(config)

        print(f"[*] Starting AegisGateway on http://{config.host}:{config.port} ...")
        print(f"[*] Upstream Provider: {config.upstream_base_url}")
        print(f"[*] Enforcement Mode:  {config.mode}")
        print(f"[*] Policy Source:     {config.policy_path}")

        uvicorn.run(app, host=config.host, port=config.port, workers=args.workers)

    elif args.subcommand == "test-dlp":
        config = load_config(args.policy)
        guard = OutboundGuardrail(config)
        verdict = guard.inspect_and_sanitize(args.text)

        print(f"[*] Input Text:      {args.text}")
        print(f"[*] Allowed:         {verdict.allowed}")
        print(f"[*] Was Redacted:    {verdict.was_redacted}")
        print(f"[*] Violations:      {verdict.violations}")
        print(f"[*] Sanitized Text:  {verdict.sanitized_text}")

    elif args.subcommand == "test-inbound":
        config = load_config(args.policy)
        guard = InboundGuardrail(config)
        verdict = guard.inspect_messages([{"role": "user", "content": args.prompt}])

        print(f"[*] Input Prompt:    {args.prompt}")
        print(f"[*] Allowed:         {verdict.allowed}")
        print(f"[*] Violation Type:  {verdict.violation_type}")
        print(f"[*] Rule Triggered:  {verdict.rule_name}")
        print(f"[*] Reason:          {verdict.reason}")


if __name__ == "__main__":
    main()
