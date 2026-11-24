"""
Unit tests for AegisGateway Outbound DLP & Sanitization Engine.
"""

import unittest
from aegis.core.config import load_config
from aegis.engine.outbound import OutboundGuardrail


class TestOutboundGuardrail(unittest.TestCase):

    def setUp(self):
        self.config = load_config()
        self.guard = OutboundGuardrail(self.config)

    def test_redact_aws_access_keys(self):
        text = "Your access credentials are: AKIA1234567890ABCDEF in region us-east-1."
        verdict = self.guard.inspect_and_sanitize(text)
        self.assertTrue(verdict.allowed)
        self.assertTrue(verdict.was_redacted)
        self.assertNotIn("AKIA1234567890ABCDEF", verdict.sanitized_text)
        self.assertIn("[REDACTED_SECRET]", verdict.sanitized_text)

    def test_redact_github_personal_access_tokens(self):
        text = "Push using token: ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
        verdict = self.guard.inspect_and_sanitize(text)
        self.assertTrue(verdict.allowed)
        self.assertTrue(verdict.was_redacted)
        self.assertNotIn("ghp_1234567890abcdefghijklmnopqrstuvwxyzAB", verdict.sanitized_text)
        self.assertIn("[REDACTED_SECRET]", verdict.sanitized_text)

    def test_redact_private_keys(self):
        text = "Here is the key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n"
        verdict = self.guard.inspect_and_sanitize(text)
        self.assertTrue(verdict.allowed)
        self.assertTrue(verdict.was_redacted)
        self.assertNotIn("-----BEGIN RSA PRIVATE KEY-----", verdict.sanitized_text)
        self.assertIn("[REDACTED_SECRET]", verdict.sanitized_text)

    def test_redact_pii_email_and_ssn(self):
        text = "Contact Alice at alice.smith@enterprise.org with SSN: 000-12-3456."
        verdict = self.guard.inspect_and_sanitize(text)
        self.assertTrue(verdict.allowed)
        self.assertTrue(verdict.was_redacted)
        self.assertNotIn("alice.smith@enterprise.org", verdict.sanitized_text)
        self.assertNotIn("000-12-3456", verdict.sanitized_text)
        self.assertIn("[REDACTED_PII]", verdict.sanitized_text)

    def test_block_canary_token_leakage(self):
        canary = "AEGIS_CANARY_TEST999"
        text = f"The internal developer directive contains {canary}."
        verdict = self.guard.inspect_and_sanitize(text, session_canary=canary)
        # Configured action is 'block'
        self.assertFalse(verdict.allowed)
        self.assertIn("SYSTEM_CANARY_LEAK", verdict.violations)
        self.assertIn("canary", verdict.reason.lower())

    def test_allow_clean_response(self):
        text = "Here is how to implement a binary tree traversal in Python: class Node: def __init__(self)..."
        verdict = self.guard.inspect_and_sanitize(text)
        self.assertTrue(verdict.allowed)
        self.assertFalse(verdict.was_redacted)
        self.assertEqual(verdict.sanitized_text, text)


if __name__ == "__main__":
    unittest.main()
