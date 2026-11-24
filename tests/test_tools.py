"""
Unit tests for AegisGateway Tool Call Firewall.
"""

import unittest
from aegis.core.config import load_config
from aegis.engine.tools import ToolFirewall


class TestToolFirewall(unittest.TestCase):

    def setUp(self):
        self.config = load_config()
        self.firewall = ToolFirewall(self.config)

    def test_block_path_traversal(self):
        tool_calls = [
            {
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "read_file",
                    "arguments": '{"path": "/etc/shadow"}',
                },
            }
        ]
        verdict = self.firewall.inspect_tool_calls(tool_calls)
        self.assertFalse(verdict.allowed)
        self.assertIn("read_file", verdict.tool_name)
        self.assertIn("restricted path", verdict.reason)

    def test_block_dangerous_bash_command(self):
        tool_calls = [
            {
                "id": "call_2",
                "type": "function",
                "function": {
                    "name": "bash",
                    "arguments": '{"command": "rm -rf / --no-preserve-root"}',
                },
            }
        ]
        verdict = self.firewall.inspect_tool_calls(tool_calls)
        self.assertFalse(verdict.allowed)
        self.assertIn("dangerous command", verdict.reason)

    def test_block_ssrf_metadata_egress(self):
        tool_calls = [
            {
                "id": "call_3",
                "type": "function",
                "function": {
                    "name": "fetch_url",
                    "arguments": '{"url": "http://169.254.169.254/latest/meta-data/"}',
                },
            }
        ]
        verdict = self.firewall.inspect_tool_calls(tool_calls)
        self.assertFalse(verdict.allowed)
        self.assertIn("blocked host", verdict.reason)

    def test_allow_safe_tool_call(self):
        tool_calls = [
            {
                "id": "call_4",
                "type": "function",
                "function": {
                    "name": "search_code",
                    "arguments": '{"query": "def parse_header", "dir": "src/"}',
                },
            }
        ]
        verdict = self.firewall.inspect_tool_calls(tool_calls)
        self.assertTrue(verdict.allowed)


if __name__ == "__main__":
    unittest.main()
