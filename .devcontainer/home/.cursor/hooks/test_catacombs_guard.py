#!/usr/bin/env python3
"""Unit tests for catacombs security guard."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from catacombs_guard import (  # noqa: E402
    DEFAULT_PROFILE,
    GuardResult,
    evaluate,
    evaluate_audit,
    load_profile,
    merge_category_settings,
)

CONFIG_ROOT = Path(__file__).resolve().parent.parent
ALL_PROFILES = ["low", "medium", "high", "extreme", "you-shall-not-pass"]

SCENARIOS = [
    {"id": "L1", "profile": "low", "event": {"command": "rm -rf /tmp/x", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "destructive_fs"}},
    {"id": "L2", "profile": "low", "event": {"command": "sudo apt install foo", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "privilege_escalation"}},
    {"id": "L3", "profile": "low", "event": {"command": "docker ps", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "container_escape", "notify": True}},
    {"id": "L4", "profile": "low", "event": {"command": "git push --force", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "git_destructive"}},
    {"id": "L5", "profile": "low", "event": {"file_path": "/repos/app/.env", "content": "DB_PASSWORD=x", "hook": "beforeReadFile"}, "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_file"}},
    {"id": "L6", "profile": "low", "event": {"file_path": "/repos/app/.env.example", "content": "PORT=3000", "hook": "beforeReadFile"}, "expect": {"permission": "allow"}},
    {"id": "L7", "profile": "low", "event": {"command": "cat .env", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "secret_values", "subtype": "env_file"}},
    {"id": "L8", "profile": "low", "event": {"command": "echo $DB_PASSWORD", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "secret_values", "subtype": "env_var"}},
    {"id": "L9", "profile": "low", "event": {"command": "printenv", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "secret_values", "subtype": "env_dump"}},
    {"id": "L10", "profile": "low", "event": {"command": "node -e 'console.log(process.env.API_KEY)'", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "secret_values", "subtype": "env_var"}},
    {"id": "L11", "profile": "low", "event": {"command": "echo $NODE_ENV", "hook": "beforeShellExecution"}, "expect": {"permission": "allow"}},
    {"id": "L12", "profile": "low", "event": {"command": "ps aux", "hook": "beforeShellExecution"}, "expect": {"permission": "allow"}},
    {"id": "L13", "profile": "low", "event": {"command": "curl https://example.com", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "network_egress"}},
    {"id": "L14", "profile": "low", "event": {"command": "npm install lodash", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "network_egress"}},
    {"id": "L15", "profile": "low", "event": {"tool_name": "WebFetch", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "http_tools"}},
    {"id": "L16", "profile": "low", "event": {"file_path": "/home/agent/.ssh/id_ed25519", "content": "key", "hook": "beforeReadFile"}, "expect": {"permission": "deny", "category": "ssh_dir"}},
    {"id": "L17", "profile": "low", "event": {"tool_name": "Task", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "subagent_spawn"}},
    {"id": "M1", "profile": "medium", "event": {"command": "rm -rf /tmp/x", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "destructive_fs"}},
    {"id": "M2", "profile": "medium", "event": {"command": "curl https://example.com", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "network_egress"}},
    {"id": "M3", "profile": "medium", "event": {"file_path": "/repos/app/.env", "content": "DB_PASSWORD=x", "hook": "beforeReadFile"}, "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_file"}},
    {"id": "M4", "profile": "medium", "event": {"tool_name": "Read", "file_path": "/repos/app/.env.example", "hook": "preToolUse"}, "expect": {"permission": "allow"}},
    {"id": "M5", "profile": "medium", "event": {"command": "echo $DB_PASSWORD", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "secret_values", "subtype": "env_var"}},
    {"id": "M6", "profile": "medium", "event": {"command": "printenv", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "secret_values", "subtype": "env_dump"}},
    {"id": "M7", "profile": "medium", "event": {"command": "node -e 'console.log(process.env.API_KEY)'", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "secret_values", "subtype": "env_var"}},
    {"id": "M8", "profile": "medium", "event": {"command": "echo $NODE_ENV", "hook": "beforeShellExecution"}, "expect": {"permission": "allow"}},
    {"id": "M9", "profile": "medium", "event": {"command": "git push --force", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "git_destructive"}},
    {"id": "M10", "profile": "medium", "event": {"command": "npm install lodash", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "network_egress"}},
    {"id": "M11", "profile": "medium", "event": {"tool_name": "WebFetch", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "http_tools"}},
    {"id": "M12", "profile": "medium", "event": {"file_path": "/home/agent/.ssh/id_ed25519", "content": "key", "hook": "beforeReadFile"}, "expect": {"permission": "deny", "category": "ssh_dir"}},
    {"id": "M13", "profile": "medium", "event": {"tool_name": "Task", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "subagent_spawn"}},
    {"id": "H1", "profile": "high", "event": {"command": "curl https://example.com", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "network_egress", "notify": True}},
    {"id": "H2", "profile": "high", "event": {"tool_name": "WebFetch", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "http_tools", "notify": True}},
    {"id": "H3", "profile": "high", "event": {"file_path": "/home/agent/.ssh/id_ed25519", "content": "key", "hook": "beforeReadFile"}, "expect": {"permission": "deny", "category": "ssh_dir", "notify": True}},
    {"id": "H4", "profile": "high", "event": {"tool_name": "Task", "hook": "preToolUse"}, "expect": {"permission": "allow"}},
    {"id": "E1", "profile": "extreme", "event": {"command": "curl https://example.com", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "network_egress", "notify": True}},
    {"id": "E2", "profile": "extreme", "event": {"tool_name": "Task", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "subagent_spawn"}},
    {"id": "Y1", "profile": "you-shall-not-pass", "event": {"tool_name": "Task", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "subagent_spawn", "notify": True}},
    {"id": "Y2", "profile": "you-shall-not-pass", "event": {"tool_name": "Write", "file_path": "/tmp/outside.txt", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "file_write_outside_repos", "notify": True}},
]


def assert_guard_result(test: unittest.TestCase, result: GuardResult, expect: dict) -> None:
    test.assertEqual(
        result.permission,
        expect["permission"],
        msg=f"expected {expect}, got {result.to_json()}",
    )
    if "category" in expect:
        test.assertEqual(result.category, expect["category"])
    if "subtype" in expect:
        test.assertEqual(result.subtype, expect["subtype"])
    if expect.get("notify"):
        test.assertTrue(result.notify)
        test.assertIn("user_message", result.to_json())
        test.assertNotIn("SECRET", result.to_json())
    if expect["permission"] == "deny":
        payload = result.to_json()
        test.assertIn("user_message", payload)
        test.assertIn("agent_message", payload)
        test.assertIn("Operation:", payload["user_message"])
        test.assertIn("Target:", payload["user_message"])
        test.assertIn("Intention:", payload["user_message"])


class TestProfileMatrix(unittest.TestCase):
    def test_scenarios(self):
        for row in SCENARIOS:
            with self.subTest(scenario_id=row["id"], profile=row["profile"]):
                with patch("catacombs_guard.write_audit"):
                    result = evaluate(
                        row["event"],
                        profile_id=row["profile"],
                        overrides={},
                        config_root=CONFIG_ROOT,
                    )
                assert_guard_result(self, result, row["expect"])


class TestSecretValues(unittest.TestCase):
    def test_sensitive_env_var_blocked_high_profiles(self):
        for profile in ("high", "extreme", "you-shall-not-pass"):
            with self.subTest(profile=profile):
                with patch("catacombs_guard.write_audit"):
                    result = evaluate(
                        {
                            "command": 'python3 -c \'import os; print(os.environ["DB_CONNECTION"])\'',
                            "hook": "beforeShellExecution",
                        },
                        profile_id=profile,
                        overrides={},
                        config_root=CONFIG_ROOT,
                    )
                self.assertEqual(result.permission, "deny")
                self.assertEqual(result.category, "secret_values")
                self.assertEqual(result.subtype, "env_var")
                self.assertIn("user_message", result.to_json())
                self.assertNotIn("DB_CONNECTION=", result.to_json())

    def test_env_example_allowed(self):
        result = evaluate(
            {"file_path": "/repos/app/.env.example", "content": "x", "hook": "beforeReadFile"},
            profile_id="medium",
            overrides={},
            config_root=CONFIG_ROOT,
        )
        self.assertEqual(result.permission, "allow")


class TestGuardPolicy(unittest.TestCase):
    def test_policy_paths_blocked_all_profiles(self):
        events = [
            {
                "tool_name": "Write",
                "file_path": ".cursor/hooks.json",
                "hook": "preToolUse",
            },
            {
                "tool_name": "Read",
                "file_path": ".cursor/hooks/catacombs_guard.py",
                "hook": "preToolUse",
            },
            {
                "tool_name": "Grep",
                "file_path": ".cursor/catacombs-security/categories.json",
                "hook": "preToolUse",
            },
            {
                "file_path": ".cursor/hooks.json",
                "hook": "beforeReadFile",
            },
            {
                "tool_name": "StrReplace",
                "file_path": ".cursor/catacombs-security.json",
                "hook": "preToolUse",
            },
            {
                "tool_name": "Write",
                "file_path": "/home/agent/.cursor/hooks/catacombs_guard.py",
                "hook": "preToolUse",
            },
            {
                "tool_name": "Write",
                "file_path": ".devcontainer/home/.cursor/hooks.json",
                "hook": "preToolUse",
            },
            {
                "command": "echo x > .cursor/hooks.json",
                "hook": "beforeShellExecution",
            },
            {
                "command": "cat ~/.cursor/hooks.json",
                "hook": "beforeShellExecution",
            },
        ]
        for profile in ALL_PROFILES:
            for event in events:
                with self.subTest(profile=profile, event=event):
                    with patch("catacombs_guard.write_audit"):
                        result = evaluate(
                            event,
                            profile_id=profile,
                            overrides={},
                            config_root=CONFIG_ROOT,
                        )
                    self.assertEqual(result.permission, "deny")
                    self.assertEqual(result.category, "guard_policy")
                    self.assertIn("user_message", result.to_json())

    def test_cursor_rules_editable(self):
        events = [
            {
                "tool_name": "Write",
                "file_path": ".cursor/rules/catacombs.mdc",
                "hook": "preToolUse",
            },
            {
                "tool_name": "Read",
                "file_path": ".cursor/settings.json",
                "hook": "preToolUse",
            },
        ]
        for event in events:
            with self.subTest(event=event):
                result = evaluate(
                    event,
                    profile_id="medium",
                    overrides={},
                    config_root=CONFIG_ROOT,
                )
                self.assertEqual(result.permission, "allow")

    def test_running_unit_tests_blocked(self):
        with patch("catacombs_guard.write_audit"):
            result = evaluate(
                {
                    "command": "python3 -m unittest discover -s .devcontainer/home/.cursor/hooks -p 'test_*.py' -v",
                    "hook": "beforeShellExecution",
                },
                profile_id="medium",
                overrides={},
                config_root=CONFIG_ROOT,
            )
        self.assertEqual(result.permission, "deny")
        self.assertEqual(result.category, "guard_policy")

    def test_write_under_repos_allowed(self):
        result = evaluate(
            {
                "tool_name": "Write",
                "file_path": "/repos/app/foo.py",
                "hook": "preToolUse",
            },
            profile_id="medium",
            overrides={},
            config_root=CONFIG_ROOT,
        )
        self.assertEqual(result.permission, "allow")

    def test_write_outside_repos_blocked_low_medium(self):
        for profile in ("low", "medium"):
            with self.subTest(profile=profile):
                with patch("catacombs_guard.write_audit"):
                    result = evaluate(
                        {
                            "tool_name": "Write",
                            "file_path": "/tmp/outside.txt",
                            "hook": "preToolUse",
                        },
                        profile_id=profile,
                        overrides={},
                        config_root=CONFIG_ROOT,
                    )
                self.assertEqual(result.permission, "deny")
                self.assertEqual(result.category, "file_write_outside_repos")


class TestSshDir(unittest.TestCase):
    def test_private_key_blocked_all_profiles(self):
        for profile in ALL_PROFILES:
            with self.subTest(profile=profile):
                with patch("catacombs_guard.write_audit"):
                    result = evaluate(
                        {
                            "file_path": "~/.ssh/id_ed25519",
                            "content": "key",
                            "hook": "beforeReadFile",
                        },
                        profile_id=profile,
                        overrides={},
                        config_root=CONFIG_ROOT,
                    )
                if profile in ("low", "medium"):
                    self.assertEqual(result.permission, "deny")
                else:
                    self.assertEqual(result.permission, "deny")
                self.assertEqual(result.category, "ssh_dir")

    def test_pub_read_allowed(self):
        result = evaluate(
            {
                "file_path": "/home/agent/.ssh/id_ed25519.pub",
                "content": "ssh-ed25519 AAAA",
                "hook": "beforeReadFile",
            },
            profile_id="medium",
            overrides={},
            config_root=CONFIG_ROOT,
        )
        self.assertEqual(result.permission, "allow")

    def test_pub_write_blocked(self):
        with patch("catacombs_guard.write_audit"):
            result = evaluate(
                {
                    "tool_name": "Write",
                    "file_path": "~/.ssh/id_ed25519.pub",
                    "hook": "preToolUse",
                },
                profile_id="low",
                overrides={},
                config_root=CONFIG_ROOT,
            )
        self.assertEqual(result.permission, "deny")
        self.assertEqual(result.category, "ssh_dir")

    def test_shell_cat_private_blocked(self):
        with patch("catacombs_guard.write_audit"):
            result = evaluate(
                {"command": "cat ~/.ssh/id_ed25519", "hook": "beforeShellExecution"},
                profile_id="low",
                overrides={},
                config_root=CONFIG_ROOT,
            )
        self.assertEqual(result.permission, "ask")
        self.assertEqual(result.category, "ssh_dir")

    def test_shell_cat_pub_allowed(self):
        result = evaluate(
            {"command": "cat ~/.ssh/id_ed25519.pub", "hook": "beforeShellExecution"},
            profile_id="low",
            overrides={},
            config_root=CONFIG_ROOT,
        )
        self.assertEqual(result.permission, "allow")


class TestOverrides(unittest.TestCase):
    def test_override_allows_network(self):
        with patch("catacombs_guard.write_audit"):
            result = evaluate(
                {"command": "curl https://example.com", "hook": "beforeShellExecution"},
                profile_id="high",
                overrides={"network_egress": {"enabled": True, "action": "allow"}},
                config_root=CONFIG_ROOT,
            )
        self.assertEqual(result.permission, "allow")


class TestAuditHook(unittest.TestCase):
    def test_shell_output_with_env_secret_triggers_warning(self):
        with patch("catacombs_guard.write_audit"):
            result = evaluate_audit(
                {"command": "cat .env", "output": "DB_PASSWORD=supersecret\n"},
                config_root=CONFIG_ROOT,
            )
        self.assertIsNotNone(result.additional_context)
        dumped = json.dumps(result.to_json())
        self.assertNotIn("supersecret", dumped)

    def test_clean_output_no_warning(self):
        result = evaluate_audit(
            {"command": "echo hello", "output": "hello\n"},
            config_root=CONFIG_ROOT,
        )
        self.assertIsNone(result.additional_context)


class TestConfigLoading(unittest.TestCase):
    def test_all_profiles_load(self):
        for profile in ALL_PROFILES:
            with self.subTest(profile=profile):
                data = load_profile(profile, CONFIG_ROOT)
                self.assertEqual(data["id"], profile)

    def test_missing_profile_fails_closed(self):
        with self.assertRaises(KeyError):
            load_profile("nonexistent-profile", CONFIG_ROOT)

        result = evaluate(
            {"command": "echo hi", "hook": "beforeShellExecution"},
            profile_id="nonexistent-profile",
            overrides={},
            config_root=CONFIG_ROOT,
        )
        self.assertEqual(result.permission, "deny")

    def test_merge_overrides(self):
        profile = load_profile("medium", CONFIG_ROOT)
        merged = merge_category_settings(profile, {"network_egress": {"action": "allow"}})
        self.assertEqual(merged["network_egress"]["action"], "allow")
        self.assertTrue(merged["network_egress"]["enabled"])

    def test_invalid_config_root_fails_closed(self):
        result = evaluate(
            {"command": "echo hi", "hook": "beforeShellExecution"},
            profile_id="medium",
            overrides={},
            config_root=Path("/nonexistent/path"),
        )
        self.assertEqual(result.permission, "deny")


if __name__ == "__main__":
    unittest.main()
