#!/usr/bin/env python3
"""Unit tests for catacombs security guard."""

from __future__ import annotations

import json
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from catacombs_guard import (  # noqa: E402
    DEFAULT_PROFILE,
    GuardResult,
    dispatch_pretooluse,
    evaluate,
    evaluate_audit,
    guard_main,
    load_profile,
    merge_category_settings,
    normalize_hook_name,
)

CONFIG_ROOT = Path(__file__).resolve().parent.parent
ALL_PROFILES = ["low", "medium", "high", "extreme", "you-shall-not-pass"]

SCENARIOS = [
    {"id": "L1", "profile": "low", "event": {"command": "rm -rf /tmp/x", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "file_write_outside_repos", "notify": True}},
    {"id": "L2", "profile": "low", "event": {"command": "sudo apt install foo", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "privilege_escalation"}},
    {"id": "L3", "profile": "low", "event": {"command": "docker ps", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "container_escape", "notify": True}},
    {"id": "L4", "profile": "low", "event": {"command": "git push --force", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "git_destructive"}},
    {"id": "L5", "profile": "low", "event": {"file_path": "/repos/app/.env", "content": "DB_PASSWORD=x", "hook": "beforeReadFile"}, "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_file"}},
    {"id": "L6", "profile": "low", "event": {"file_path": "/repos/app/.env.example", "content": "PORT=3000", "hook": "beforeReadFile"}, "expect": {"permission": "allow"}},
    {"id": "L7", "profile": "low", "event": {"command": "cat .env", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_file", "notify": True}},
    {"id": "L8", "profile": "low", "event": {"command": "echo $DB_PASSWORD", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_var", "notify": True}},
    {"id": "L9", "profile": "low", "event": {"command": "printenv", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_dump", "notify": True}},
    {"id": "L10", "profile": "low", "event": {"command": "node -e 'console.log(process.env.API_KEY)'", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_var", "notify": True}},
    {"id": "L11", "profile": "low", "event": {"command": "echo $NODE_ENV", "hook": "beforeShellExecution"}, "expect": {"permission": "allow"}},
    {"id": "L12", "profile": "low", "event": {"command": "ps aux", "hook": "beforeShellExecution"}, "expect": {"permission": "allow"}},
    {"id": "L13", "profile": "low", "event": {"command": "curl https://example.com", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "network_egress"}},
    {"id": "L14", "profile": "low", "event": {"command": "npm install lodash", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "network_egress"}},
    {"id": "L15", "profile": "low", "event": {"tool_name": "WebFetch", "hook": "preToolUse"}, "expect": {"permission": "allow"}},
    {"id": "L16", "profile": "low", "event": {"file_path": "/home/agent/.ssh/id_ed25519", "content": "key", "hook": "beforeReadFile"}, "expect": {"permission": "deny", "category": "ssh_dir"}},
    {"id": "L17", "profile": "low", "event": {"tool_name": "Task", "hook": "preToolUse"}, "expect": {"permission": "allow"}},
    {"id": "M1", "profile": "medium", "event": {"command": "rm -rf /tmp/x", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "file_write_outside_repos", "notify": True}},
    {"id": "M2", "profile": "medium", "event": {"command": "curl https://example.com", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "network_egress"}},
    {"id": "M3", "profile": "medium", "event": {"file_path": "/repos/app/.env", "content": "DB_PASSWORD=x", "hook": "beforeReadFile"}, "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_file"}},
    {"id": "M4", "profile": "medium", "event": {"tool_name": "Read", "file_path": "/repos/app/.env.example", "hook": "preToolUse"}, "expect": {"permission": "allow"}},
    {"id": "M5", "profile": "medium", "event": {"command": "echo $DB_PASSWORD", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_var", "notify": True}},
    {"id": "M6", "profile": "medium", "event": {"command": "printenv", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_dump", "notify": True}},
    {"id": "M7", "profile": "medium", "event": {"command": "node -e 'console.log(process.env.API_KEY)'", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_var", "notify": True}},
    {"id": "M8", "profile": "medium", "event": {"command": "echo $NODE_ENV", "hook": "beforeShellExecution"}, "expect": {"permission": "allow"}},
    {"id": "M9", "profile": "medium", "event": {"command": "git push --force", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "git_destructive"}},
    {"id": "M10", "profile": "medium", "event": {"command": "npm install lodash", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "network_egress"}},
    {"id": "M11", "profile": "medium", "event": {"tool_name": "WebFetch", "hook": "preToolUse"}, "expect": {"permission": "allow"}},
    {"id": "M12", "profile": "medium", "event": {"file_path": "/home/agent/.ssh/id_ed25519", "content": "key", "hook": "beforeReadFile"}, "expect": {"permission": "deny", "category": "ssh_dir"}},
    {"id": "M13", "profile": "medium", "event": {"tool_name": "Task", "hook": "preToolUse"}, "expect": {"permission": "allow"}},
    {"id": "H1", "profile": "high", "event": {"command": "curl https://example.com", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "network_egress", "notify": True}},
    {"id": "H2", "profile": "high", "event": {"tool_name": "WebFetch", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "http_tools", "notify": True}},
    {"id": "H3", "profile": "high", "event": {"file_path": "/home/agent/.ssh/id_ed25519", "content": "key", "hook": "beforeReadFile"}, "expect": {"permission": "deny", "category": "ssh_dir", "notify": True}},
    {"id": "H4", "profile": "high", "event": {"tool_name": "Task", "hook": "preToolUse"}, "expect": {"permission": "allow"}},
    {"id": "E1", "profile": "extreme", "event": {"command": "curl https://example.com", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "network_egress", "notify": True}},
    {"id": "E2", "profile": "extreme", "event": {"tool_name": "Task", "hook": "preToolUse"}, "expect": {"permission": "allow"}},
    {"id": "Y1", "profile": "you-shall-not-pass", "event": {"tool_name": "Task", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "subagent_spawn", "notify": True}},
    {"id": "Y2", "profile": "you-shall-not-pass", "event": {"tool_name": "Write", "file_path": "/tmp/outside.txt", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "file_write_outside_repos", "notify": True}},
    {"id": "Y3", "profile": "you-shall-not-pass", "event": {"tool_name": "Write", "file_path": ".cursor/rules/catacombs.mdc", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "agent_config", "notify": True}},
    {"id": "Y4", "profile": "you-shall-not-pass", "event": {"tool_name": "Write", "file_path": ".agents/skills/foo/SKILL.md", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "agent_config", "notify": True}},
    {"id": "Y5", "profile": "you-shall-not-pass", "event": {"tool_name": "Write", "file_path": ".cursor/mcp.json", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "agent_config", "notify": True}},
    {"id": "Y6", "profile": "you-shall-not-pass", "event": {"tool_name": "Read", "file_path": "/home/agent/.cursor/settings.json", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "file_read_outside_repos", "notify": True}},
    {"id": "Y7", "profile": "you-shall-not-pass", "event": {"file_path": "/home/agent/.cursor/settings.json", "hook": "beforeReadFile"}, "expect": {"permission": "deny", "category": "file_read_outside_repos", "notify": True}},
    {"id": "Y8", "profile": "you-shall-not-pass", "event": {"command": "psql -h host.docker.internal -U postgres", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "network_egress", "notify": True}},
    {"id": "Y9", "profile": "you-shall-not-pass", "event": {"command": "mysql -h host.docker.internal -u root", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "network_egress", "notify": True}},
    {"id": "Y10", "profile": "you-shall-not-pass", "event": {"command": "git push origin main", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "network_egress", "notify": True}},
    {"id": "Y11", "profile": "you-shall-not-pass", "event": {"command": "ln -s ../../.ssh evil", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "symlink_escape", "notify": True}},
    {"id": "H5", "profile": "high", "event": {"tool_name": "Write", "file_path": "/tmp/outside.txt", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "file_write_outside_repos", "notify": True}},
    {"id": "M14", "profile": "medium", "event": {"tool_name": "Write", "file_path": ".cursor/rules/catacombs.mdc", "hook": "preToolUse"}, "expect": {"permission": "deny", "category": "agent_config"}},
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


class TestAuditProbeGuardMain(unittest.TestCase):
    """Replay audit probes 8.x and 15.x through guard_main (live stdin JSON shape)."""

    def _run_guard(self, payload: dict) -> dict:
        with patch("sys.stdin", io.StringIO(json.dumps(payload))):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                with patch("catacombs_guard.write_audit"):
                    code = guard_main()
        self.assertEqual(code, 0)
        return json.loads(out.getvalue())

    def test_write_outside_tmp_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Write",
                "tool_input": {"path": "/tmp/audit-probe-write.txt"},
            }
        )
        self.assertEqual(result["permission"], "deny")
        self.assertIn("user_message", result)
        self.assertIn("agent_message", result)

    def test_write_outside_home_agent_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Write",
                "tool_input": {"path": "/home/agent/audit-probe-write.txt"},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_write_outside_etc_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Write",
                "tool_input": {"path": "/etc/audit-probe-write.txt"},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_shell_redirect_outside_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "echo audit > /tmp/audit-probe-redirect.txt"},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_shell_rm_outside_denied(self):
        for command in ("rm /tmp/audit-probe-missing", "rm /tmp/audit-probe-existing"):
            with self.subTest(command=command):
                result = self._run_guard(
                    {
                        "hook_event_name": "preToolUse",
                        "tool_name": "Shell",
                        "tool_input": {"command": command},
                    }
                )
                self.assertEqual(result["permission"], "deny")

    def test_shell_rm_rf_outside_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "rm -rf /tmp/x"},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_shell_rm_inside_repos_asks(self):
        result = self._run_guard(
            {
                "hook_event_name": "beforeShellExecution",
                "command": "rm /repos/app/foo",
            }
        )
        self.assertEqual(result["permission"], "ask")

    def test_delete_outside_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Delete",
                "tool_input": {"path": "/tmp/audit-probe-delete.txt"},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_delete_inside_repos_destructive_fs(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Delete",
                "tool_input": {"path": "/repos/app/foo"},
            }
        )
        # preToolUse cannot surface ask; policy is destructive_fs (ask → deny)
        self.assertEqual(result["permission"], "deny")
        self.assertIn("user_message", result)

    def test_cat_proc_self_environ_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "cat /proc/self/environ"},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_bare_set_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "set"},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_set_shell_options_allowed(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "set -euo pipefail"},
            }
        )
        self.assertEqual(result["permission"], "allow")

    def test_node_process_env_keys_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {
                    "command": 'node -e "console.log(Object.keys(process.env))"'
                },
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_echo_home_allowed(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "echo $HOME"},
            }
        )
        self.assertEqual(result["permission"], "allow")

    def test_python_write_outside_tmp_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {
                    "command": """python3 -c "open('/tmp/x','w').write('a')" """
                },
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_node_write_outside_tmp_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {
                    "command": """node -e "require('fs').writeFileSync('/tmp/x','a')" """
                },
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_php_write_outside_tmp_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {
                    "command": """php -r "file_put_contents('/tmp/x','a');" """
                },
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_python_os_remove_outside_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {
                    "command": """python3 -c "import os; os.remove('/tmp/x')" """
                },
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_python_read_outside_tmp_allowed(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {
                    "command": """python3 -c "print(open('/tmp/x').read())" """
                },
            }
        )
        self.assertEqual(result["permission"], "allow")

    def test_read_git_credentials_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Read",
                "tool_input": {"path": "/home/agent/.git-credentials"},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_read_home_npmrc_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Read",
                "tool_input": {"path": "/home/agent/.npmrc"},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_read_repos_npmrc_allowed(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Read",
                "tool_input": {"path": "/repos/app/.npmrc"},
            }
        )
        self.assertEqual(result["permission"], "allow")

    def test_delete_inside_repos_evaluate_destructive_fs(self):
        with patch("catacombs_guard.write_audit"):
            result = evaluate(
                {
                    "hook": "preToolUse",
                    "tool_name": "Delete",
                    "file_path": "/repos/app/foo",
                },
                profile_id="medium",
                overrides={},
                config_root=CONFIG_ROOT,
            )
        self.assertEqual(result.category, "destructive_fs")
        self.assertEqual(result.subtype, "delete")

    def test_write_inside_repos_allowed(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Write",
                "tool_input": {"path": "/repos/app/foo.py"},
            }
        )
        self.assertEqual(result["permission"], "allow")

    def test_tool_input_json_string_and_target_file(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Write",
                "tool_input": json.dumps({"target_file": "/tmp/audit-probe-target-file.txt"}),
            }
        )
        self.assertEqual(result["permission"], "deny")


class TestAudit3GuardMain(unittest.TestCase):
    """Replay audit 3 probes through guard_main (obfuscation + Read path shapes)."""

    def _run_guard(self, payload: dict) -> dict:
        with patch("sys.stdin", io.StringIO(json.dumps(payload))):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                with patch("catacombs_guard.write_audit"):
                    code = guard_main()
        self.assertEqual(code, 0)
        return json.loads(out.getvalue())

    def test_read_env_tool_input_path_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Read",
                "tool_input": {"path": "/repos/app/.env"},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_read_env_top_level_file_path_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Read",
                "file_path": "/repos/app/.env",
                "tool_input": {},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_read_env_file_uri_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "beforeReadFile",
                "file_path": "file:///repos/app/.env",
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_read_relative_env_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Read",
                "tool_input": {"path": ".env"},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_read_env_example_allowed(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Read",
                "tool_input": {"path": "/repos/app/.env.example"},
            }
        )
        self.assertEqual(result["permission"], "allow")

    def test_split_string_hooks_json_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {
                    "command": """python3 -c "open('/home/agent/.cursor/'+'hoo'+'ks.json')" """
                },
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_split_string_catacombs_security_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {
                    "command": """python3 -c "open('/home/agent/.cursor/'+'cata'+'combs-security.json')" """
                },
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_split_string_proc_environ_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {
                    "command": """python3 -c "open('/proc/self/'+'envir'+'on')" """
                },
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_chr_tmp_python_write_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {
                    "command": """python3 -c "open(chr(47)+'t'+'mp'+'/x','w').write('a')" """
                },
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_chr_tmp_node_write_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {
                    "command": """node -e "require('fs').writeFileSync(String.fromCharCode(47)+'tmp/x','a')" """
                },
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_chr_tmp_php_write_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {
                    "command": """php -r "file_put_contents(chr(47).'tmp/x','a');" """
                },
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_tempfile_mkstemp_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {
                    "command": """python3 -c "import tempfile; tempfile.mkstemp()" """
                },
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_os_remove_inside_repos_deferred_via_pretooluse(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {
                    "command": """python3 -c "import os; os.remove('/repos/app/foo')" """
                },
            }
        )
        self.assertEqual(result["permission"], "allow")

    def test_awk_environ_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "awk 'BEGIN { print ENVIRON[\"HOME\"] }'"},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_php_server_count_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": """php -r 'echo count($_SERVER);'"""},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_urllib_urlopen_asks_on_medium(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {
                    "command": """python3 -c "import urllib.request; urllib.request.urlopen('https://example.com')" """
                },
            }
        )
        self.assertEqual(result["permission"], "allow")

    def test_mount_container_escape_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "mount -t tmpfs tmpfs /mnt"},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_pivot_root_container_escape_denied(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "pivot_root /new_root /old_root"},
            }
        )
        self.assertEqual(result["permission"], "deny")

    def test_echo_dev_null_allowed(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "echo hi >/dev/null"},
            }
        )
        self.assertEqual(result["permission"], "allow")

    def test_stderr_redirect_dev_null_allowed(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "ls /nonexistent 2>/dev/null"},
            }
        )
        self.assertEqual(result["permission"], "allow")

    def test_os_remove_inside_repos_asks_before_shell(self):
        with patch("catacombs_guard.write_audit"):
            result = evaluate(
                {
                    "hook": "beforeShellExecution",
                    "command": """python3 -c "import os; os.remove('/repos/app/foo')" """,
                },
                profile_id="medium",
                overrides={},
                config_root=CONFIG_ROOT,
            )
        self.assertEqual(result.permission, "ask")
        self.assertEqual(result.category, "destructive_fs")


class TestAudit4GuardMain(unittest.TestCase):
    """Replay audit 4 probes: hex argv decode, ENVIRON/mount needles, fetch URLs."""

    def _run_guard(self, payload: dict) -> dict:
        with patch("sys.stdin", io.StringIO(json.dumps(payload))):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                with patch("catacombs_guard.write_audit"):
                    code = guard_main()
        self.assertEqual(code, 0)
        return json.loads(out.getvalue())

    def _shell(self, command: str) -> dict:
        return self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": command},
            }
        )

    def test_hex_catacombs_security_json_denied(self):
        result = self._shell(
            """python3 -c "open('/home/agent/.cursor/'+bytes.fromhex('63617461636f6d62732d73656375726974792e6a736f6e'))" """
        )
        self.assertEqual(result["permission"], "deny")

    def test_hex_hooks_json_denied(self):
        result = self._shell(
            """python3 -c "open('/home/agent/.cursor/'+bytes.fromhex('686f6f6b732e6a736f6e'))" """
        )
        self.assertEqual(result["permission"], "deny")

    def test_hex_env_file_denied(self):
        result = self._shell(
            """python3 -c "open(bytes.fromhex('2e656e76'))" """
        )
        self.assertEqual(result["permission"], "deny")

    def test_hex_proc_self_environ_denied(self):
        result = self._shell(
            """python3 -c "open(bytes.fromhex('2f70726f632f73656c662f656e7669726f6e'))" """
        )
        self.assertEqual(result["permission"], "deny")

    def test_hex_getattr_os_environ_denied(self):
        result = self._shell(
            """python3 -c "import os; getattr(os, bytes.fromhex('656e7669726f6e'))" """
        )
        self.assertEqual(result["permission"], "deny")

    def test_hex_buffer_process_env_denied(self):
        result = self._shell(
            """node -e "console.log(process[Buffer.from('656e76','hex')])" """
        )
        self.assertEqual(result["permission"], "deny")

    def test_hex_tmp_python_write_denied(self):
        result = self._shell(
            """python3 -c "open(bytes.fromhex('2f746d70')+'/x','w').write('a')" """
        )
        self.assertEqual(result["permission"], "deny")

    def test_hex_tmp_node_write_denied(self):
        result = self._shell(
            """node -e "require('fs').writeFileSync(Buffer.from('2f746d70','hex')+'/x','a')" """
        )
        self.assertEqual(result["permission"], "deny")

    def test_hex_tmp_php_write_denied(self):
        result = self._shell(
            """php -r "file_put_contents(hex2bin('2f746d702f78'),'a');" """
        )
        self.assertEqual(result["permission"], "deny")

    def test_b64_tmp_write_denied(self):
        result = self._shell(
            """python3 -c "open(base64.b64decode('L3RtcC94'),'w').write('a')" """
        )
        self.assertEqual(result["permission"], "deny")

    def test_b64_env_file_denied(self):
        result = self._shell(
            """python3 -c "open(base64.b64decode('LmVudg=='))" """
        )
        self.assertEqual(result["permission"], "deny")

    def test_chr_dot_ssh_denied_not_network(self):
        result = self._shell(
            """python3 -c "open('/home/agent/'+chr(46)+'ssh/known_hosts')" """
        )
        self.assertEqual(result["permission"], "deny")
        self.assertIn("ssh", result.get("user_message", "").lower())

    def test_awk_environ_iterate_denied(self):
        result = self._shell("awk 'BEGIN{c=0; for (k in ENVIRON) c++}'")
        self.assertEqual(result["permission"], "deny")

    def test_awk_environ_length_denied(self):
        result = self._shell("awk 'BEGIN { print length(ENVIRON) }'")
        self.assertEqual(result["permission"], "deny")

    def test_bare_mount_denied(self):
        result = self._shell("mount")
        self.assertEqual(result["permission"], "deny")

    def test_node_fetch_asks_network_not_write_outside(self):
        result = self._run_guard(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": """node -e "fetch('https://example.com')"""},
            }
        )
        self.assertEqual(result["permission"], "allow")
        self.assertNotIn("write outside", result.get("user_message", "").lower())

    def test_echo_home_still_allowed(self):
        result = self._shell("echo $HOME")
        self.assertEqual(result["permission"], "allow")


class TestHookDispatch(unittest.TestCase):
    def test_normalize_hook_event_name(self):
        self.assertEqual(
            normalize_hook_name({"hook_event_name": "preToolUse", "tool_name": "Read"}),
            "preToolUse",
        )
        self.assertEqual(
            normalize_hook_name({"hook_event_name": "beforeShellExecution", "command": "echo hi"}),
            "beforeShellExecution",
        )

    def test_infer_hook_from_shape(self):
        self.assertEqual(
            normalize_hook_name({"command": "echo hi"}),
            "beforeShellExecution",
        )
        self.assertEqual(
            normalize_hook_name({"file_path": "/repos/foo.txt"}),
            "beforeReadFile",
        )

    def test_dispatch_shell_to_before_shell(self):
        hook, shaped = dispatch_pretooluse(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "curl https://example.com", "cwd": "/repos"},
            }
        )
        self.assertEqual(hook, "beforeShellExecution")
        self.assertEqual(shaped["command"], "curl https://example.com")

    def test_dispatch_read_to_before_read(self):
        hook, shaped = dispatch_pretooluse(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Read",
                "tool_input": {"path": "/repos/app/package.json"},
            }
        )
        self.assertEqual(hook, "beforeReadFile")
        self.assertEqual(shaped["file_path"], "/repos/app/package.json")

    def test_pretooluse_shell_curl_defers_ask_on_medium(self):
        with patch("catacombs_guard.write_audit"):
            result = evaluate(
                {
                    "hook": "beforeShellExecution",
                    "command": "curl -sI --max-time 5 https://example.com",
                },
                profile_id="medium",
                overrides={},
                config_root=CONFIG_ROOT,
                original_hook="preToolUse",
                defer_ask=True,
            )
        self.assertEqual(result.permission, "allow")

    def test_pretooluse_shell_printenv_blocks_on_medium(self):
        with patch("catacombs_guard.write_audit"):
            result = evaluate(
                {
                    "hook": "beforeShellExecution",
                    "command": "printenv",
                },
                profile_id="medium",
                overrides={},
                config_root=CONFIG_ROOT,
                original_hook="preToolUse",
                defer_ask=True,
            )
        self.assertEqual(result.permission, "deny")
        self.assertEqual(result.category, "secret_values")

    def test_hook_event_name_read_under_repos_allowed(self):
        with patch("catacombs_guard.write_audit"):
            result = evaluate(
                {
                    "hook": "beforeReadFile",
                    "file_path": "/repos/app/package.json",
                },
                profile_id="medium",
                overrides={},
                config_root=CONFIG_ROOT,
                original_hook="preToolUse",
                defer_ask=True,
            )
        self.assertEqual(result.permission, "allow")

    def test_guard_main_observational_allows(self):
        with patch("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "postToolUse"}))):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                code = guard_main()
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue()), {"permission": "allow"})

    def test_guard_main_no_missing_hook(self):
        payload = {
            "hook_event_name": "preToolUse",
            "tool_name": "Read",
            "tool_input": {"path": "/repos/app/package.json"},
        }
        with patch("sys.stdin", io.StringIO(json.dumps(payload))):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                with patch("catacombs_guard.write_audit"):
                    code = guard_main()
        self.assertEqual(code, 0)
        result = json.loads(out.getvalue())
        self.assertEqual(result["permission"], "allow")
        self.assertNotIn("missing hook", json.dumps(result))


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

    def test_cursor_rules_write_asks_medium_read_allowed(self):
        with patch("catacombs_guard.write_audit"):
            write_result = evaluate(
                {
                    "tool_name": "Write",
                    "file_path": ".cursor/rules/catacombs.mdc",
                    "hook": "preToolUse",
                },
                profile_id="medium",
                overrides={},
                config_root=CONFIG_ROOT,
            )
        self.assertEqual(write_result.permission, "deny")
        self.assertEqual(write_result.category, "agent_config")

        read_result = evaluate(
            {
                "tool_name": "Read",
                "file_path": ".cursor/rules/catacombs.mdc",
                "hook": "preToolUse",
            },
            profile_id="medium",
            overrides={},
            config_root=CONFIG_ROOT,
        )
        self.assertEqual(read_result.permission, "allow")

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


    def test_agent_config_blocked_high(self):
        with patch("catacombs_guard.write_audit"):
            result = evaluate(
                {
                    "tool_name": "Write",
                    "file_path": ".cursor/mcp.json",
                    "hook": "preToolUse",
                },
                profile_id="high",
                overrides={},
                config_root=CONFIG_ROOT,
            )
        self.assertEqual(result.permission, "deny")
        self.assertEqual(result.category, "agent_config")


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
        self.assertEqual(result.permission, "deny")
        self.assertEqual(result.category, "ssh_dir")
        self.assertTrue(result.notify)

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
