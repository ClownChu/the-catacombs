#!/usr/bin/env python3
"""Unit tests for catacombs security guard."""

from __future__ import annotations

import json
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from catacombs_guard import (  # noqa: E402
    DEFAULT_PROFILE,
    GuardResult,
    apply_ask_deferral,
    dispatch_pretooluse,
    evaluate,
    evaluate_audit,
    guard_main,
    load_profile,
    merge_category_settings,
    normalize_hook_name,
)

CONFIG_ROOT = Path(__file__).resolve().parent.parent
HOOK_SCRIPT = Path(__file__).resolve().parent / "catacombs-hook.sh"
SENTINEL = Path("/etc/catacombs-container")
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
    {"id": "M1b", "profile": "medium", "event": {"command": "rm /repos/app/foo", "hook": "beforeShellExecution"}, "expect": {"permission": "ask", "category": "destructive_fs"}},
    {"id": "M1c", "profile": "medium", "event": {"command": "rm /tmp/x", "hook": "beforeShellExecution"}, "expect": {"permission": "deny", "category": "file_write_outside_repos"}},
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

GUARD_MAIN_SCENARIOS = [
    {"id": "write_tmp", "payload": {"hook_event_name": "preToolUse", "tool_name": "Write", "tool_input": {"path": "/tmp/audit-probe-write.txt"}}, "expect": {"permission": "deny"}},
    {"id": "write_home_agent", "payload": {"hook_event_name": "preToolUse", "tool_name": "Write", "tool_input": {"path": "/home/agent/audit-probe-write.txt"}}, "expect": {"permission": "deny"}},
    {"id": "write_etc", "payload": {"hook_event_name": "preToolUse", "tool_name": "Write", "tool_input": {"path": "/etc/audit-probe-write.txt"}}, "expect": {"permission": "deny"}},
    {"id": "redirect_outside", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "echo audit > /tmp/audit-probe-redirect.txt"}}, "expect": {"permission": "deny"}},
    {"id": "rm_outside", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "rm /tmp/audit-probe-missing"}}, "expect": {"permission": "deny"}},
    {"id": "rm_rf_outside", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "rm -rf /tmp/x"}}, "expect": {"permission": "deny"}},
    {"id": "rm_inside_repos_ask", "payload": {"hook_event_name": "beforeShellExecution", "command": "rm /repos/app/foo"}, "expect": {"permission": "ask"}},
    {"id": "delete_outside", "payload": {"hook_event_name": "preToolUse", "tool_name": "Delete", "tool_input": {"path": "/tmp/audit-probe-delete.txt"}}, "expect": {"permission": "deny"}},
    {"id": "delete_inside_repos", "payload": {"hook_event_name": "preToolUse", "tool_name": "Delete", "tool_input": {"path": "/repos/app/foo"}}, "expect": {"permission": "deny"}},
    {"id": "cat_proc_environ", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "cat /proc/self/environ"}}, "expect": {"permission": "deny"}},
    {"id": "bare_set", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "set"}}, "expect": {"permission": "deny"}},
    {"id": "set_options", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "set -euo pipefail"}}, "expect": {"permission": "allow"}},
    {"id": "node_env_keys", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": 'node -e "console.log(Object.keys(process.env))"'}}, "expect": {"permission": "deny"}},
    {"id": "echo_home", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "echo $HOME"}}, "expect": {"permission": "allow"}},
    {"id": "python_write_tmp", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"open('/tmp/x','w').write('a')\""}}, "expect": {"permission": "deny"}},
    {"id": "node_write_tmp", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "node -e \"require('fs').writeFileSync('/tmp/x','a')\""}}, "expect": {"permission": "deny"}},
    {"id": "php_write_tmp", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "php -r \"file_put_contents('/tmp/x','a');\""}}, "expect": {"permission": "deny"}},
    {"id": "python_os_remove_outside", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"import os; os.remove('/tmp/x')\""}}, "expect": {"permission": "deny"}},
    {"id": "python_read_tmp", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"print(open('/tmp/x').read())\""}}, "expect": {"permission": "allow"}},
    {"id": "read_git_credentials", "payload": {"hook_event_name": "preToolUse", "tool_name": "Read", "tool_input": {"path": "/home/agent/.git-credentials"}}, "expect": {"permission": "deny"}},
    {"id": "read_home_npmrc", "payload": {"hook_event_name": "preToolUse", "tool_name": "Read", "tool_input": {"path": "/home/agent/.npmrc"}}, "expect": {"permission": "deny"}},
    {"id": "read_repos_npmrc", "payload": {"hook_event_name": "preToolUse", "tool_name": "Read", "tool_input": {"path": "/repos/app/.npmrc"}}, "expect": {"permission": "allow"}},
    {"id": "write_inside_repos", "payload": {"hook_event_name": "preToolUse", "tool_name": "Write", "tool_input": {"path": "/repos/app/foo.py"}}, "expect": {"permission": "allow"}},
    {"id": "target_file_json", "payload": {"hook_event_name": "preToolUse", "tool_name": "Write", "tool_input": json.dumps({"target_file": "/tmp/audit-probe-target-file.txt"})}, "expect": {"permission": "deny"}},
    {"id": "read_env_tool_input", "payload": {"hook_event_name": "preToolUse", "tool_name": "Read", "tool_input": {"path": "/repos/app/.env"}}, "expect": {"permission": "deny"}},
    {"id": "read_env_file_path", "payload": {"hook_event_name": "preToolUse", "tool_name": "Read", "file_path": "/repos/app/.env", "tool_input": {}}, "expect": {"permission": "deny"}},
    {"id": "read_env_uri", "payload": {"hook_event_name": "beforeReadFile", "file_path": "file:///repos/app/.env"}, "expect": {"permission": "deny"}},
    {"id": "read_relative_env", "payload": {"hook_event_name": "preToolUse", "tool_name": "Read", "tool_input": {"path": ".env"}}, "expect": {"permission": "deny"}},
    {"id": "read_env_example", "payload": {"hook_event_name": "preToolUse", "tool_name": "Read", "tool_input": {"path": "/repos/app/.env.example"}}, "expect": {"permission": "allow"}},
    {"id": "split_hooks_json", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"open('/home/agent/.cursor/'+'hoo'+'ks.json')\""}}, "expect": {"permission": "deny"}},
    {"id": "split_security_json", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"open('/home/agent/.cursor/'+'cata'+'combs-security.json')\""}}, "expect": {"permission": "deny"}},
    {"id": "split_proc_environ", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"open('/proc/self/'+'envir'+'on')\""}}, "expect": {"permission": "deny"}},
    {"id": "chr_python_write", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"open(chr(47)+'t'+'mp'+'/x','w').write('a')\""}}, "expect": {"permission": "deny"}},
    {"id": "chr_node_write", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "node -e \"require('fs').writeFileSync(String.fromCharCode(47)+'tmp/x','a')\""}}, "expect": {"permission": "deny"}},
    {"id": "chr_php_write", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "php -r \"file_put_contents(chr(47).'tmp/x','a');\""}}, "expect": {"permission": "deny"}},
    {"id": "tempfile_mkstemp", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"import tempfile; tempfile.mkstemp()\""}}, "expect": {"permission": "deny"}},
    {"id": "os_remove_inside_deferred", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"import os; os.remove('/repos/app/foo')\""}}, "expect": {"permission": "allow"}},
    {"id": "awk_environ", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "awk 'BEGIN { print ENVIRON[\"HOME\"] }'"}}, "expect": {"permission": "deny"}},
    {"id": "php_server_count", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "php -r 'echo count($_SERVER);'"}}, "expect": {"permission": "deny"}},
    {"id": "urllib_deferred_allow", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"import urllib.request; urllib.request.urlopen('https://example.com')\""}}, "expect": {"permission": "allow"}},
    {"id": "mount_escape", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "mount -t tmpfs tmpfs /mnt"}}, "expect": {"permission": "deny"}},
    {"id": "pivot_root_escape", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "pivot_root /new_root /old_root"}}, "expect": {"permission": "deny"}},
    {"id": "echo_dev_null", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "echo hi >/dev/null"}}, "expect": {"permission": "allow"}},
    {"id": "stderr_dev_null", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "ls /nonexistent 2>/dev/null"}}, "expect": {"permission": "allow"}},
    {"id": "hex_security_json", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"open('/home/agent/.cursor/'+bytes.fromhex('63617461636f6d62732d73656375726974792e6a736f6e'))\""}}, "expect": {"permission": "deny"}},
    {"id": "hex_hooks_json", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"open('/home/agent/.cursor/'+bytes.fromhex('686f6f6b732e6a736f6e'))\""}}, "expect": {"permission": "deny"}},
    {"id": "hex_env_file", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"open(bytes.fromhex('2e656e76'))\""}}, "expect": {"permission": "deny"}},
    {"id": "hex_proc_environ", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"open(bytes.fromhex('2f70726f632f73656c662f656e7669726f6e'))\""}}, "expect": {"permission": "deny"}},
    {"id": "hex_getattr_environ", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"import os; getattr(os, bytes.fromhex('656e7669726f6e'))\""}}, "expect": {"permission": "deny"}},
    {"id": "hex_buffer_process_env", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "node -e \"console.log(process[Buffer.from('656e76','hex')])\""}}, "expect": {"permission": "deny"}},
    {"id": "hex_tmp_python", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"open(bytes.fromhex('2f746d70')+'/x','w').write('a')\""}}, "expect": {"permission": "deny"}},
    {"id": "hex_tmp_node", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "node -e \"require('fs').writeFileSync(Buffer.from('2f746d70','hex')+'/x','a')\""}}, "expect": {"permission": "deny"}},
    {"id": "hex_tmp_php", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "php -r \"file_put_contents(hex2bin('2f746d702f78'),'a');\""}}, "expect": {"permission": "deny"}},
    {"id": "b64_tmp_write", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"open(base64.b64decode('L3RtcC94'),'w').write('a')\""}}, "expect": {"permission": "deny"}},
    {"id": "b64_env_file", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"open(base64.b64decode('LmVudg=='))\""}}, "expect": {"permission": "deny"}},
    {"id": "chr_dot_ssh", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "python3 -c \"open('/home/agent/'+chr(46)+'ssh/known_hosts')\""}}, "expect": {"permission": "deny", "message_contains": "ssh"}},
    {"id": "awk_environ_iterate", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "awk 'BEGIN{c=0; for (k in ENVIRON) c++'"}}, "expect": {"permission": "deny"}},
    {"id": "awk_environ_length", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "awk 'BEGIN { print length(ENVIRON) }'"}}, "expect": {"permission": "deny"}},
    {"id": "bare_mount", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "mount"}}, "expect": {"permission": "deny"}},
    {"id": "node_fetch_deferred", "payload": {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "node -e \"fetch('https://example.com')\""}}, "expect": {"permission": "allow", "message_excludes": "write outside"}},
]

AUDIT6_ENV_SCENARIOS = [
    {
        "id": "chr46_env_prefix",
        "command": "python3 -c \"open('/repos/app/'+chr(46)+'env')\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_file"},
    },
    {
        "id": "hex_env_prefix",
        "command": "python3 -c \"open('/repos/app/'+bytes.fromhex('2e656e76'))\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_file"},
    },
    {
        "id": "b64_env_prefix",
        "command": "python3 -c \"open('/repos/app/'+base64.b64decode('LmVudg=='))\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_file"},
    },
    {
        "id": "join_chr_list",
        "command": "python3 -c \"open(''.join(chr(c) for c in [46,101,110,118]))\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_file"},
    },
    {
        "id": "reverse_slice_env",
        "command": "python3 -c \"open('vne.'[::-1])\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_file"},
    },
    {
        "id": "from_char_code_env",
        "command": "node -e \"require('fs').readFileSync(String.fromCharCode(46,101,110,118))\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_file"},
    },
    {
        "id": "multiline_python_env",
        "command": "python3 -c \"\nopen('/repos/app/.env')\n\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_file"},
    },
    {
        "id": "env_example_shell_allowed",
        "command": "python3 -c \"open('/repos/app/.env.example')\"",
        "expect": {"permission": "allow"},
    },
    {
        "id": "echo_home_allowed",
        "command": "echo $HOME",
        "expect": {"permission": "allow"},
    },
]

AUDIT7_ARGV_ALIASES = [
    {
        "id": "hex_getattr_environ",
        "command": "python3 -c \"import os; getattr(os, bytes.fromhex('656e7669726f6e'))\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_dump"},
    },
    {
        "id": "from_os_import_environ",
        "command": "python3 -c \"from os import environ\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_dump"},
    },
    {
        "id": "posix_environ",
        "command": "python3 -c \"import posix; posix.environ\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_dump"},
    },
    {
        "id": "from_posix_import_environ",
        "command": "python3 -c \"from posix import environ\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_dump"},
    },
    {
        "id": "import_os_as_o",
        "command": "python3 -c \"import os as o; o.environ\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_dump"},
    },
    {
        "id": "os_dict_environ",
        "command": "python3 -c \"import os; os.__dict__['environ']\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_dump"},
    },
    {
        "id": "vars_os_environ",
        "command": "python3 -c \"import os; vars(os)['environ']\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_dump"},
    },
    {
        "id": "importlib_os_environ",
        "command": "python3 -c \"import importlib; importlib.import_module('os').environ\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_dump"},
    },
    {
        "id": "reverse_getattribute",
        "command": "python3 -c \"import os; os.__getattribute__('norivne'[::-1])\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_dump"},
    },
    {
        "id": "reverse_dict_get",
        "command": "python3 -c \"import os; os.__dict__.get('norivne'[::-1])\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_dump"},
    },
    {
        "id": "object_getattribute",
        "command": "python3 -c \"import os; object.__getattribute__(os, 'norivne'[::-1])\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_dump"},
    },
    {
        "id": "codecs_decode_getattr",
        "command": "python3 -c \"import os,codecs; getattr(os, codecs.decode('656e7669726f6e', 'hex'))\"",
        "expect": {"permission": "deny", "category": "secret_values", "subtype": "env_dump"},
    },
]


def _evaluate_shell(command: str, profile_id: str = "low") -> GuardResult:
    with patch("catacombs_guard.write_audit"):
        return evaluate(
            {"hook": "beforeShellExecution", "command": command},
            profile_id=profile_id,
            overrides={},
            config_root=CONFIG_ROOT,
        )


def _write_probe_script(tmp: Path, name: str, body: str) -> Path:
    path = tmp / name
    path.write_text(body, encoding="utf-8")
    return path


def _run_guard(payload: dict) -> dict:
    with patch("sys.stdin", io.StringIO(json.dumps(payload))):
        with patch("sys.stdout", new_callable=io.StringIO) as out:
            with patch("catacombs_guard.write_audit"):
                code = guard_main()
    if code != 0:
        raise AssertionError(f"guard_main returned {code}")
    return json.loads(out.getvalue())


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


def _run_hook_subprocess(mode: str, *, path_prefix: str | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if path_prefix is not None:
        env["PATH"] = f"{path_prefix}:{env.get('PATH', '')}"
    return subprocess.run(
        ["bash", str(HOOK_SCRIPT), mode],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


@unittest.skipIf(SENTINEL.exists(), "sentinel present (container image)")
class TestContainerSentinelGate(unittest.TestCase):
    def test_sentinel_absent_guard_allows(self):
        result = _run_hook_subprocess("guard")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {"permission": "allow"})

    def test_sentinel_absent_audit_empty_json(self):
        result = _run_hook_subprocess("audit")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {})

    def test_sentinel_absent_with_fake_id_still_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_id = Path(tmp) / "id"
            fake_id.write_text("#!/bin/sh\nprintf 'root\\n'\n", encoding="utf-8")
            fake_id.chmod(0o755)
            result = _run_hook_subprocess("guard", path_prefix=tmp)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {"permission": "allow"})


class TestAudit6EnvProbes(unittest.TestCase):
    def test_audit6_env_obfuscation_probes(self):
        for row in AUDIT6_ENV_SCENARIOS:
            with self.subTest(scenario_id=row["id"]):
                with patch("catacombs_guard.write_audit"):
                    result = evaluate(
                        {"hook": "beforeShellExecution", "command": row["command"]},
                        profile_id="low",
                        overrides={},
                        config_root=CONFIG_ROOT,
                    )
                assert_guard_result(self, result, row["expect"])

    def test_audit6_chr46_evaluate_secret_values(self):
        with patch("catacombs_guard.write_audit"):
            result = evaluate(
                {
                    "hook": "beforeShellExecution",
                    "command": "python3 -c \"open('/repos/app/'+chr(46)+'env')\"",
                },
                profile_id="medium",
                overrides={},
                config_root=CONFIG_ROOT,
            )
        self.assertEqual(result.permission, "deny")
        self.assertEqual(result.category, "secret_values")
        self.assertEqual(result.subtype, "env_file")

    def test_audit6_multiline_evaluate_secret_values(self):
        with patch("catacombs_guard.write_audit"):
            result = evaluate(
                {
                    "hook": "beforeShellExecution",
                    "command": "python3 -c \"\nopen('/repos/app/.env')\n\"",
                },
                profile_id="medium",
                overrides={},
                config_root=CONFIG_ROOT,
            )
        self.assertEqual(result.permission, "deny")
        self.assertEqual(result.category, "secret_values")
        self.assertEqual(result.subtype, "env_file")


class TestAudit7HelperScripts(unittest.TestCase):
    def test_audit7_argv_env_aliases(self):
        for row in AUDIT7_ARGV_ALIASES:
            with self.subTest(scenario_id=row["id"]):
                result = _evaluate_shell(row["command"])
                assert_guard_result(self, result, row["expect"])

    def test_audit7_helper_script_denies(self):
        cases = [
            (
                "policy_open",
                "probe_policy.py",
                "open('/home/agent/.cursor/catacombs-security.json')",
                {"permission": "deny", "category": "guard_policy"},
            ),
            (
                "ssh_known_hosts",
                "probe_ssh_hosts.py",
                "open('/home/agent/.ssh/known_hosts')",
                {"permission": "deny", "category": "ssh_dir"},
            ),
            (
                "ssh_id_rsa",
                "probe_ssh_key.py",
                "open('/home/agent/.ssh/id_rsa')",
                {"permission": "deny", "category": "ssh_dir"},
            ),
            (
                "ssh_config",
                "probe_ssh_cfg.py",
                "open('/home/agent/.ssh/config')",
                {"permission": "deny", "category": "ssh_dir"},
            ),
            (
                "repos_dotvars",
                "probe_dotvars.py",
                "open('/repos/site-remake/.env')",
                {"permission": "deny", "category": "secret_values", "subtype": "env_file"},
            ),
            (
                "nested_dotvars",
                "probe_nested.py",
                "open('/repos/app/nested/.env')",
                {"permission": "deny", "category": "secret_values", "subtype": "env_file"},
            ),
            (
                "from_os_keys",
                "probe_keys.py",
                "from os import environ\nprint(list(environ.keys()))",
                {"permission": "deny", "category": "secret_values", "subtype": "env_dump"},
            ),
            (
                "hooks_json",
                "probe_hooks.py",
                "open('/home/agent/.cursor/hooks.json')",
                {"permission": "deny", "category": "guard_policy"},
            ),
            (
                "listdir_hooks",
                "probe_listdir.py",
                "import os\nos.listdir('/home/agent/.cursor/hooks')",
                {"permission": "deny", "category": "guard_policy"},
            ),
            (
                "guard_source",
                "probe_guard_src.py",
                "open('/home/agent/.cursor/hooks/catacombs_guard.py')",
                {"permission": "deny", "category": "guard_policy"},
            ),
            (
                "write_tmp_python",
                "probe_write_py.py",
                "from pathlib import Path\nPath('/tmp/audit7_probe_py.txt').write_text('x')",
                {"permission": "deny", "category": "file_write_outside_repos"},
            ),
            (
                "write_tmp_node",
                "probe_write_js.js",
                "require('fs').writeFileSync('/tmp/audit7_probe_js.txt','x')",
                {"permission": "deny", "category": "file_write_outside_repos"},
            ),
            (
                "write_tmp_php",
                "probe_write_php.php",
                "file_put_contents('/tmp/audit7_probe_php.txt','x');",
                {"permission": "deny", "category": "file_write_outside_repos"},
            ),
            (
                "netrc_credential",
                "probe_netrc.py",
                "open('/home/agent/.netrc')",
                {"permission": "deny", "category": "credential_access"},
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for scenario_id, filename, body, expect in cases:
                with self.subTest(scenario_id=scenario_id):
                    helper = _write_probe_script(tmp_path, filename, body)
                    if filename.endswith(".js"):
                        cmd = f"node {helper}"
                    elif filename.endswith(".php"):
                        cmd = f"php {helper}"
                    elif filename.endswith(".sh"):
                        cmd = f"bash {helper}"
                    else:
                        cmd = f"python3 {helper}"
                    result = _evaluate_shell(cmd)
                    assert_guard_result(self, result, expect)

    def test_audit7_exec_open_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            helper = _write_probe_script(
                tmp_path,
                "probe_exec.py",
                "open('/home/agent/.cursor/catacombs-security.json')",
            )
            cmd = f"python3 -c \"exec(open('{helper}').read())\""
            result = _evaluate_shell(cmd)
            self.assertEqual(result.permission, "deny")
            self.assertEqual(result.category, "guard_policy")

    def test_audit7_symlink_helper_resolved_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            dotvars = tmp_path / ".env"
            dotvars.write_text("SECRET=1\n", encoding="utf-8")
            link = tmp_path / "lnk_probe.py"
            link.symlink_to(dotvars)
            result = _evaluate_shell(f"python3 {link}")
            self.assertEqual(result.permission, "deny")
            self.assertEqual(result.category, "secret_values")
            self.assertEqual(result.subtype, "env_file")

    def test_audit7_node_readfile_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            helper = _write_probe_script(
                tmp_path,
                "probe_read.js",
                "require('fs').readFileSync('/repos/site-remake/.env')",
            )
            result = _evaluate_shell(f"node {helper}")
            self.assertEqual(result.permission, "deny")
            self.assertEqual(result.category, "secret_values")
            self.assertEqual(result.subtype, "env_file")

    def test_audit7_bash_cat_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            helper = _write_probe_script(
                tmp_path,
                "probe_cat.sh",
                "cat '/repos/site-remake/.env'",
            )
            result = _evaluate_shell(f"bash {helper}")
            self.assertEqual(result.permission, "deny")
            self.assertEqual(result.category, "secret_values")
            self.assertEqual(result.subtype, "env_file")

    def test_audit7_controls_allow(self):
        controls = [
            ("print_hi", "print('hi')", "python3"),
            ("write_repos", "import shutil; shutil.copyfile('/repos/app/a.txt','/repos/app/b.txt')", "python3"),
            ("getenv_port", "import os; os.getenv('PORT')", "python3"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for scenario_id, body, interpreter in controls:
                with self.subTest(scenario_id=scenario_id):
                    helper = _write_probe_script(tmp_path, f"ctrl_{scenario_id}.py", body)
                    result = _evaluate_shell(f"{interpreter} {helper}")
                    self.assertEqual(result.permission, "allow")

        allow_cmds = [
            ("env_example_argv", "python3 -c \"open('/repos/app/.env.example')\""),
            ("echo_home", "echo $HOME"),
            ("echo_dev_null", "echo hi >/dev/null"),
        ]
        for scenario_id, command in allow_cmds:
            with self.subTest(scenario_id=scenario_id):
                result = _evaluate_shell(command)
                self.assertEqual(result.permission, "allow")


class TestGuardMainScenarios(unittest.TestCase):
    def test_guard_main_scenarios(self):
        for row in GUARD_MAIN_SCENARIOS:
            with self.subTest(scenario_id=row["id"]):
                result = _run_guard(row["payload"])
                expect = row["expect"]
                self.assertEqual(result["permission"], expect["permission"])
                if "message_contains" in expect:
                    self.assertIn(
                        expect["message_contains"],
                        result.get("user_message", "").lower(),
                    )
                if "message_excludes" in expect:
                    self.assertNotIn(
                        expect["message_excludes"],
                        result.get("user_message", "").lower(),
                    )
                if expect["permission"] == "deny":
                    self.assertIn("user_message", result)
                    self.assertIn("agent_message", result)


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
        self.assertEqual(normalize_hook_name({"command": "echo hi"}), "beforeShellExecution")
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

    def test_apply_ask_deferral_curl_on_medium(self):
        with patch("catacombs_guard.write_audit"):
            result = apply_ask_deferral(
                evaluate(
                    {
                        "hook": "beforeShellExecution",
                        "command": "curl -sI --max-time 5 https://example.com",
                    },
                    profile_id="medium",
                    overrides={},
                    config_root=CONFIG_ROOT,
                ),
                "preToolUse",
                "beforeShellExecution",
            )
        self.assertEqual(result.permission, "allow")

    def test_apply_ask_deferral_printenv_still_denies(self):
        with patch("catacombs_guard.write_audit"):
            result = apply_ask_deferral(
                evaluate(
                    {"hook": "beforeShellExecution", "command": "printenv"},
                    profile_id="medium",
                    overrides={},
                    config_root=CONFIG_ROOT,
                ),
                "preToolUse",
                "beforeShellExecution",
            )
        self.assertEqual(result.permission, "deny")
        self.assertEqual(result.category, "secret_values")

    def test_os_remove_inside_repos_asks_before_shell(self):
        with patch("catacombs_guard.write_audit"):
            result = evaluate(
                {
                    "hook": "beforeShellExecution",
                    "command": "python3 -c \"import os; os.remove('/repos/app/foo')\"",
                },
                profile_id="medium",
                overrides={},
                config_root=CONFIG_ROOT,
            )
        self.assertEqual(result.permission, "ask")
        self.assertEqual(result.category, "destructive_fs")

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
            {"tool_name": "Write", "file_path": ".cursor/hooks.json", "hook": "preToolUse"},
            {"tool_name": "Read", "file_path": ".cursor/hooks/catacombs_guard.py", "hook": "preToolUse"},
            {"tool_name": "Grep", "file_path": ".cursor/catacombs-security/categories.json", "hook": "preToolUse"},
            {"file_path": ".cursor/hooks.json", "hook": "beforeReadFile"},
            {"tool_name": "StrReplace", "file_path": ".cursor/catacombs-security.json", "hook": "preToolUse"},
            {"tool_name": "Write", "file_path": "/home/agent/.cursor/hooks/catacombs_guard.py", "hook": "preToolUse"},
            {"tool_name": "Write", "file_path": ".devcontainer/home/.cursor/hooks.json", "hook": "preToolUse"},
            {"command": "echo x > .cursor/hooks.json", "hook": "beforeShellExecution"},
            {"command": "cat ~/.cursor/hooks.json", "hook": "beforeShellExecution"},
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
