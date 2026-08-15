# Security recommendations

![The Catacumbs — Security recommendations](../docs/images/hero-recommendations.webp)

Mitigations for the vulnerabilities documented in [known-vulnerabilities.md](./known-vulnerabilities.md). Ordered by impact; implement the **Critical** and **High** items before trusting the sandbox with sensitive keys or production-adjacent services.

---

## Quick priority matrix

| Priority | IDs | Theme |
|----------|-----|-------|
| **P0 — do first** | KV-02, KV-03 | Keys and host services |
| **P1 — high value** | KV-01, KV-04, KV-05 | Mount scope and persistence |
| **P2 — harden** | KV-07, KV-08, KV-09 | Egress, tooling, auto-run |
| **Mitigated** | KV-06 | Capabilities — `--cap-add=all` already removed |

---

## KV-02: SSH private key exposure

### Recommendations

1. **Use a dedicated deploy key per repo** (read-only when possible) instead of your personal `id_ed25519`. Generate on the host:
   ```bash
   ssh-keygen -t ed25519 -f .devcontainer/home/.ssh/id_ed25519_github -C "catacumbs-agent"
   ```
   Add the public key to a single GitHub repo with **read-only** access.

2. **Never mount your primary SSH key.** Do not symlink `~/.ssh/id_ed25519` via `init.sh` for high-trust setups; copy or generate a limited key instead.

3. **Mount `.ssh` read-only** in `devcontainer.json`:
   ```json
   "source=${localWorkspaceFolder}/.devcontainer/home/.ssh,target=/home/agent/.ssh,type=bind,readonly"
   ```
   Note: read-only prevents the agent from altering `known_hosts` but still allows **using** the private key. Combine with a scoped key.

4. **Use HTTPS + credential helper with a fine-grained PAT** instead of SSH when you need write access with revocable, repo-scoped tokens.

5. **Rotate keys** if you suspect an agent run was malicious or ran untrusted prompts.

---

## KV-03: Host network via `host.docker.internal`

### Recommendations

1. **Bind host services to `127.0.0.1` only** where possible. `host.docker.internal` resolves to the host gateway; services listening only on localhost may still be reachable depending on Docker networking — treat published ports as agent-accessible.

2. **Do not publish sensitive databases to `0.0.0.0`.** Use Docker networks that are not bridged to the devcontainer, or firewall the host port so only true localhost can connect (knowing Docker may bypass naive localhost-only assumptions).

3. **Run dev databases in isolated compose projects** with strong passwords and no default credentials. Assume the agent can attempt connections.

4. **Remove `host.docker.internal` when not needed** by dropping `--add-host=host.docker.internal:host-gateway` from `runArgs`. Agents then cannot reach host services by that hostname (may break workflows that depend on it).

5. **Use a host firewall** (e.g. `ufw`, `nftables`) to deny the Docker bridge subnet access to sensitive host ports.

---

## KV-01: Host filesystem via bind mounts

### Recommendations

1. **Keep only intended projects under `repos/`.** Do not symlink your entire home directory or secrets into `repos/`.

2. **Split sensitive config from mounted paths:**
   - Keep production secrets out of `repos/` entirely (use host-only env files, secret managers).
   - Consider mounting `.cursor/rules` read-only if agents should not rewrite policy:
     ```json
     "source=${localWorkspaceFolder}/.cursor/rules,target=/home/agent/.cursor/rules,type=bind,readonly"
     ```

3. **Version-control and review changes** to `.cursor/`, `.agents/`, and `skills-lock.json` the same as application code. After agent sessions, run `git diff` on the catacumbs root.

4. **Use a dedicated catacumbs clone** on a machine or user account that does not hold unrelated personal files.

5. **Optional: narrow workspace mount** to a single project directory instead of all of `repos/` when working on one module.

---

## KV-04: Agent config persistence

### Recommendations

1. **Mount `.cursor/rules` read-only** (see KV-01). Allow writes only to project code under `repos/`, not policy files.

2. **Pin and audit MCP config** (`.cursor/mcp.json`). Reject agent-proposed changes that add unknown MCP servers or broaden tool access.

3. **Treat `skills-lock.json` changes as security-relevant.** Review before running `npx skills experimental_install` on the host.

4. **Add a post-session hook or checklist** to diff `.cursor/` and `.agents/` before committing.

5. **Use branch protection** on the catacumbs repo so agent-modified rules cannot merge without human review.

---

## KV-05: Symlink traversal under `repos/`

### Recommendations

1. **Audit `repos/` for symlinks** before opening the devcontainer:
   ```bash
   find repos/ -type l -ls
   ```

2. **Refuse symlinks that escape `repos/`** in your onboarding docs or a small host-side check in `init.sh`.

3. **Clone repos directly** into `repos/<name>/` instead of symlinking arbitrary host paths.

4. **Enable `core.protectNTFS` / avoid following symlinks in tooling** where supported (editor-specific; not a full fix).

---

## KV-06: Broad Linux capabilities

### Recommendations

1. **Remove `--cap-add=all`** from `devcontainer.json` `runArgs` — **already done by default**; the current config ships with Docker's default capability set.

2. **Do not re-add broad capabilities.** If a specific cap is required, add only that one (typical dev work needs none).

3. **Keep gVisor enabled** (`--runtime=runsc`). Do not switch to `runc` for convenience without accepting a larger escape surface.

4. **Keep the image updated** — rebuild the devcontainer when the base image or gVisor runtime is patched.

---

## KV-07: Unrestricted outbound network

### Recommendations

1. **Run on an isolated network** (VM, cloud dev box) without access to production VPCs.

2. **Use Docker user-defined networks with egress restrictions** or a host firewall blocking container egress except allowlisted domains (advanced; may break npm, MCP, etc.).

3. **Do not store secrets in `repos/`** — assume exfiltration is possible.

4. **Review agent network activity** in logs when debugging suspicious behavior.

---

## KV-08: Remote repo and API access

### Recommendations

1. **Scope credentials:** read-only deploy keys, fine-grained GitHub PATs, separate `gh auth` tokens with minimal scopes.

2. **Disable or remove `gh`** from the image if not required for your workflow.

3. **Use GitHub branch protection and required reviews** so agent pushes cannot merge without humans.

4. **Pin dependencies** and avoid blind `npm install` / `npx` of unaudited packages in agent-driven sessions.

5. **Consider a dedicated bot GitHub account** for agent operations, not tied to a human's full org access.

---

## KV-09: Auto-run agent commands

### Recommendations

1. **Keep the default** — `"cursor.chat.autoRun": false` in `devcontainer.json` is the safe baseline; the agent prompts before each shell command.

2. **Opt in only for trusted workflows** — set `"cursor.chat.autoRun": true` when you want unattended command execution and mounts/keys are already limited per KV-01 and KV-02:
   ```json
   "cursor.chat.autoRun": true
   ```

3. **Prefer plan/review mode** for destructive operations (migrations, mass deletes, force-push).

---

## Hardened profile (checklist)

A practical “safer catacumbs” setup:

- [ ] Dedicated read-only or single-repo SSH deploy key in `.devcontainer/home/.ssh/`
- [ ] `.ssh` mount marked `readonly` where compatible
- [ ] `.cursor/rules` mounted read-only
- [ ] No symlinks escaping `repos/`
- [ ] Host DBs and admin UIs not exposed on bridge-accessible ports
- [x] `--cap-add=all` removed from `runArgs` (already the default)
- [ ] `cursor.chat.autoRun` left disabled (default) or only enabled for trusted sessions
- [ ] Post-session `git diff` on `.cursor/`, `.agents/`, and `repos/`
- [ ] Catacumbs runs on a dedicated dev machine or VM, not your daily driver with full keys

---

## Trade-offs

Tighter security reduces agent autonomy and convenience. The catacumbs design intentionally trades **some** host exposure for productivity (git over SSH, host DB access, editable rules). Choose a profile that matches your data classification:

| Profile | Mounts | Keys | `host.docker.internal` | Auto-run |
|---------|--------|------|------------------------|----------|
| **Dev (default)** | Full | Linked personal key | Enabled | false |
| **Team** | `repos/` + read-only rules | Per-repo deploy key | Enabled, firewalled | false |
| **Paranoid** | Single project subfolder | None (HTTPS read-only) | Disabled | false |

Document which profile you use in your team onboarding so expectations match the actual threat model.
