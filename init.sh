#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

SSH_DIR="$ROOT/.devcontainer/home/.ssh"

info() {
  printf '[init] %s\n' "$*"
}

warn() {
  printf '[init] WARNING: %s\n' "$*" >&2
}

die() {
  printf '[init] ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed."
}

info "Initializing catacumbs (host setup before devcontainer build)..."

# --- Prerequisites (host) ---------------------------------------------------

require_command git
require_command docker
require_command node
require_command npm

if ! docker info >/dev/null 2>&1; then
  die "Docker is installed but the daemon is not running. Start Docker, then re-run ./init.sh"
fi

if ! command -v uv >/dev/null 2>&1; then
  warn "uv is not installed. Serena MCP (.cursor/mcp.json) uses 'uvx'; install uv from https://docs.astral.sh/uv/"
fi

# --- Directory layout ---------------------------------------------------------

info "Ensuring required directories exist..."
mkdir -p "$SSH_DIR" "$ROOT/repos" "$ROOT/.agents/skills"

# --- SSH keys for the devcontainer mount --------------------------------------

info "Configuring SSH keys for the devcontainer (.devcontainer/home/.ssh)..."

link_or_copy_key() {
  local source_key="$1"
  local target_name="$2"

  if [[ -f "$SSH_DIR/$target_name" ]]; then
    return 0
  fi

  if [[ ! -f "$source_key" ]]; then
    return 1
  fi

  ln -sf "$source_key" "$SSH_DIR/$target_name"
  info "Linked $source_key -> $SSH_DIR/$target_name"

  local pub_key="${source_key}.pub"
  if [[ -f "$pub_key" && ! -f "$SSH_DIR/${target_name}.pub" ]]; then
    ln -sf "$pub_key" "$SSH_DIR/${target_name}.pub"
  fi

  return 0
}

has_usable_key=false
if link_or_copy_key "$HOME/.ssh/id_ed25519" "id_ed25519"; then
  has_usable_key=true
elif link_or_copy_key "$HOME/.ssh/id_rsa" "id_rsa"; then
  has_usable_key=true
fi

chmod 700 "$SSH_DIR"
for key in "$SSH_DIR"/id_*; do
  [[ -f "$key" && "$key" != *.pub ]] && chmod 600 "$key"
done

if [[ "$has_usable_key" == false ]]; then
  warn "No SSH private key found in ~/.ssh (id_ed25519 or id_rsa)."
  warn "Copy or link a GitHub SSH key into $SSH_DIR before using git inside the devcontainer."
fi

# --- GitHub host keys ---------------------------------------------------------

if [[ ! -f "$SSH_DIR/known_hosts" ]] || ! grep -q '^github\.com' "$SSH_DIR/known_hosts" 2>/dev/null; then
  if command -v ssh-keyscan >/dev/null 2>&1; then
    info "Adding github.com to $SSH_DIR/known_hosts..."
    ssh-keyscan -t ed25519,rsa github.com >>"$SSH_DIR/known_hosts" 2>/dev/null || warn "Could not fetch GitHub host keys."
    chmod 644 "$SSH_DIR/known_hosts"
  else
    warn "ssh-keyscan not found; skip adding github.com to known_hosts."
  fi
fi

# --- Git submodules -----------------------------------------------------------

if [[ -d "$ROOT/.git" ]]; then
  if [[ -f "$ROOT/.gitmodules" ]] && grep -q 'path = devenv' "$ROOT/.gitmodules" 2>/dev/null; then
    warn "The legacy devenv submodule is deprecated and will not be initialized."
    warn "Remove the devenv submodule from .gitmodules when you are ready."
  fi

  other_submodules="$(git config -f "$ROOT/.gitmodules" --get-regexp path 2>/dev/null | awk '{print $2}' | grep -v '^devenv$' || true)"
  if [[ -n "$other_submodules" ]]; then
    info "Initializing git submodules (excluding devenv)..."
    while IFS= read -r submodule_path; do
      git submodule update --init --recursive "$submodule_path"
    done <<<"$other_submodules"
  fi
else
  warn "Not a git repository; skipping submodule initialization."
fi

# --- Agent skills -------------------------------------------------------------

if [[ ! -f "$ROOT/skills-lock.json" ]]; then
  die "skills-lock.json not found in $ROOT"
fi

info "Installing agent skills from skills-lock.json..."
npx --yes skills experimental_install

# --- Done ---------------------------------------------------------------------

cat <<EOF

[init] Host setup complete.

Next steps:
  1. Clone module workspaces into repos/ (if you have not already).
  2. Open this folder in Cursor.
  3. Run "Dev Containers: Reopen in Container" to build and enter the sandbox.

Inside the devcontainer:
  - Workspace root is /repos (host repos/).
  - Host services are reached via host.docker.internal, not localhost.
  - Docker commands must be run on the host, outside the container.

EOF
