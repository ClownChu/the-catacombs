#!/usr/bin/env bash
# Catacombs hook entrypoint — exec python3 guard|audit with hook name from CATACOMBS_HOOK.
set -euo pipefail

if [ ! -e /etc/catacombs-container ]; then
  case "${1:-}" in
    audit) printf '%s\n' '{}' ;;
    *) printf '%s\n' '{"permission":"allow"}' ;;
  esac
  exit 0
fi

MODE="${1:-}"
if [ -z "$MODE" ]; then
  printf '%s\n' '{"permission":"deny","user_message":"Catacombs hook entrypoint: missing mode (guard|audit)."}'
  exit 1
fi

_hooks_disabled_by_config() {
  command -v python3 >/dev/null 2>&1 || return 1
  local cfg hook_dir
  hook_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  for cfg in \
    "/home/agent/.cursor/catacombs-security.json" \
    "${hook_dir}/catacombs-security.json"; do
    if [ -f "$cfg" ]; then
      python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("enabled") is False else 1)' "$cfg" 2>/dev/null
      return $?
    fi
  done
  return 1
}

if _hooks_disabled_by_config; then
  case "$MODE" in
    audit) printf '%s\n' '{}' ;;
    *) printf '%s\n' '{"permission":"allow"}' ;;
  esac
  exit 0
fi

SCRIPT=""
for p in \
  "/home/agent/.cursor/hooks/catacombs_guard.py" \
  "./.cursor/hooks/catacombs_guard.py"; do
  if [ -f "$p" ]; then
    SCRIPT="$p"
    break
  fi
done

if [ -z "$SCRIPT" ]; then
  case "$MODE" in
    audit) printf '%s\n' '{}' ;;
    *) printf '%s\n' '{"permission":"deny","user_message":"Catacombs guard Python module not found."}' ;;
  esac
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  case "$MODE" in
    audit) printf '%s\n' '{}' ;;
    *) printf '%s\n' '{"permission":"deny","user_message":"Catacombs security guard requires python3."}' ;;
  esac
  exit 1
fi

exec python3 "$SCRIPT" "$MODE"
