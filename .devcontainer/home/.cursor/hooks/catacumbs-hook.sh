#!/usr/bin/env bash
# Catacumbs hook entrypoint — exec python3 guard|audit with hook name from CATACUMBS_HOOK.
set -euo pipefail

MODE="${1:-}"
if [ -z "$MODE" ]; then
  printf '%s\n' '{"permission":"deny","user_message":"Catacumbs hook entrypoint: missing mode (guard|audit)."}'
  exit 1
fi

SCRIPT=""
for p in .cursor/hooks/catacumbs_guard.py ~/.cursor/hooks/catacumbs_guard.py; do
  if [ -f "$p" ]; then
    SCRIPT="$p"
    break
  fi
done

if [ -z "$SCRIPT" ]; then
  case "$MODE" in
    audit) printf '%s\n' '{}' ;;
    *) printf '%s\n' '{"permission":"deny","user_message":"Catacumbs guard Python module not found."}' ;;
  esac
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  case "$MODE" in
    audit) printf '%s\n' '{}' ;;
    *) printf '%s\n' '{"permission":"deny","user_message":"Catacumbs security guard requires python3."}' ;;
  esac
  exit 1
fi

exec python3 "$SCRIPT" "$MODE"
