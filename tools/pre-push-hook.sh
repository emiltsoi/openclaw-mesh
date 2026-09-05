#!/usr/bin/env bash
# Pre-push hook — refuse to push if the local gate fails.
# Language-aware: routes to the repo's actual toolchain.
#   - Python repo (.venv/bin/python3 present): ruff check . + pytest (mirrors Python CI)
#   - TypeScript repo (package.json + tsconfig): npm run typecheck + npm test (mirrors TS CI)
#   - Neither: pass-through (nothing to gate locally).
# Install: cp tools/pre-push-hook.sh .git/hooks/pre-push && chmod +x .git/hooks/pre-push
# NOTE: hooks are executed from the repo root by git, but $0 is .git/hooks/pre-push.
# Resolve the repo root via `git rev-parse`, never via $0/dirname.
set -euo pipefail

echo "── pre-push gate (language-aware) ──"
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if [ -f "$REPO_ROOT/pyproject.toml" ]; then
  # --- Python repo ---
  # Prefer the repo-root venv; fall back to any python3 (system or env) so
  # repos without a root .venv (hermes-mesh, mesh-peer-registry) still gate.
  VENV_PY=""
  if [ -x "$REPO_ROOT/.venv/bin/python3" ]; then
    VENV_PY="$REPO_ROOT/.venv/bin/python3"
  elif command -v python3 >/dev/null 2>&1; then
    VENV_PY="$(command -v python3)"
  fi
  if [ -z "$VENV_PY" ]; then
    echo "ℹ no python3 found — skipping local Python gate (CI is the gate)"
    exit 0
  fi
  echo "  (python: $VENV_PY)"
  # If the toolchain deps aren't installed in this python, there's nothing
  # faithful to run locally — CI is the real gate (hermes-mesh/mesh-peer-registry
  # install per-run in CI). Soft-skip rather than hard-block on missing deps.
  if ! "$VENV_PY" -c "import ruff, pytest" >/dev/null 2>&1; then
    echo "ℹ ruff/pytest not installed in $VENV_PY — skipping local Python gate (CI is the gate)"
    exit 0
  fi
  echo "[1/2] ruff check ."
  if ! "$VENV_PY" -m ruff check . 2>&1; then
    echo "✖ ruff FAILED — push blocked. Fix lint before pushing." >&2
    exit 1
  fi
  echo "  ✔ ruff clean"
  echo "[2/2] pytest (full suite)"
  if ! "$VENV_PY" -m pytest -q 2>&1 | tail -5; then
    echo "✖ pytest FAILED — push blocked. Fix tests before pushing." >&2
    exit 1
  fi
  echo "✔ pre-push gate PASSED (python)"
  exit 0
fi

if [ -f "$REPO_ROOT/package.json" ] && [ -f "$REPO_ROOT/tsconfig.json" ]; then
  # --- TypeScript repo ---
  # npm may be absent (node not installed) — then there is nothing to run locally.
  if command -v npm >/dev/null 2>&1; then
    echo "[1/2] npm run typecheck"
    if ! npm run typecheck 2>&1; then
      echo "✖ typecheck FAILED — push blocked. Fix types before pushing." >&2
      exit 1
    fi
    echo "  ✔ typecheck clean"
    echo "[2/2] npm test (full suite)"
    if ! npm test 2>&1 | tail -8; then
      echo "✖ npm test FAILED — push blocked. Fix tests before pushing." >&2
      exit 1
    fi
    echo "✔ pre-push gate PASSED (typescript)"
    exit 0
  fi
  echo "ℹ npm not found — skipping local TS gate (CI is the gate)"
  exit 0
fi

echo "ℹ no Python venv or package.json — nothing to gate locally, passing"
exit 0
