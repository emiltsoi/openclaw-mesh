#!/usr/bin/env bash
#
# Sandboxed test launcher for openclaw-mesh.
#
# Why: several suites drive real delivery failure/success paths through
# `sendToAgent` and key generation without an explicit `outboxDir`/
# `privateKeyPath`. Those defaults resolve at call time to:
#   - outbox  -> $OPENCLAW_STATE_DIR/mesh/outbox  (else ~/.openclaw/state/mesh/outbox)
#   - keypair -> ~/.mesh/keys/<name>.pem
# so running the suite from a live agent shell appends fixture failed-send
# records into the REAL outbox and can mint fixture keys into the REAL
# ~/.mesh/keys. This launcher points HOME and OPENCLAW_STATE_DIR at a
# throwaway dir for the duration of the run, so nothing a test writes can
# reach the live state. Compilation is unaffected (tsc does not touch HOME).
#
# Usage:  bash scripts/run-tests.sh [extra node --test args...]
set -euo pipefail
cd "$(dirname "$0")/.."

SB="$(mktemp -d "${TMPDIR:-/tmp}/openclaw-mesh-test.XXXXXX")"
cleanup() { rm -rf "$SB"; }
trap cleanup EXIT

export HOME="$SB/home"
export OPENCLAW_STATE_DIR="$SB/state"
mkdir -p "$HOME" "$OPENCLAW_STATE_DIR"

echo "openclaw-mesh tests: sandbox HOME=$HOME OPENCLAW_STATE_DIR=$OPENCLAW_STATE_DIR"
node --test dist-test/test/*.test.js "$@"
