#!/usr/bin/env bash
# Regenerate the three fixed demo scenarios (keys are derived from fixed
# seeds, so output is deterministic). Re-run this and rebuild the server to
# pick up changed embedded files.
set -euo pipefail
cd "$(dirname "$0")/../backend"
exec go run ./cmd/gendemo ./internal/demo/demodata
