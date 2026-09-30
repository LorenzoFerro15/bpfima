#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"
make test-security

case "${1:-}" in
    "") ;;
    --kernel)
        make security-regression
        exec "$PROJECT_ROOT/build/security-regression" \
            "$PROJECT_ROOT/build/security-regression.bpf.o" "$PROJECT_ROOT/build"
        ;;
    *)
        echo "Usage: $0 [--kernel]" >&2
        exit 1
        ;;
esac
