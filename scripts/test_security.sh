#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

case "${1:-}" in
    "") make test-security ;;
    --kernel)
        shift
        exec "$SCRIPT_DIR/test_kernel.sh" "$@"
        ;;
    *)
        echo "Usage: $0 [--kernel]" >&2
        exit 1
        ;;
esac
