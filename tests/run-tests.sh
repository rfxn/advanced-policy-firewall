#!/bin/bash
#
# APF Smoke Test Runner
# Usage: ./tests/run-tests.sh [bats args...]
# Examples:
#   ./tests/run-tests.sh                            # Run all tests
#   ./tests/run-tests.sh --filter "install"          # Filter by name
#   ./tests/run-tests.sh /opt/tests/04-trust-system.bats  # Specific file
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE_NAME="apf-smoke-test"

echo "Building APF smoke test image..."
docker build -f "$SCRIPT_DIR/Dockerfile" -t "$IMAGE_NAME" "$PROJECT_DIR"

echo "Running tests..."
if [ $# -eq 0 ]; then
    # No args: use default CMD (all tests, tap format)
    docker run --rm --privileged "$IMAGE_NAME"
else
    # Custom args: user must provide test path if overriding
    docker run --rm --privileged "$IMAGE_NAME" bats "$@"
fi
