#!/bin/bash
#
# APF Smoke Test Runner — batsman integration wrapper
# Usage: ./tests/run-tests.sh [--os OS] [--parallel [N]] [bats args...]
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BATSMAN_PROJECT="apf"
BATSMAN_PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BATSMAN_TESTS_DIR="$SCRIPT_DIR"
BATSMAN_INFRA_DIR="$SCRIPT_DIR/infra"
BATSMAN_DOCKER_FLAGS="--privileged"
BATSMAN_DEFAULT_OS="debian12"
BATSMAN_CONTAINER_TEST_PATH="/opt/tests"
BATSMAN_SUPPORTED_OS="debian12 centos6 centos7 rocky8 rocky9 rocky10 ubuntu1204 ubuntu2004 ubuntu2404"

source "$BATSMAN_INFRA_DIR/lib/run-tests-core.sh"
batsman_run "$@"
