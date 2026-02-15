#!/bin/bash
#
# APF Smoke Test Runner
# Usage: ./tests/run-tests.sh [--os OS] [bats args...]
# Examples:
#   ./tests/run-tests.sh                                 # Run all tests (Debian 12)
#   ./tests/run-tests.sh --os rocky9                     # Run on Rocky Linux 9
#   ./tests/run-tests.sh --os ubuntu2404                 # Run on Ubuntu 24.04
#   ./tests/run-tests.sh --filter "install"              # Filter by name
#   ./tests/run-tests.sh /opt/tests/04-trust-system.bats # Specific file
#
# Supported OS values:
#   debian12     Debian 12 slim (default)
#   centos6      CentOS 6 (EOL, iptables-legacy, SysV init)
#   centos7      CentOS 7 (EOL, iptables-legacy, systemd)
#   rocky8       Rocky Linux 8 (iptables-nft, systemd)
#   rocky9       Rocky Linux 9 (iptables-nft, systemd)
#   rocky10      Rocky Linux 10 (iptables-nft, systemd)
#   ubuntu1604   Ubuntu 16.04 LTS (EOL, iptables-legacy)
#   ubuntu1804   Ubuntu 18.04 LTS (EOL, iptables-legacy)
#   ubuntu2004   Ubuntu 20.04 LTS (iptables-nft)
#   ubuntu2204   Ubuntu 22.04 LTS (iptables-nft)
#   ubuntu2404   Ubuntu 24.04 LTS (iptables-nft)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Parse --os flag
OS="debian12"
if [ "$1" = "--os" ]; then
    OS="$2"
    shift 2
fi

# Map OS to Dockerfile
case "$OS" in
    debian12)
        DOCKERFILE="$SCRIPT_DIR/Dockerfile"
        ;;
    centos6)
        DOCKERFILE="$SCRIPT_DIR/Dockerfile.centos6"
        ;;
    centos7)
        DOCKERFILE="$SCRIPT_DIR/Dockerfile.centos7"
        ;;
    rocky8)
        DOCKERFILE="$SCRIPT_DIR/Dockerfile.rocky8"
        ;;
    rocky9)
        DOCKERFILE="$SCRIPT_DIR/Dockerfile.rocky9"
        ;;
    rocky10)
        DOCKERFILE="$SCRIPT_DIR/Dockerfile.rocky10"
        ;;
    ubuntu1604)
        DOCKERFILE="$SCRIPT_DIR/Dockerfile.ubuntu1604"
        ;;
    ubuntu1804)
        DOCKERFILE="$SCRIPT_DIR/Dockerfile.ubuntu1804"
        ;;
    ubuntu2004)
        DOCKERFILE="$SCRIPT_DIR/Dockerfile.ubuntu2004"
        ;;
    ubuntu2204)
        DOCKERFILE="$SCRIPT_DIR/Dockerfile.ubuntu2204"
        ;;
    ubuntu2404)
        DOCKERFILE="$SCRIPT_DIR/Dockerfile.ubuntu2404"
        ;;
    *)
        echo "Unknown OS: $OS"
        echo "Supported: debian12, centos6, centos7, rocky8, rocky9, rocky10,"
        echo "           ubuntu1604, ubuntu1804, ubuntu2004, ubuntu2204, ubuntu2404"
        exit 1
        ;;
esac

if [ ! -f "$DOCKERFILE" ]; then
    echo "Dockerfile not found: $DOCKERFILE"
    exit 1
fi

IMAGE_NAME="apf-smoke-test-${OS}"

echo "Building APF smoke test image ($OS)..."
docker build -f "$DOCKERFILE" -t "$IMAGE_NAME" "$PROJECT_DIR"

echo "Running tests on $OS..."
if [ $# -eq 0 ]; then
    # No args: use default CMD (all tests, tap format)
    docker run --rm --privileged "$IMAGE_NAME"
else
    # Custom args: user must provide test path if overriding
    docker run --rm --privileged "$IMAGE_NAME" bats "$@"
fi
