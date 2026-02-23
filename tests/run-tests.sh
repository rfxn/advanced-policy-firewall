#!/bin/bash
#
# APF Smoke Test Runner
# Usage: ./tests/run-tests.sh [--os OS] [--parallel [N]] [bats args...]
# Examples:
#   ./tests/run-tests.sh                                 # Run all tests (Debian 12, parallel)
#   ./tests/run-tests.sh --os rocky9                     # Run on Rocky Linux 9
#   ./tests/run-tests.sh --parallel                      # Parallel (nproc*2 containers)
#   ./tests/run-tests.sh --parallel 4                    # Parallel with 4 containers
#   ./tests/run-tests.sh --filter "install"              # Filter by name
#   ./tests/run-tests.sh /opt/tests/04-trust-system.bats # Specific file
#
# Supported OS values (CI matrix marked with *):
#   debian12     * Debian 12 slim (default, nft backend)
#   centos6        CentOS 6 (EOL, legacy backend, vault repos)
#   centos7      * CentOS 7 (EOL, legacy backend)
#   rocky8       * Rocky Linux 8 (nft backend)
#   rocky9       * Rocky Linux 9 (nft backend)
#   rocky10        Rocky Linux 10 (nft backend, pending stable)
#   ubuntu1204     Ubuntu 12.04 (EOL, legacy backend, old-releases repos)
#   ubuntu2004   * Ubuntu 20.04 LTS (nft backend)
#   ubuntu2204   * Ubuntu 22.04 LTS (nft backend)
#   ubuntu2404   * Ubuntu 24.04 LTS (nft backend)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Parse flags
OS="debian12"
PARALLEL=0
PARALLEL_N=0
while [ $# -gt 0 ]; do
    case "$1" in
        --os)
            OS="$2"
            shift 2
            ;;
        --parallel)
            PARALLEL=1
            # Check if next arg is a number (optional N)
            if [ $# -ge 2 ] && [[ "$2" =~ ^[0-9]+$ ]]; then
                PARALLEL_N="$2"
                shift 2
            else
                shift
            fi
            ;;
        *)
            break
            ;;
    esac
done

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
    ubuntu1204)
        DOCKERFILE="$SCRIPT_DIR/Dockerfile.ubuntu1204"
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
        echo "Supported: debian12, centos6, centos7, rocky8, rocky9, rocky10, ubuntu1204, ubuntu2004, ubuntu2204, ubuntu2404"
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

# If specific test file(s) passed as args, run directly (no parallel)
if [ $# -gt 0 ]; then
    echo "Running tests on $OS..."
    docker run --rm --privileged "$IMAGE_NAME" bats "$@"
    exit $?
fi

# Sequential mode (no --parallel)
if [ "$PARALLEL" -eq 0 ]; then
    echo "Running tests on $OS..."
    docker run --rm --privileged "$IMAGE_NAME"
    exit $?
fi

# --- Parallel mode ---

# Determine number of parallel groups
if [ "$PARALLEL_N" -gt 0 ]; then
    NUM_GROUPS="$PARALLEL_N"
else
    NUM_GROUPS=$(( $(nproc) * 2 ))
    [ "$NUM_GROUPS" -lt 1 ] && NUM_GROUPS=1
fi

# Discover test files (sorted by name)
TEST_FILES=()
while IFS= read -r f; do
    TEST_FILES+=("$f")
done < <(ls "$SCRIPT_DIR"/[0-9]*.bats 2>/dev/null | sort)

NUM_FILES=${#TEST_FILES[@]}
if [ "$NUM_FILES" -eq 0 ]; then
    echo "No test files found"
    exit 1
fi

# Cap groups at number of files
[ "$NUM_GROUPS" -gt "$NUM_FILES" ] && NUM_GROUPS="$NUM_FILES"

# Round-robin distribute files into groups
declare -a GROUP_FILES
for i in $(seq 0 $(( NUM_GROUPS - 1 ))); do
    GROUP_FILES[$i]=""
done

for i in $(seq 0 $(( NUM_FILES - 1 ))); do
    group=$(( i % NUM_GROUPS ))
    fname="$(basename "${TEST_FILES[$i]}")"
    container_path="/opt/tests/$fname"
    if [ -z "${GROUP_FILES[$group]}" ]; then
        GROUP_FILES[$group]="$container_path"
    else
        GROUP_FILES[$group]="${GROUP_FILES[$group]} $container_path"
    fi
done

# Create temp dir for output
TMPDIR_PAR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_PAR"' EXIT

echo "Running tests on $OS (parallel: $NUM_GROUPS groups, $NUM_FILES files)..."
START_TIME=$SECONDS

# Launch containers in parallel
PIDS=()
for i in $(seq 0 $(( NUM_GROUPS - 1 ))); do
    # shellcheck disable=SC2086
    docker run --rm --privileged "$IMAGE_NAME" \
        bats --formatter tap ${GROUP_FILES[$i]} \
        > "$TMPDIR_PAR/group-$i.tap" 2>&1 &
    PIDS+=($!)
done

# Wait for all containers, collect exit codes
FAILED_GROUPS=0
EXIT_CODES=()
for i in $(seq 0 $(( NUM_GROUPS - 1 ))); do
    if wait "${PIDS[$i]}"; then
        EXIT_CODES[$i]=0
    else
        EXIT_CODES[$i]=1
        FAILED_GROUPS=$(( FAILED_GROUPS + 1 ))
    fi
done

ELAPSED=$(( SECONDS - START_TIME ))

# Display output with group headers
TOTAL_TESTS=0
TOTAL_PASS=0
TOTAL_FAIL=0
for i in $(seq 0 $(( NUM_GROUPS - 1 ))); do
    # Build short file list for header
    short_names=""
    for f in ${GROUP_FILES[$i]}; do
        name="$(basename "$f" .bats)"
        if [ -z "$short_names" ]; then
            short_names="$name"
        else
            short_names="$short_names $name"
        fi
    done

    status="PASS"
    [ "${EXIT_CODES[$i]}" -ne 0 ] && status="FAIL"

    echo ""
    echo "=== Group $((i+1))/$NUM_GROUPS [$status]: $short_names ==="
    cat "$TMPDIR_PAR/group-$i.tap"

    # Count tests from TAP output
    while IFS= read -r line; do
        case "$line" in
            ok\ *)
                TOTAL_TESTS=$(( TOTAL_TESTS + 1 ))
                TOTAL_PASS=$(( TOTAL_PASS + 1 ))
                ;;
            not\ ok\ *)
                TOTAL_TESTS=$(( TOTAL_TESTS + 1 ))
                TOTAL_FAIL=$(( TOTAL_FAIL + 1 ))
                ;;
        esac
    done < "$TMPDIR_PAR/group-$i.tap"
done

echo ""
PASSED_GROUPS=$(( NUM_GROUPS - FAILED_GROUPS ))
echo "=== Results: $PASSED_GROUPS/$NUM_GROUPS groups passed ($TOTAL_TESTS tests, $TOTAL_FAIL failed) in ${ELAPSED}s ==="

[ "$FAILED_GROUPS" -gt 0 ] && exit 1
exit 0
