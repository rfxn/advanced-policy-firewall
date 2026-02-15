#!/usr/bin/env bats
#
# 16: Dependency Checking — check_deps() validates critical/optional binaries
#
# Tests temporarily hide binaries by renaming them, then restore in teardown.
# All tests run inside Docker with --privileged.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

# Track hidden binaries for cleanup
HIDDEN_BINS=""

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

# Hide a binary by renaming all instances across PATH until unfindable.
# Uses APF's PATH to ensure the binary is hidden from APF's perspective.
hide_bin() {
    local name="$1"
    local bin_path
    local search_path="/sbin:/usr/sbin:/usr/bin:/bin:/usr/local/sbin:/usr/local/bin:$PATH"
    while bin_path=$(PATH="$search_path" command -v "$name" 2>/dev/null) && [ -n "$bin_path" ]; do
        if [ -f "$bin_path" ] && [ ! -f "${bin_path}.__hidden" ]; then
            mv "$bin_path" "${bin_path}.__hidden"
            HIDDEN_BINS="$HIDDEN_BINS $bin_path"
        else
            break
        fi
    done
}

# Restore all hidden binaries
restore_bins() {
    for bin_path in $HIDDEN_BINS; do
        if [ -f "${bin_path}.__hidden" ]; then
            mv "${bin_path}.__hidden" "$bin_path"
        fi
    done
    HIDDEN_BINS=""
}

teardown() {
    restore_bins
}

@test "apf -s succeeds with all dependencies present" {
    run "$APF" -s
    assert_success
    "$APF" -f 2>/dev/null || true
}

@test "detects missing iptables" {
    hide_bin iptables
    run "$APF" -s
    assert_failure
    assert_output --partial "iptables"
    assert_output --partial "missing critical dependencies"
}

@test "detects missing ip" {
    hide_bin ip
    run "$APF" -s
    assert_failure
    assert_output --partial "iproute"
    assert_output --partial "missing critical dependencies"
}

@test "skips modprobe check when SET_MONOKERN=1" {
    # Our test environment has SET_MONOKERN=1, so hiding modprobe should be fine
    hide_bin modprobe
    run "$APF" -s
    assert_success
    "$APF" -f 2>/dev/null || true
}

@test "warns on missing wget when DLIST enabled" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DLIST_PHP" "1"
    hide_bin wget
    run "$APF" -s
    # Should still succeed (warning, not critical)
    assert_success
    # Check log for warning
    run grep "missing optional dependencies.*wget" /var/log/apf_log
    assert_success
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
}

@test "requires ip6tables when USE_IPV6=1" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_IPV6" "1"
    hide_bin ip6tables
    hide_bin ip6tables-save
    hide_bin ip6tables-restore
    run "$APF" -s
    assert_failure
    assert_output --partial "ip6tables"
    assert_output --partial "missing critical dependencies"
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
}

@test "correct install hint for package manager" {
    hide_bin iptables
    run "$APF" -s
    assert_failure
    # Should show apt-get on Debian/Ubuntu or dnf/yum on RHEL
    if command -v apt-get > /dev/null 2>&1; then
        assert_output --partial "apt-get install"
    elif command -v dnf > /dev/null 2>&1; then
        assert_output --partial "dnf install"
    elif command -v yum > /dev/null 2>&1; then
        assert_output --partial "yum install"
    elif command -v microdnf > /dev/null 2>&1; then
        assert_output --partial "microdnf install"
    fi
}

@test "apf -f works without dependency check" {
    run "$APF" -f
    refute_output --partial "missing critical dependencies"
}

@test "apf -l works without dependency check" {
    run "$APF" -l
    refute_output --partial "missing critical dependencies"
}
