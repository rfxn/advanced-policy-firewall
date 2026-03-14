#!/usr/bin/env bats
#
# 38: CT_LIMIT — connection tracking limit scanner, cron, CLI, validation.
#
# Uses synthetic /proc/net/nf_conntrack fixtures for unit tests.
# Integration tests start the firewall and exercise CLI commands.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash
source /opt/tests/helpers/capability-detect.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"
# Fixed fixture path — avoids BATS variable propagation issues
CT_FIXTURE_DIR="/tmp/ct-fixtures"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""

    # Create conntrack fixture directory
    rm -rf "$CT_FIXTURE_DIR"
    mkdir -p "$CT_FIXTURE_DIR"

    # Generate synthetic /proc/net/nf_conntrack data
    # 200 entries from 192.0.2.50 (will exceed threshold)
    # 50 entries from 198.51.100.1 (under threshold)
    # 10 entries from 127.0.0.1 (loopback, exempt)
    # 5 entries from 2001:db8::50 (IPv6 test)
    local f="$CT_FIXTURE_DIR/nf_conntrack"
    true > "$f"
    local i
    for i in $(seq 1 200); do
        echo "ipv4     2 tcp      6 300 ESTABLISHED src=192.0.2.50 dst=10.0.0.1 sport=1$i dport=80 src=10.0.0.1 dst=192.0.2.50 sport=80 dport=1$i [ASSURED] mark=0 use=2" >> "$f"
    done
    for i in $(seq 1 50); do
        echo "ipv4     2 tcp      6 300 ESTABLISHED src=198.51.100.1 dst=10.0.0.1 sport=2$i dport=443 src=10.0.0.1 dst=198.51.100.1 sport=443 dport=2$i [ASSURED] mark=0 use=2" >> "$f"
    done
    for i in $(seq 1 10); do
        echo "ipv4     2 tcp      6 300 ESTABLISHED src=127.0.0.1 dst=127.0.0.1 sport=3$i dport=80 src=127.0.0.1 dst=127.0.0.1 sport=80 dport=3$i [ASSURED] mark=0 use=2" >> "$f"
    done
    for i in $(seq 1 5); do
        echo "ipv6     10 tcp     6 300 ESTABLISHED src=2001:db8::50 dst=2001:db8::1 sport=4$i dport=80 src=2001:db8::1 dst=2001:db8::50 sport=80 dport=4$i [ASSURED] mark=0 use=2" >> "$f"
    done

    # Generate port-filtered fixture (some on port 80, some on port 443)
    local fp="$CT_FIXTURE_DIR/nf_conntrack_ports"
    true > "$fp"
    for i in $(seq 1 100); do
        echo "ipv4     2 tcp      6 300 ESTABLISHED src=192.0.2.60 dst=10.0.0.1 sport=5$i dport=80 src=10.0.0.1 dst=192.0.2.60 sport=80 dport=5$i [ASSURED] mark=0 use=2" >> "$fp"
    done
    for i in $(seq 1 100); do
        echo "ipv4     2 tcp      6 300 ESTABLISHED src=192.0.2.60 dst=10.0.0.1 sport=6$i dport=443 src=10.0.0.1 dst=192.0.2.60 sport=443 dport=6$i [ASSURED] mark=0 use=2" >> "$fp"
    done

    # Generate TIME_WAIT fixture
    local ft="$CT_FIXTURE_DIR/nf_conntrack_tw"
    true > "$ft"
    for i in $(seq 1 150); do
        echo "ipv4     2 tcp      6 5 TIME_WAIT src=192.0.2.70 dst=10.0.0.1 sport=7$i dport=80 src=10.0.0.1 dst=192.0.2.70 sport=80 dport=7$i [ASSURED] mark=0 use=2" >> "$ft"
    done
    for i in $(seq 1 50); do
        echo "ipv4     2 tcp      6 300 ESTABLISHED src=192.0.2.70 dst=10.0.0.1 sport=8$i dport=80 src=10.0.0.1 dst=192.0.2.70 sport=80 dport=8$i [ASSURED] mark=0 use=2" >> "$ft"
    done

    # Start firewall for integration tests
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
    rm -rf "$CT_FIXTURE_DIR"
}

teardown() {
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
}

# Helper: source ctlimit.apf with minimal variable setup (no conf.apf sourcing)
_source_ctlimit() {
    # Set only the variables that ctlimit.apf needs
    INSTALL_PATH="$APF_DIR"
    ALLOW_HOSTS="$APF_DIR/allow_hosts.rules"
    DENY_HOSTS="$APF_DIR/deny_hosts.rules"
    IFACE_TRUSTED=""
    SET_VNET="0"
    CT_SKIP=""
    ip=$(command -v ip 2>/dev/null)
    # Source just functions.apf temp file helpers
    eval "$(sed -n '/^_apf_reg_tmp()/,/^}/p' "$APF_DIR/internals/functions.apf")"
    _APF_TMPFILES=""
    _APF_CTLIMIT_LOADED=""
    source "$APF_DIR/internals/ctlimit.apf"
}

# ---- Unit tests: awk counting ----

@test "awk counter: counts 200 connections from 192.0.2.50" {
    _source_ctlimit

    local exempt_tmp
    exempt_tmp=$(mktemp)
    echo "127.0.0.0/8" > "$exempt_tmp"

    local result
    result=$(_ct_count_ips "$exempt_tmp" "100" "" "" "0" < "$CT_FIXTURE_DIR/nf_conntrack")
    rm -f "$exempt_tmp"

    echo "$result" | grep -q "200 192.0.2.50"
}

@test "awk counter: 198.51.100.1 under threshold (50 < 100)" {
    _source_ctlimit

    local exempt_tmp
    exempt_tmp=$(mktemp)
    echo "127.0.0.0/8" > "$exempt_tmp"

    local result
    result=$(_ct_count_ips "$exempt_tmp" "100" "" "" "0" < "$CT_FIXTURE_DIR/nf_conntrack")
    rm -f "$exempt_tmp"

    # 198.51.100.1 has 50 conns, threshold 100 — should NOT appear
    ! echo "$result" | grep -q "198.51.100.1"
}

@test "awk counter: loopback (127.0.0.1) is exempt" {
    _source_ctlimit

    local exempt_tmp
    exempt_tmp=$(mktemp)
    echo "127.0.0.0/8" > "$exempt_tmp"

    local result
    result=$(_ct_count_ips "$exempt_tmp" "1" "" "" "0" < "$CT_FIXTURE_DIR/nf_conntrack")
    rm -f "$exempt_tmp"

    # 127.0.0.1 has 10 conns but should be exempt
    ! echo "$result" | grep -q "127.0.0.1"
}

@test "awk counter: port filter counts only matching ports" {
    _source_ctlimit

    local exempt_tmp
    exempt_tmp=$(mktemp)
    echo "127.0.0.0/8" > "$exempt_tmp"

    # Only count port 80 — 192.0.2.60 has 100 on port 80, 100 on port 443
    local result
    result=$(_ct_count_ips "$exempt_tmp" "50" "80" "" "0" < "$CT_FIXTURE_DIR/nf_conntrack_ports")
    rm -f "$exempt_tmp"

    # Should show 100 connections (port 80 only), which exceeds threshold 50
    echo "$result" | grep -q "100 192.0.2.60"
}

@test "awk counter: TIME_WAIT skip reduces count" {
    _source_ctlimit

    local exempt_tmp
    exempt_tmp=$(mktemp)
    echo "127.0.0.0/8" > "$exempt_tmp"

    # Without TIME_WAIT skip: 200 total (150 TW + 50 ESTABLISHED) > threshold 100
    local result_all
    result_all=$(_ct_count_ips "$exempt_tmp" "100" "" "" "0" < "$CT_FIXTURE_DIR/nf_conntrack_tw")
    echo "$result_all" | grep -q "200 192.0.2.70"

    # With TIME_WAIT skip: only 50 ESTABLISHED < threshold 100
    local result_skip
    result_skip=$(_ct_count_ips "$exempt_tmp" "100" "" "" "1" < "$CT_FIXTURE_DIR/nf_conntrack_tw")
    rm -f "$exempt_tmp"

    ! echo "$result_skip" | grep -q "192.0.2.70"
}

@test "awk counter: CIDR exemption works" {
    _source_ctlimit

    local exempt_tmp
    exempt_tmp=$(mktemp)
    echo "127.0.0.0/8" > "$exempt_tmp"
    echo "192.0.2.0/24" >> "$exempt_tmp"

    local result
    result=$(_ct_count_ips "$exempt_tmp" "1" "" "" "0" < "$CT_FIXTURE_DIR/nf_conntrack")
    rm -f "$exempt_tmp"

    # 192.0.2.50 should be exempt via CIDR
    ! echo "$result" | grep -q "192.0.2.50"
}

@test "awk counter: IPv6 addresses are counted" {
    _source_ctlimit

    local exempt_tmp
    exempt_tmp=$(mktemp)
    echo "127.0.0.0/8" > "$exempt_tmp"

    local result
    result=$(_ct_count_ips "$exempt_tmp" "1" "" "" "0" < "$CT_FIXTURE_DIR/nf_conntrack")
    rm -f "$exempt_tmp"

    # 2001:db8::50 has 5 connections, threshold 1 — should appear
    echo "$result" | grep -q "2001:db8::50"
}

@test "awk counter: exact IP exemption works" {
    _source_ctlimit

    local exempt_tmp
    exempt_tmp=$(mktemp)
    echo "127.0.0.0/8" > "$exempt_tmp"
    echo "192.0.2.50" >> "$exempt_tmp"

    local result
    result=$(_ct_count_ips "$exempt_tmp" "1" "" "" "0" < "$CT_FIXTURE_DIR/nf_conntrack")
    rm -f "$exempt_tmp"

    ! echo "$result" | grep -q "192.0.2.50"
}

# ---- Integration tests: CLI and cron ----

@test "--ct-status shows config when disabled" {
    run "$APF" --ct-status
    assert_success
    assert_output --partial "CT_LIMIT=0"
    assert_output --partial "max connections per IP"
}

@test "--ct-scan shows disabled message when CT_LIMIT=0" {
    run "$APF" --ct-scan
    assert_success
    assert_output --partial "CT_LIMIT not enabled"
}

@test "cron created on start when CT_LIMIT enabled" {
    [[ -d /etc/cron.d ]] || skip "no /etc/cron.d directory"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "CT_LIMIT" "100"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    [[ -f /etc/cron.d/ctlimit.apf ]]
    grep -q "ct-scan" /etc/cron.d/ctlimit.apf
}

@test "cron removed on flush" {
    [[ -d /etc/cron.d ]] || skip "no /etc/cron.d directory"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "CT_LIMIT" "100"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    [[ -f /etc/cron.d/ctlimit.apf ]]
    "$APF" -f
    [[ ! -f /etc/cron.d/ctlimit.apf ]]
}

@test "cron not created when CT_LIMIT disabled" {
    [[ -d /etc/cron.d ]] || skip "no /etc/cron.d directory"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "CT_LIMIT" "0"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    [[ ! -f /etc/cron.d/ctlimit.apf ]]
}

# ---- Validation tests ----

@test "validate_config rejects non-integer CT_LIMIT" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "CT_LIMIT" "abc"
    run "$APF" -s
    assert_failure
    assert_output --partial "CT_LIMIT"
}

@test "validate_config rejects CT_INTERVAL=0 when CT_LIMIT enabled" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "CT_LIMIT" "100"
    apf_set_config "CT_INTERVAL" "0"
    run "$APF" -s
    assert_failure
    assert_output --partial "CT_INTERVAL"
}

@test "validate_config rejects CT_BLOCK_TIME=0 when CT_LIMIT enabled" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "CT_LIMIT" "100"
    apf_set_config "CT_BLOCK_TIME" "0"
    run "$APF" -s
    assert_failure
    assert_output --partial "CT_BLOCK_TIME"
}

@test "validate_config passes with valid CT_LIMIT config" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "CT_LIMIT" "200"
    apf_set_config "CT_INTERVAL" "60"
    apf_set_config "CT_BLOCK_TIME" "1800"
    "$APF" -f 2>/dev/null || true
    run "$APF" -s
    assert_success
}

@test "validate_config skips CT validation when disabled" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "CT_LIMIT" "0"
    apf_set_config "CT_INTERVAL" "invalid"
    "$APF" -f 2>/dev/null || true
    run "$APF" -s
    # Should not fail — CT_INTERVAL validation only triggers when CT_LIMIT > 0
    assert_success
}

@test "ct_enabled returns true when CT_LIMIT > 0" {
    # Source just the function definition
    eval "$(sed -n '/^ct_enabled()/,/^}/p' "$APF_DIR/internals/functions.apf")"
    CT_LIMIT="100"
    ct_enabled
}

@test "ct_enabled returns false when CT_LIMIT=0" {
    eval "$(sed -n '/^ct_enabled()/,/^}/p' "$APF_DIR/internals/functions.apf")"
    CT_LIMIT="0"
    ! ct_enabled
}

@test "--ct-status shows data source" {
    run "$APF" --ct-status
    assert_success
    assert_output --partial "Data source:"
}

@test "--ct-status shows last scan: never on fresh install" {
    run "$APF" --ct-status
    assert_success
    assert_output --partial "Last scan: never"
}
