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

# Helper: source apf_ctlimit.sh with minimal variable setup (no conf.apf sourcing)
_source_ctlimit() {
    # Set only the variables that apf_ctlimit.sh needs
    INSTALL_PATH="$APF_DIR"
    ALLOW_HOSTS="$APF_DIR/allow_hosts.rules"
    DENY_HOSTS="$APF_DIR/deny_hosts.rules"
    IFACE_TRUSTED=""
    SET_VNET="0"
    CT_SKIP=""
    ip=$(command -v ip 2>/dev/null)
    # Source apf.lib.sh temp file helpers
    eval "$(sed -n '/^_apf_reg_tmp()/,/^}/p' "$APF_DIR/internals/apf.lib.sh")"
    _APF_TMPFILES=""
    _APF_CTLIMIT_LOADED=""
    source "$APF_DIR/internals/apf_ctlimit.sh"
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

@test "--ct-status shows config, data source, and scan status when disabled" {
    run "$APF" --ct-status
    assert_success
    assert_output --partial "CT_LIMIT=0"
    assert_output --partial "max connections per IP"
    assert_output --partial "Data source:"
    assert_output --partial "Last scan: never"
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
    eval "$(sed -n '/^ct_enabled()/,/^}/p' "$APF_DIR/internals/apf_validate.sh")"
    CT_LIMIT="100"
    ct_enabled
}

@test "ct_enabled returns false when CT_LIMIT=0" {
    eval "$(sed -n '/^ct_enabled()/,/^}/p' "$APF_DIR/internals/apf_validate.sh")"
    CT_LIMIT="0"
    ! ct_enabled
}


# ---- CT_PERMANENT behavior tests ----

# Helper: create a mock conntrack binary that outputs fixture data.
# Used to inject synthetic conntrack into ct_scan() via the CONNTRACK variable.
# Args: fixture_file output_script_path
_create_mock_conntrack() {
    local fixture="$1" script="$2"
    printf '#!/bin/bash\ncat "%s"\n' "$fixture" > "$script"
    chmod 755 "$script"
}

# Helper: create a small fixture with a single offender IP exceeding threshold.
# Args: fixture_path offender_ip conn_count
_create_offender_fixture() {
    local fixture="$1" offender_ip="$2" conn_count="$3"
    local i
    true > "$fixture"
    for i in $(seq 1 "$conn_count"); do
        echo "ipv4     2 tcp      6 300 ESTABLISHED src=${offender_ip} dst=10.0.0.1 sport=$((10000+i)) dport=80 src=10.0.0.1 dst=${offender_ip} sport=80 dport=$((10000+i)) [ASSURED] mark=0 use=2" >> "$fixture"
    done
}

@test "CT_PERMANENT=0: block_history entry removed after ct_scan block" {
    source /opt/tests/helpers/apf-config.sh
    local offender_ip="198.51.100.99"

    # Configure CT_LIMIT with low threshold; enable PERMBLOCK so that
    # apf -td records block_history entries (PERMBLOCK_COUNT must be > 0)
    apf_set_config "CT_LIMIT" "5"
    apf_set_config "CT_INTERVAL" "60"
    apf_set_config "CT_BLOCK_TIME" "300"
    apf_set_config "CT_PERMANENT" "0"
    apf_set_config "PERMBLOCK_COUNT" "5"

    # Restart firewall with CT_LIMIT enabled
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Create fixture with offender exceeding threshold
    _create_offender_fixture "$CT_FIXTURE_DIR/ct_perm_test" "$offender_ip" 20

    # Create mock conntrack binary that outputs fixture data
    # The -L flag is passed by _ct_read_conntrack but our mock ignores it
    _create_mock_conntrack "$CT_FIXTURE_DIR/ct_perm_test" "$CT_FIXTURE_DIR/mock-conntrack"

    # Override CONNTRACK after internals.conf is sourced — append after
    # the '. "$CNFINT"' line at the end of conf.apf
    echo "CONNTRACK=\"$CT_FIXTURE_DIR/mock-conntrack\"" >> "$APF_DIR/conf.apf"

    # Run ct_scan via CLI
    "$APF" --ct-scan

    # Verify the offender was temp-denied
    grep -Fq "$offender_ip" "$APF_DIR/deny_hosts.rules"

    # CT_PERMANENT=0: block_history entry should have been removed
    if [ -f "$APF_DIR/internals/.block_history" ]; then
        ! grep -Fq "${offender_ip}|" "$APF_DIR/internals/.block_history"
    fi
    # else: no block_history file means no entry — correct for CT_PERMANENT=0

    # Clean up: remove the temp deny
    "$APF" -u "$offender_ip" 2>/dev/null || true
}

@test "CT_PERMANENT=1: block_history entry preserved after ct_scan block" {
    source /opt/tests/helpers/apf-config.sh
    local offender_ip="198.51.100.98"

    # Configure CT_LIMIT with CT_PERMANENT=1; PERMBLOCK_COUNT > 0 enables
    # block_history recording in apf -td
    apf_set_config "CT_LIMIT" "5"
    apf_set_config "CT_INTERVAL" "60"
    apf_set_config "CT_BLOCK_TIME" "300"
    apf_set_config "CT_PERMANENT" "1"
    apf_set_config "PERMBLOCK_COUNT" "5"

    # Restart firewall with CT_LIMIT enabled
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Create fixture with offender exceeding threshold
    _create_offender_fixture "$CT_FIXTURE_DIR/ct_perm_test1" "$offender_ip" 20

    # Create mock conntrack binary
    _create_mock_conntrack "$CT_FIXTURE_DIR/ct_perm_test1" "$CT_FIXTURE_DIR/mock-conntrack1"

    # Override CONNTRACK after internals.conf sourcing
    echo "CONNTRACK=\"$CT_FIXTURE_DIR/mock-conntrack1\"" >> "$APF_DIR/conf.apf"

    # Run ct_scan via CLI
    "$APF" --ct-scan

    # Verify the offender was temp-denied
    grep -Fq "$offender_ip" "$APF_DIR/deny_hosts.rules"

    # CT_PERMANENT=1: block_history entry should be preserved
    [ -f "$APF_DIR/internals/.block_history" ]
    grep -Fq "${offender_ip}|" "$APF_DIR/internals/.block_history"

    # Clean up
    "$APF" -u "$offender_ip" 2>/dev/null || true
}

@test "CT_PERMANENT=0: block_history removal does not affect IPs sharing prefix" {
    source /opt/tests/helpers/apf-config.sh
    local offender_ip="1.2.3.4"
    local bystander_ip="11.2.3.4"
    local history_file="$APF_DIR/internals/.block_history"

    apf_set_config "CT_LIMIT" "5"
    apf_set_config "CT_INTERVAL" "60"
    apf_set_config "CT_BLOCK_TIME" "300"
    apf_set_config "CT_PERMANENT" "0"
    apf_set_config "PERMBLOCK_COUNT" "5"

    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Pre-populate block_history with bystander IP (shares prefix with offender)
    # Use current timestamp so record_block() doesn't prune it as expired
    local _now
    _now=$(date +%s)
    echo "${bystander_ip}|2|${_now}|${_now}" > "$history_file"

    # Create fixture with offender exceeding threshold
    _create_offender_fixture "$CT_FIXTURE_DIR/ct_prefix_test" "$offender_ip" 20

    _create_mock_conntrack "$CT_FIXTURE_DIR/ct_prefix_test" "$CT_FIXTURE_DIR/mock-conntrack-prefix"
    echo "CONNTRACK=\"$CT_FIXTURE_DIR/mock-conntrack-prefix\"" >> "$APF_DIR/conf.apf"

    "$APF" --ct-scan

    # Offender should be temp-denied
    grep -Fq "$offender_ip" "$APF_DIR/deny_hosts.rules"

    # Bystander IP must NOT be removed from block_history (regression for B-001)
    [ -f "$history_file" ]
    grep -Fq "${bystander_ip}|" "$history_file"

    "$APF" -u "$offender_ip" 2>/dev/null || true
}

@test "VNET CT_LIMIT: non-numeric value in vnet rules falls back to global" {
    source /opt/tests/helpers/apf-config.sh
    local offender_ip="198.51.100.50"
    local vnet_ip="10.0.0.100"

    apf_set_config "CT_LIMIT" "5"
    apf_set_config "CT_INTERVAL" "60"
    apf_set_config "CT_BLOCK_TIME" "300"
    apf_set_config "CT_PERMANENT" "1"
    apf_set_config "SET_VNET" "1"

    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Create a VNET rules file with non-numeric CT_LIMIT
    mkdir -p "$APF_DIR/vnet"
    echo 'CT_LIMIT="abc"' > "$APF_DIR/vnet/${offender_ip}.rules"

    # Create fixture: offender_ip with 20 connections (exceeds global CT_LIMIT=5)
    _create_offender_fixture "$CT_FIXTURE_DIR/ct_vnet_nonnumeric" "$offender_ip" 20

    _create_mock_conntrack "$CT_FIXTURE_DIR/ct_vnet_nonnumeric" "$CT_FIXTURE_DIR/mock-conntrack-vnet"
    echo "CONNTRACK=\"$CT_FIXTURE_DIR/mock-conntrack-vnet\"" >> "$APF_DIR/conf.apf"

    # Should not produce bash arithmetic errors on stderr
    run "$APF" --ct-scan
    [ "$status" -eq 0 ]

    # Non-numeric VNET CT_LIMIT is silently ignored; global CT_LIMIT=5 applies;
    # 20 connections exceeds 5, so the offender should be blocked
    grep -Fq "$offender_ip" "$APF_DIR/deny_hosts.rules"

    "$APF" -u "$offender_ip" 2>/dev/null || true
    rm -f "$APF_DIR/vnet/${offender_ip}.rules"
}
