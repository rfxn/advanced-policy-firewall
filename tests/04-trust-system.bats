#!/usr/bin/env bats
#
# 04: Trust system — apf -a/-d/-u, CIDR, validation

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/install-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

setup() {
    # Direct cleanup — more reliable than apf -u in container
    # Remove all lines mentioning test IPs (entries + comments)
    for host in 192.0.2.50 192.0.2.51 192.0.2.55 "198.51.100.0/24" "198.51.100.1/32"; do
        local escaped
        escaped=$(echo "$host" | sed 's/[.\/]/\\&/g')
        sed -i "/${escaped}/d" "$APF_DIR/allow_hosts.rules" 2>/dev/null || true
        sed -i "/${escaped}/d" "$APF_DIR/deny_hosts.rules" 2>/dev/null || true
    done
    # Flush trust chains so stale iptables rules don't interfere
    iptables -F TALLOW 2>/dev/null || true
    iptables -F TDENY 2>/dev/null || true
}

@test "apf -a adds host to allow_hosts.rules file" {
    run "$APF" -a 192.0.2.50 "test allow"
    assert_success
    run grep "192.0.2.50" "$APF_DIR/allow_hosts.rules"
    assert_success
}

@test "apf -a adds host to TALLOW chain" {
    "$APF" -a 192.0.2.50 "test allow"
    assert_rule_exists TALLOW "192.0.2.50"
}

@test "apf -a creates both src and dst rules" {
    "$APF" -a 192.0.2.50 "test allow"
    # Source rule (inbound from host) and dest rule (outbound to host)
    local rules
    rules=$(iptables -L TALLOW -nv)
    echo "$rules" | grep -q "192.0.2.50"
    # Check both -s and -d entries exist (iptables -S gives clearer view)
    local srules
    srules=$(iptables -S TALLOW)
    echo "$srules" | grep -q "\-s 192.0.2.50"
    echo "$srules" | grep -q "\-d 192.0.2.50"
}

@test "apf -d adds host to deny_hosts.rules file" {
    run "$APF" -d 192.0.2.51 "test deny"
    assert_success
    run grep "192.0.2.51" "$APF_DIR/deny_hosts.rules"
    assert_success
}

@test "apf -d adds host to TDENY chain" {
    "$APF" -d 192.0.2.51 "test deny"
    assert_rule_exists TDENY "192.0.2.51"
}

@test "apf -u removes host from file and chain" {
    "$APF" -a 192.0.2.50 "test remove"
    # Verify it was added
    assert_rule_exists TALLOW "192.0.2.50"

    # Remove it
    run "$APF" -u 192.0.2.50
    assert_success

    # Verify the host entry line is gone from the rules file
    run grep "^192.0.2.50" "$APF_DIR/allow_hosts.rules"
    assert_failure

    # Verify it's gone from iptables
    local rules
    rules=$(iptables -S TALLOW 2>/dev/null || true)
    if echo "$rules" | grep -q "192.0.2.50"; then
        echo "Host 192.0.2.50 still in TALLOW chain after -u" >&2
        return 1
    fi
}

@test "apf -a rejects duplicate host" {
    "$APF" -a 192.0.2.50 "first add"
    run "$APF" -a 192.0.2.50 "duplicate"
    assert_success
    assert_output --partial "already exists"
}

@test "apf -a rejects local address" {
    # 203.0.113.1 is assigned to veth-pub (our local addr)
    run "$APF" -a 203.0.113.1 "local addr"
    assert_success
    assert_output --partial "local address"
}

@test "apf -a rejects invalid host" {
    run "$APF" -a "not-valid" "bad host"
    assert_success
    assert_output --partial "Invalid host"
}

@test "apf -a records comment" {
    "$APF" -a 192.0.2.50 "my test comment"
    run grep "my test comment" "$APF_DIR/allow_hosts.rules"
    assert_success
}

@test "apf -a accepts CIDR notation" {
    run "$APF" -a 198.51.100.0/24 "cidr test"
    assert_success
    assert_rule_exists TALLOW "198.51.100.0/24"
}

@test "apf -a with no host shows error" {
    run "$APF" -a
    assert_output --partial "FQDN or IP address is required"
}

@test "apf -a accepts /32 single-host CIDR" {
    run "$APF" -a 198.51.100.1/32 "single host cidr"
    assert_success
    # iptables normalizes /32 to bare IP in display
    assert_rule_exists TALLOW "198.51.100.1"
}

@test "apf -u removes CIDR without breaking sed" {
    # Verifies sed delimiter hardening: / in CIDR doesn't break removal
    "$APF" -a 198.51.100.0/24 "cidr remove test"
    assert_rule_exists TALLOW "198.51.100.0/24"

    run "$APF" -u 198.51.100.0/24
    assert_success

    run grep "^198.51.100.0/24" "$APF_DIR/allow_hosts.rules"
    assert_failure
}

@test "apf -a with special characters in comment" {
    "$APF" -a 192.0.2.55 "test's comment with spaces & special"
    run grep "192.0.2.55" "$APF_DIR/allow_hosts.rules"
    assert_success
    run grep "test's comment" "$APF_DIR/allow_hosts.rules"
    assert_success
}
