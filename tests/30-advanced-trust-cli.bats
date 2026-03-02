#!/usr/bin/env bats
#
# 30: Advanced trust syntax in CLI commands
#
# Validates that apf -a/-d/-u/-ta/-td accept advanced trust syntax
# (proto:flow:port:ip) in addition to bare IPs/CIDRs/FQDNs.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash
source /opt/tests/helpers/capability-detect.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    if ip6tables_available; then
        apf_set_config "USE_IPV6" "1"
    fi
    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

setup() {
    clean_trust_entries 192.0.2.50 192.0.2.51 192.0.2.52 192.0.2.53 "2001:db8::50"
}

# =====================================================================
# 5-field: proto:dir:port_flow=PORT:ip_flow=IP
# =====================================================================

@test "apf -a 5-field: tcp:in:d=22:s=IP creates TALLOW rule" {
    run "$APF" -a "tcp:in:d=22:s=192.0.2.50"
    assert_success
    assert_rule_exists_ips TALLOW "-s 192.0.2.50.*-p tcp.*--dports 22.*-j ACCEPT"
}

@test "apf -a 5-field: entry written to allow_hosts.rules" {
    "$APF" -a "tcp:in:d=22:s=192.0.2.50" "test comment"
    run grep "^tcp:in:d=22:s=192.0.2.50$" "$APF_DIR/allow_hosts.rules"
    assert_success
    run grep "# added tcp:in:d=22:s=192.0.2.50.*with comment: test comment" "$APF_DIR/allow_hosts.rules"
    assert_success
}

@test "apf -d 5-field: tcp deny creates rule with TCP_STOP target" {
    "$APF" -d "tcp:in:d=22:s=192.0.2.51"
    # Default TCP_STOP is DROP
    assert_rule_exists_ips TDENY "-s 192.0.2.51.*-p tcp.*--dports 22.*-j DROP"
}

@test "apf -a 5-field: udp:out creates single UDP rule" {
    "$APF" -a "udp:out:d=53:s=192.0.2.50"
    assert_rule_exists_ips TALLOW "-s 192.0.2.50.*-p udp.*--dports 53.*-j ACCEPT"
    # Should NOT create a tcp rule
    local rules
    rules=$(iptables -S TALLOW 2>/dev/null | grep "192.0.2.50.*-p tcp" || true)
    [ -z "$rules" ]
}

# =====================================================================
# 3-field: port_flow=PORT:ip_flow=IP (both TCP+UDP)
# =====================================================================

@test "apf -a 3-field: d=3306:s=IP creates both tcp and udp rules" {
    "$APF" -a "d=3306:s=192.0.2.50"
    assert_rule_exists_ips TALLOW "-s 192.0.2.50.*-p tcp.*--dports 3306.*-j ACCEPT"
    assert_rule_exists_ips TALLOW "-s 192.0.2.50.*-p udp.*--dports 3306.*-j ACCEPT"
}

@test "apf -d 3-field: deny creates tcp+udp with protocol-specific stop targets" {
    "$APF" -d "d=80:s=192.0.2.51"
    assert_rule_exists_ips TDENY "-s 192.0.2.51.*-p tcp.*--dports 80.*-j DROP"
    assert_rule_exists_ips TDENY "-s 192.0.2.51.*-p udp.*--dports 80.*-j DROP"
}

# =====================================================================
# 4-field: dir:port_flow=PORT:ip_flow=IP
# =====================================================================

@test "apf -a 4-field: in:d=80:s=IP creates both tcp and udp rules" {
    "$APF" -a "in:d=80:s=192.0.2.50"
    assert_rule_exists_ips TALLOW "-s 192.0.2.50.*-p tcp.*--dports 80.*-j ACCEPT"
    assert_rule_exists_ips TALLOW "-s 192.0.2.50.*-p udp.*--dports 80.*-j ACCEPT"
}

# =====================================================================
# Port ranges
# =====================================================================

@test "apf -a with port range 8000_8100 creates multiport rule" {
    "$APF" -a "tcp:in:d=8000_8100:s=192.0.2.50"
    assert_rule_exists_ips TALLOW "-s 192.0.2.50.*-p tcp.*--dports 8000:8100.*-j ACCEPT"
}

# =====================================================================
# IPv6 (with skip guard)
# =====================================================================

@test "apf -a advanced syntax with IPv6 address" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    "$APF" -a "d=22:s=[2001:db8::50]"
    assert_rule_exists_ip6s TALLOW "-s 2001:db8::50.*-p tcp.*--dports 22.*-j ACCEPT"
    assert_rule_exists_ip6s TALLOW "-s 2001:db8::50.*-p udp.*--dports 22.*-j ACCEPT"
}

# =====================================================================
# Validation: invalid entries
# =====================================================================

@test "apf -a rejects invalid protocol in advanced syntax" {
    run "$APF" -a "icmp:in:d=22:s=192.0.2.50"
    assert_output --partial "Invalid trust entry"
}

@test "apf -a rejects invalid direction in advanced syntax" {
    run "$APF" -a "tcp:fwd:d=22:s=192.0.2.50"
    assert_output --partial "Invalid trust entry"
}

@test "apf -a rejects missing port flow in advanced syntax" {
    run "$APF" -a "tcp:in:x=22:s=192.0.2.50"
    assert_output --partial "Invalid trust entry"
}

@test "apf -a rejects non-numeric port in advanced syntax" {
    run "$APF" -a "tcp:in:d=http:s=192.0.2.50"
    assert_output --partial "Invalid trust entry"
}

# =====================================================================
# Removal: advanced syntax
# =====================================================================

@test "apf -u removes advanced trust entry and iptables rules" {
    "$APF" -a "tcp:in:d=22:s=192.0.2.50"
    # Verify rule exists
    assert_rule_exists_ips TALLOW "-s 192.0.2.50.*-p tcp.*--dports 22.*-j ACCEPT"
    # Remove
    run "$APF" -u "tcp:in:d=22:s=192.0.2.50"
    assert_success
    # Verify entry removed from file
    run grep "^tcp:in:d=22:s=192.0.2.50$" "$APF_DIR/allow_hosts.rules"
    assert_failure
    # Verify iptables rule removed
    local rules
    rules=$(iptables -S TALLOW 2>/dev/null | grep "192.0.2.50.*-p tcp.*--dports 22" || true)
    [ -z "$rules" ]
}

@test "apf -u bare IP also removes advanced entries containing that IP" {
    "$APF" -a "tcp:in:d=22:s=192.0.2.52"
    # Verify rule and file entry exist
    assert_rule_exists_ips TALLOW "-s 192.0.2.52.*-p tcp.*--dports 22.*-j ACCEPT"
    run grep "^tcp:in:d=22:s=192.0.2.52$" "$APF_DIR/allow_hosts.rules"
    assert_success
    # Remove by bare IP
    run "$APF" -u 192.0.2.52
    assert_success
    # Verify advanced entry removed from file
    run grep "192.0.2.52" "$APF_DIR/allow_hosts.rules"
    assert_failure
}

# =====================================================================
# Duplicate detection
# =====================================================================

@test "apf -a advanced syntax duplicate detection" {
    "$APF" -a "tcp:in:d=22:s=192.0.2.50"
    run "$APF" -a "tcp:in:d=22:s=192.0.2.50"
    assert_output --partial "already exists"
}

# =====================================================================
# Temp trust with advanced syntax
# =====================================================================

@test "-ta with advanced syntax creates rule and ttl marker" {
    run "$APF" -ta "tcp:in:d=22:s=192.0.2.50" 300
    assert_success
    # Rule exists
    assert_rule_exists_ips TALLOW "-s 192.0.2.50.*-p tcp.*--dports 22.*-j ACCEPT"
    # File has ttl marker
    run grep "tcp:in:d=22:s=192.0.2.50.*ttl=300 expire=" "$APF_DIR/allow_hosts.rules"
    assert_success
    # Data entry exists
    run grep "^tcp:in:d=22:s=192.0.2.50$" "$APF_DIR/allow_hosts.rules"
    assert_success
}

@test "-td with advanced syntax creates deny rule" {
    run "$APF" -td "d=80:s=192.0.2.51" 600
    assert_success
    assert_rule_exists_ips TDENY "-s 192.0.2.51.*-p tcp.*--dports 80.*-j DROP"
    assert_rule_exists_ips TDENY "-s 192.0.2.51.*-p udp.*--dports 80.*-j DROP"
    run grep "d=80:s=192.0.2.51.*ttl=600 expire=" "$APF_DIR/deny_hosts.rules"
    assert_success
}

@test "-ta advanced syntax duplicate detection" {
    "$APF" -ta "tcp:in:d=22:s=192.0.2.53" 300
    run "$APF" -ta "tcp:in:d=22:s=192.0.2.53" 600
    assert_output --partial "already exists"
}

@test "--templ lists advanced syntax temp entries" {
    "$APF" -ta "tcp:in:d=22:s=192.0.2.50" 3600
    run "$APF" --templ
    assert_success
    assert_output --partial "tcp:in:d=22:s=192.0.2.50"
}
