#!/usr/bin/env bats
#
# 26: Hook scripts, silent IPs, search CLI
#
# Validates hook_pre.sh/hook_post.sh (activation by permission, ordering),
# silent_ips.rules (inbound/outbound DROP, IPv6, empty no-op),
# and apf -g/--search (rule match, trust file match, no match, usage).

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    # Clean up any test artifacts
    chmod 640 "$APF_DIR/hook_pre.sh" 2>/dev/null || true
    chmod 640 "$APF_DIR/hook_post.sh" 2>/dev/null || true
    echo "" > "$APF_DIR/silent_ips.rules"
    source /opt/tests/helpers/teardown-netns.sh
}

# =====================================================================
# Hook scripts
# =====================================================================

@test "hook_pre.sh inactive when not executable (perms 640)" {
    source /opt/tests/helpers/apf-config.sh
    # Write a rule that creates a custom chain
    cat > "$APF_DIR/hook_pre.sh" <<'HOOK'
#!/bin/bash
$IPT $IPT_FLAGS -N HOOK_PRE_TEST
HOOK
    chmod 640 "$APF_DIR/hook_pre.sh"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Chain should NOT exist because hook was not executable
    assert_chain_not_exists HOOK_PRE_TEST
}

@test "hook_pre.sh active when executable (perms 750)" {
    source /opt/tests/helpers/apf-config.sh
    cat > "$APF_DIR/hook_pre.sh" <<'HOOK'
#!/bin/bash
$IPT $IPT_FLAGS -N HOOK_PRE_TEST
HOOK
    chmod 750 "$APF_DIR/hook_pre.sh"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Chain should exist because hook was executable
    assert_chain_exists HOOK_PRE_TEST

    # Cleanup
    chmod 640 "$APF_DIR/hook_pre.sh"
}

@test "hook_post.sh active when executable" {
    source /opt/tests/helpers/apf-config.sh
    cat > "$APF_DIR/hook_post.sh" <<'HOOK'
#!/bin/bash
$IPT $IPT_FLAGS -N HOOK_POST_TEST
HOOK
    chmod 750 "$APF_DIR/hook_post.sh"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Chain should exist
    assert_chain_exists HOOK_POST_TEST

    # Cleanup
    chmod 640 "$APF_DIR/hook_post.sh"
}

# =====================================================================
# Silent IPs
# =====================================================================

@test "silent_ips blocks inbound traffic to listed IP" {
    source /opt/tests/helpers/apf-config.sh
    cat > "$APF_DIR/silent_ips.rules" <<'RULES'
# Test silent IP
192.0.2.200
RULES
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips INPUT "-d 192.0.2.200.*-j DROP"
}

@test "silent_ips blocks outbound traffic from listed IP" {
    source /opt/tests/helpers/apf-config.sh
    cat > "$APF_DIR/silent_ips.rules" <<'RULES'
192.0.2.200
RULES
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips OUTPUT "-s 192.0.2.200.*-j DROP"
}

@test "silent_ips supports IPv6 addresses" {
    source /opt/tests/helpers/apf-config.sh
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    apf_set_config "USE_IPV6" "1"

    cat > "$APF_DIR/silent_ips.rules" <<'RULES'
2001:db8::dead
RULES
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ip6s INPUT "-d 2001:db8::dead.*-j DROP"
    assert_rule_exists_ip6s OUTPUT "-s 2001:db8::dead.*-j DROP"

    # Cleanup
    apf_set_config "USE_IPV6" "0"
}

@test "silent_ips empty file produces no silent drop rules" {
    source /opt/tests/helpers/apf-config.sh
    cat > "$APF_DIR/silent_ips.rules" <<'RULES'
# Only comments, no actual IPs
RULES
    "$APF" -f 2>/dev/null
    "$APF" -s

    # No silent drop rules should exist — check that no bare DROP rules
    # exist in INPUT before the trust chains (i.e., no -d IP -j DROP without
    # a chain or other match criteria that would indicate it's from silent_ips)
    local silent_drops
    silent_drops=$(iptables -S INPUT 2>/dev/null | grep -c "192.0.2.200.*-j DROP" || true)
    [ "$silent_drops" -eq 0 ]
}

# =====================================================================
# Search CLI
# =====================================================================

@test "search finds iptables rule" {
    source /opt/tests/helpers/apf-config.sh
    "$APF" -f 2>/dev/null
    "$APF" -s

    run "$APF" -g TALLOW
    assert_success
    assert_output --partial "=== IPv4 (iptables -S) ==="
    assert_output --partial "TALLOW"
}

@test "search finds trust file entry" {
    source /opt/tests/helpers/apf-config.sh
    "$APF" -f 2>/dev/null
    "$APF" -s
    "$APF" -a 192.0.2.50 "test search"

    run "$APF" -g "192.0.2.50"
    assert_success
    assert_output --partial "=== allow_hosts.rules ==="
    assert_output --partial "192.0.2.50"

    # Cleanup
    "$APF" -u 192.0.2.50
}

@test "search returns no matches message" {
    source /opt/tests/helpers/apf-config.sh
    "$APF" -f 2>/dev/null
    "$APF" -s

    run "$APF" -g "XYZNONEXISTENT999"
    assert_success
    assert_output --partial "No matches found."
}

@test "search finds IPv6 rule when enabled" {
    source /opt/tests/helpers/apf-config.sh
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    apf_set_config "USE_IPV6" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    run "$APF" -g TALLOW
    assert_success
    assert_output --partial "=== IPv6 (ip6tables -S) ==="
    assert_output --partial "TALLOW"

    # Cleanup
    apf_set_config "USE_IPV6" "0"
}

@test "search with empty pattern shows usage" {
    run "$APF" -g
    assert_output --partial "usage: apf -g PATTERN"
}
