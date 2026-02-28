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

teardown() {
    # Reset hooks between tests to prevent cascading failures
    chmod 640 "$APF_DIR/hook_pre.sh" 2>/dev/null || true
    chmod 640 "$APF_DIR/hook_post.sh" 2>/dev/null || true
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

@test "hook_pre.sh executes before trust chains" {
    source /opt/tests/helpers/apf-config.sh
    # Create hook_pre that adds a jump to a marker chain in INPUT
    cat > "$APF_DIR/hook_pre.sh" <<'HOOK'
#!/bin/bash
$IPT $IPT_FLAGS -N HOOK_ORDER_PRE
$IPT $IPT_FLAGS -A INPUT -j HOOK_ORDER_PRE
HOOK
    chmod 750 "$APF_DIR/hook_pre.sh"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # hook_pre's INPUT jump should appear before TALLOW jump
    local rules
    rules=$(iptables -S INPUT 2>/dev/null)
    local pre_line tallow_line
    pre_line=$(echo "$rules" | grep -n "HOOK_ORDER_PRE" | head -1 | cut -d: -f1)
    tallow_line=$(echo "$rules" | grep -n "TALLOW" | head -1 | cut -d: -f1)

    [ -n "$pre_line" ] || { echo "No HOOK_ORDER_PRE jump found"; echo "$rules"; return 1; }
    [ -n "$tallow_line" ] || { echo "No TALLOW jump found"; echo "$rules"; return 1; }
    [ "$pre_line" -lt "$tallow_line" ] || {
        echo "hook_pre jump (line $pre_line) should appear before TALLOW (line $tallow_line)" >&2
        echo "$rules" >&2
        return 1
    }

    # Cleanup
    chmod 640 "$APF_DIR/hook_pre.sh"
}

@test "hook_post.sh executes after default DROP policies" {
    source /opt/tests/helpers/apf-config.sh
    # Create hook_post that adds a jump to a marker chain in INPUT
    cat > "$APF_DIR/hook_post.sh" <<'HOOK'
#!/bin/bash
$IPT $IPT_FLAGS -N HOOK_ORDER_POST
$IPT $IPT_FLAGS -A INPUT -j HOOK_ORDER_POST
HOOK
    chmod 750 "$APF_DIR/hook_post.sh"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # hook_post's INPUT jump should appear after the default DROP policy rules
    local rules
    rules=$(iptables -S INPUT 2>/dev/null)
    local post_line drop_line
    post_line=$(echo "$rules" | grep -n "HOOK_ORDER_POST" | head -1 | cut -d: -f1)
    # Default input policy is the last "-j DROP" in INPUT (firewall adds
    # tcp DROP, udp DROP, then all DROP — all before hook_post).
    # iptables -S shows "-A INPUT -j DROP" (no -p all) for the catch-all.
    drop_line=$(echo "$rules" | grep -nE -- "-j (DROP|REJECT)$" | tail -1 | cut -d: -f1)

    [ -n "$post_line" ] || { echo "No HOOK_ORDER_POST jump found"; echo "$rules"; return 1; }
    [ -n "$drop_line" ] || { echo "No default DROP policy found"; echo "$rules"; return 1; }
    [ "$post_line" -gt "$drop_line" ] || {
        echo "hook_post jump (line $post_line) should appear after default DROP (line $drop_line)" >&2
        echo "$rules" >&2
        return 1
    }

    # Cleanup
    chmod 640 "$APF_DIR/hook_post.sh"
}

@test "hook scripts have access to APF variables" {
    source /opt/tests/helpers/apf-config.sh
    # Create hook_pre that uses $IPT and $INSTALL_PATH — both set by internals.conf
    cat > "$APF_DIR/hook_pre.sh" <<'HOOK'
#!/bin/bash
# Test that $IPT is available (set by internals.conf)
$IPT $IPT_FLAGS -N HOOK_ENV_TEST
# Test that $INSTALL_PATH is available (set by conf.apf)
if [ -d "$INSTALL_PATH" ]; then
    $IPT $IPT_FLAGS -A HOOK_ENV_TEST -j RETURN -m comment --comment "path_ok"
fi
HOOK
    chmod 750 "$APF_DIR/hook_pre.sh"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Chain should exist (proves $IPT was available)
    assert_chain_exists HOOK_ENV_TEST
    # RETURN rule with comment should exist (proves $INSTALL_PATH was available)
    assert_rule_exists_ips HOOK_ENV_TEST "comment.*path_ok.*RETURN"

    # Cleanup
    chmod 640 "$APF_DIR/hook_pre.sh"
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

# =====================================================================
# Hook error handling (C4)
# =====================================================================

@test "firewall continues loading when hook_pre.sh fails" {
    source /opt/tests/helpers/apf-config.sh
    # Create a hook that exits non-zero and produces an error
    cat > "$APF_DIR/hook_pre.sh" <<'HOOK'
#!/bin/bash
# This hook intentionally fails
false
# This line should still run because set -e is not active in hooks
$IPT $IPT_FLAGS -N HOOK_FAIL_MARKER 2>/dev/null || true
HOOK
    chmod 750 "$APF_DIR/hook_pre.sh"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Firewall should have loaded fully despite hook failure
    # Verify trust chains exist (loaded in Step 15, well after hook_pre)
    assert_chain_exists TALLOW
    assert_chain_exists TDENY

    # Verify default DROP policies are in place (loaded at Step 30)
    assert_rule_exists_ips INPUT "-j DROP"

    # Cleanup
    chmod 640 "$APF_DIR/hook_pre.sh"
}

@test "firewall continues loading when hook_post.sh fails" {
    source /opt/tests/helpers/apf-config.sh
    # Create a hook_post that references a non-existent command
    cat > "$APF_DIR/hook_post.sh" <<'HOOK'
#!/bin/bash
# This hook intentionally fails
/nonexistent/command 2>/dev/null
false
HOOK
    chmod 750 "$APF_DIR/hook_post.sh"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Firewall should have loaded fully — all steps before hook_post completed
    # Verify trust chains exist
    assert_chain_exists TALLOW
    assert_chain_exists TDENY

    # Verify port filtering rules were loaded (Step 22, before hook_post)
    # The default INPUT DROP rules confirm full chain was loaded
    assert_rule_exists_ips INPUT "-j DROP"

    # Cleanup
    chmod 640 "$APF_DIR/hook_post.sh"
}

# =====================================================================
# Search special character patterns (C6)
# =====================================================================

@test "search handles dot in pattern without crash" {
    source /opt/tests/helpers/apf-config.sh
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Dot is a regex metacharacter — should not crash grep
    run "$APF" -g "192.0.2"
    assert_success
}

@test "search handles bracket in pattern gracefully" {
    source /opt/tests/helpers/apf-config.sh
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Unmatched bracket is invalid regex — grep returns error but
    # search() should not crash; it reports no matches instead
    run "$APF" -g "[invalid"
    assert_success
}

@test "search handles pattern starting with dash" {
    source /opt/tests/helpers/apf-config.sh
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Patterns starting with - could be mistaken as grep flags
    # search() uses grep -- "$pattern" to handle this
    run "$APF" -g "-j DROP"
    assert_success
    assert_output --partial "DROP"
}
