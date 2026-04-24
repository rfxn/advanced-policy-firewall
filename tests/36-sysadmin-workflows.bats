#!/usr/bin/env bats
#
# 36: Sysadmin workflow UATs — end-to-end scenarios sourced from real-world
#     usage patterns (hosting guides, forum posts, support tickets).
#
# These tests exercise multi-step workflows that a Linux system administrator
# performs day-to-day: incident response, server hardening, trust management,
# monitoring, and failure recovery. Each test maps to a documented sysadmin
# workflow from hosting providers (HowToForge, A2 Hosting, crybit),
# sysadmin communities (WHT, ServerFault, DirectAdmin forums), and the
# rfxn.com documentation.
#
# Tests that overlap with unit tests in other files are intentionally excluded.
# Only end-to-end workflows that exercise multi-command sequences remain.

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
    apf_set_ports "22,80,443" "53" "22,25,53,80,443" "53"
    apf_set_config "EGF" "1"
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

teardown() {
    # Clean up trust entries
    "$APF" -u 192.0.2.50 2>/dev/null || true
    "$APF" -u 192.0.2.51 2>/dev/null || true
    "$APF" -u 192.0.2.52 2>/dev/null || true
    "$APF" -u 192.0.2.53 2>/dev/null || true
    "$APF" -u 192.0.2.54 2>/dev/null || true
    "$APF" -u 192.0.2.90 2>/dev/null || true
    "$APF" -u 198.51.100.10 2>/dev/null || true
    "$APF" -u 198.51.100.11 2>/dev/null || true
    "$APF" -u 192.0.2.0/24 2>/dev/null || true
    "$APF" -u 2001:db8::50 2>/dev/null || true

    # Restore config and rules files from .clean copies
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    apf_set_ports "22,80,443" "53" "22,25,53,80,443" "53"
    apf_set_config "EGF" "1"
    if ip6tables_available; then
        apf_set_config "USE_IPV6" "1"
    fi
}

# ============================================================================
# UAT-001: Incident Response — block attacker, verify, unblock, verify gone
# Source: Every APF guide (LiquidWeb, SysadminSpot, crybit) — #1 daily task
# Workflow: apf -d IP → apf -g IP → verify chain + file → apf -u IP → verify gone
# ============================================================================

@test "UAT-001a: block attacker and verify via search + iptables" {
    run "$APF" -d 198.51.100.10 "port scan detected"
    assert_success

    # Sysadmin verifies block is active via search
    run "$APF" -g 198.51.100.10
    assert_success
    assert_output --partial "198.51.100.10"

    # Verify in rules file
    run grep "198.51.100.10" "$APF_DIR/deny_hosts.rules"
    assert_success

    # Verify in live iptables
    assert_rule_exists_ips TDENY "198.51.100.10"
}

@test "UAT-001b: unblock attacker and verify fully removed" {
    "$APF" -d 198.51.100.10 "port scan" 2>/dev/null

    run "$APF" -u 198.51.100.10
    assert_success

    # Search should not show in deny file
    run "$APF" -g 198.51.100.10
    refute_output --partial "deny_hosts"

    # Gone from rules file
    run grep "198.51.100.10" "$APF_DIR/deny_hosts.rules"
    assert_failure

    # Gone from iptables
    local count
    count=$(iptables -S TDENY 2>/dev/null | grep -c "198.51.100.10" || true)
    [ "$count" -eq 0 ]
}

# ============================================================================
# UAT-002: Whitelist office network (CIDR) and verify via lookup
# Source: SysadminSpot guide — "allow complete access" to office range
# Workflow: apf -a CIDR → --lookup CIDR → apf -u CIDR → --lookup CIDR
# ============================================================================

@test "UAT-002: whitelist /24 then remove and verify via lookup" {
    run "$APF" -a 192.0.2.0/24 "Melbourne office"
    assert_success

    # Lookup confirms the entry
    run "$APF" --lookup 192.0.2.0/24
    assert_success
    assert_output --partial "ALLOW"

    # Remove
    run "$APF" -u 192.0.2.0/24
    assert_success

    # Lookup shows not found
    run "$APF" --lookup 192.0.2.0/24
    assert_failure
    assert_output --partial "not found"
}

# ============================================================================
# UAT-003: Multiple CLI operations accumulate without restart
# Source: SysadminSpot — "you do not need to restart or reload your firewall"
# Workflow: apf -a IP1 → apf -a IP2 → apf -d IP3 → apf -d IP4 → all four live
# ============================================================================

@test "UAT-003: sequential add/deny accumulate without restart" {
    "$APF" -a 192.0.2.50 "office-1" 2>/dev/null
    "$APF" -a 192.0.2.51 "office-2" 2>/dev/null
    "$APF" -d 198.51.100.10 "attacker-1" 2>/dev/null
    "$APF" -d 198.51.100.11 "attacker-2" 2>/dev/null

    # All four should be in live iptables simultaneously
    assert_rule_exists_ips TALLOW "192.0.2.50"
    assert_rule_exists_ips TALLOW "192.0.2.51"
    assert_rule_exists_ips TDENY "198.51.100.10"
    assert_rule_exists_ips TDENY "198.51.100.11"
}

# ============================================================================
# UAT-004: Restart preserves trust entries added via CLI
# Source: Every guide — edit config or rules → "apf -r" → rules survive
# Workflow: apf -a → apf -d → apf -r → verify entries survive in chain + file
# ============================================================================

@test "UAT-004: restart preserves allowed and denied hosts" {
    "$APF" -a 192.0.2.50 "persist-test allow" 2>/dev/null
    "$APF" -d 198.51.100.10 "persist-test deny" 2>/dev/null

    # Restart flushes and reloads
    "$APF" -r

    # Trust entries must survive restart
    assert_rule_exists_ips TALLOW "192.0.2.50"
    assert_rule_exists_ips TDENY "198.51.100.10"

    # Rules files must still have entries
    run grep "192.0.2.50" "$APF_DIR/allow_hosts.rules"
    assert_success
    run grep "198.51.100.10" "$APF_DIR/deny_hosts.rules"
    assert_success
}

# ============================================================================
# UAT-005: Bulk edit rules file + restart (maintenance window)
# Source: HowToForge, A2 Hosting — "edit rules files, then apf -r"
# Workflow: add IPs to allow_hosts.rules directly → apf -r → verify all loaded
# ============================================================================

@test "UAT-005: bulk add to allow_hosts.rules and restart loads all" {
    # Sysadmin adds 5 IPs directly to the file (one IP per line)
    {
        echo "192.0.2.50"
        echo "192.0.2.51"
        echo "192.0.2.52"
        echo "192.0.2.53"
        echo "192.0.2.54"
    } >> "$APF_DIR/allow_hosts.rules"

    "$APF" -r

    # All 5 should be in live iptables
    assert_rule_exists_ips TALLOW "192.0.2.50"
    assert_rule_exists_ips TALLOW "192.0.2.51"
    assert_rule_exists_ips TALLOW "192.0.2.52"
    assert_rule_exists_ips TALLOW "192.0.2.53"
    assert_rule_exists_ips TALLOW "192.0.2.54"
}

# ============================================================================
# UAT-006: Web server port configuration (realistic hosting setup)
# Source: HowToForge, LiquidWeb — cPanel/hosting server port list
# Workflow: configure realistic web+mail ports → start → verify all open
# ============================================================================

@test "UAT-006: realistic web+mail port config creates all inbound rules" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_ports "22,25,53,80,110,143,443,465,587,993,995" "53" \
                  "22,25,53,80,443" "53"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Core web: HTTP + HTTPS + SSH
    assert_rule_exists_ips INPUT "-p tcp.*--dport 80.*-j ACCEPT"
    assert_rule_exists_ips INPUT "-p tcp.*--dport 443.*-j ACCEPT"
    assert_rule_exists_ips INPUT "-p tcp.*--dport 22.*-j ACCEPT"

    # Mail: SMTP + POP3 + IMAP + secure variants
    assert_rule_exists_ips INPUT "-p tcp.*--dport 25.*-j ACCEPT"
    assert_rule_exists_ips INPUT "-p tcp.*--dport 110.*-j ACCEPT"
    assert_rule_exists_ips INPUT "-p tcp.*--dport 143.*-j ACCEPT"
    assert_rule_exists_ips INPUT "-p tcp.*--dport 465.*-j ACCEPT"
    assert_rule_exists_ips INPUT "-p tcp.*--dport 587.*-j ACCEPT"
    assert_rule_exists_ips INPUT "-p tcp.*--dport 993.*-j ACCEPT"
    assert_rule_exists_ips INPUT "-p tcp.*--dport 995.*-j ACCEPT"

    # DNS (UDP)
    assert_rule_exists_ips INPUT "-p udp.*--dport 53.*-j ACCEPT"
}

# ============================================================================
# UAT-007: DEVEL_MODE full lifecycle — enable → start → disable → restart
# Source: HowToForge — "set DEVEL_MODE=1 first, change to 0 after testing"
# Workflow: DEVEL_MODE=1 → start → verify cron → DEVEL_MODE=0 → restart → no cron
# ============================================================================

@test "UAT-007: DEVEL_MODE enable then disable lifecycle" {
    if [ ! -d /etc/cron.d ]; then skip "no /etc/cron.d directory"; fi

    source /opt/tests/helpers/apf-config.sh

    # Step 1: Enable DEVEL_MODE and start (initial setup safety)
    apf_set_config "DEVEL_MODE" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Verify safety cron was created
    [ -f /etc/cron.d/apf_develmode ]

    # Step 2: Disable DEVEL_MODE and restart (going to production)
    apf_set_config "DEVEL_MODE" "0"
    "$APF" -r

    # Verify safety cron was removed
    [ ! -f /etc/cron.d/apf_develmode ]
}

# ============================================================================
# UAT-008: --info trust counts reflect actual CLI operations
# Source: Monitoring workflow — sysadmin checks firewall status daily
# Workflow: capture baseline → add entries → --info → verify counts increased
# ============================================================================

@test "UAT-008: --info trust counts increase after CLI operations" {
    # Capture baseline count
    "$APF" -r
    local baseline_allow baseline_deny
    baseline_allow=$("$APF" --info | grep "Allow entries:" | grep -o '[0-9]\+' | head -1)
    baseline_deny=$("$APF" --info | grep "Deny entries:" | grep -o '[0-9]\+' | head -1)

    # Add entries
    "$APF" -a 192.0.2.50 "info-test-1" 2>/dev/null
    "$APF" -a 192.0.2.51 "info-test-2" 2>/dev/null
    "$APF" -d 198.51.100.10 "info-test-3" 2>/dev/null

    # Verify counts increased
    local new_allow new_deny
    new_allow=$("$APF" --info | grep "Allow entries:" | grep -o '[0-9]\+' | head -1)
    new_deny=$("$APF" --info | grep "Deny entries:" | grep -o '[0-9]\+' | head -1)

    [ "$new_allow" -ge $((baseline_allow + 2)) ]
    [ "$new_deny" -ge $((baseline_deny + 1)) ]
}

# ============================================================================
# UAT-009: Lookup tracks full add/remove lifecycle
# Source: Troubleshooting workflow — "is this IP blocked or allowed?"
# Workflow: --lookup unknown → add → --lookup found → remove → --lookup gone
# ============================================================================

@test "UAT-009: lookup tracks add/remove lifecycle" {
    # Use a unique IP — 192.0.2.50 collides with advanced trust entries
    # in 30-advanced-trust-cli.bats under file-group splitting
    # Initially not found
    run "$APF" --lookup 192.0.2.90
    assert_failure

    # Add to allow
    "$APF" -a 192.0.2.90 "lifecycle test" 2>/dev/null

    # Now found as ALLOW
    run "$APF" --lookup 192.0.2.90
    assert_success
    assert_output --partial "ALLOW"

    # Remove
    "$APF" -u 192.0.2.90

    # Gone again
    run "$APF" --lookup 192.0.2.90
    assert_failure
}

# ============================================================================
# UAT-010: Mixed allow and deny entries coexist correctly
# Source: Forums — sysadmin managing multiple incidents simultaneously
# Workflow: deny attacker1 + allow partner1 + deny attacker2 → all coexist
# ============================================================================

@test "UAT-010: mixed allow and deny entries in correct chains" {
    "$APF" -a 192.0.2.50 "partner" 2>/dev/null
    "$APF" -d 198.51.100.10 "attacker-1" 2>/dev/null
    "$APF" -a 192.0.2.51 "vendor" 2>/dev/null
    "$APF" -d 198.51.100.11 "attacker-2" 2>/dev/null

    # All entries should be in their correct chains
    assert_rule_exists_ips TALLOW "192.0.2.50"
    assert_rule_exists_ips TALLOW "192.0.2.51"
    assert_rule_exists_ips TDENY "198.51.100.10"
    assert_rule_exists_ips TDENY "198.51.100.11"

    # Allow and deny lists are separate files
    run grep "192.0.2.50" "$APF_DIR/allow_hosts.rules"
    assert_success
    run grep "198.51.100.10" "$APF_DIR/deny_hosts.rules"
    assert_success
    # Allowed IP should NOT be in deny file
    run grep "192.0.2.50" "$APF_DIR/deny_hosts.rules"
    assert_failure
}

# ============================================================================
# UAT-011: Search finds rules across both iptables and trust files
# Source: Troubleshooting — "why is this IP blocked?" / "is port 80 open?"
# Workflow: apf -g PORT → finds rule; apf -g IP → finds trust entry
# ============================================================================

@test "UAT-011: search finds port rules and trust entries" {
    "$APF" -a 192.0.2.50 "search-test" 2>/dev/null

    # Search for port rule in iptables output
    run "$APF" -g "dpt:80"
    assert_success
    assert_output --partial "80"

    # Search for trust entry
    run "$APF" -g "192.0.2.50"
    assert_success
    assert_output --partial "192.0.2.50"
}

# ============================================================================
# UAT-012: IPv6 dual-stack trust lifecycle
# Source: Modern server configs — IPv6 whitelisting alongside IPv4
# Workflow: add IPv6 → verify in ip6tables → lookup → remove → verify gone
# ============================================================================

@test "UAT-012: IPv6 allow/lookup/remove lifecycle" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi

    # Allow an IPv6 address
    "$APF" -a 2001:db8::50 "ipv6-office" 2>/dev/null

    # Verify in ip6tables
    assert_rule_exists_ip6s TALLOW "2001:db8::50"

    # Lookup should find it
    run "$APF" --lookup 2001:db8::50
    assert_success
    assert_output --partial "ALLOW"

    # Remove
    "$APF" -u 2001:db8::50

    # Verify gone from ip6tables
    local count
    count=$(ip6tables -S TALLOW 2>/dev/null | grep -c "2001:db8::50" || true)
    [ "$count" -eq 0 ]
}

# ============================================================================
# UAT-013: Full start→operate→restart→flush→restart lifecycle
# Source: The complete "day in the life" workflow
# Workflow: start → add trust → restart → verify survives → flush (safe) →
#           restart → verify restored from files
# ============================================================================

@test "UAT-013: full day-in-life lifecycle" {
    # Start fresh
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Add trust entries during the day
    "$APF" -a 192.0.2.50 "morning-allow" 2>/dev/null
    "$APF" -d 198.51.100.10 "morning-block" 2>/dev/null

    # Restart (e.g., after config change)
    "$APF" -r

    # State should survive restart
    assert_rule_exists_ips TALLOW "192.0.2.50"
    assert_rule_exists_ips TDENY "198.51.100.10"

    # Port rules should survive restart
    assert_rule_exists_ips INPUT "-p tcp.*--dport 22.*-j ACCEPT"
    assert_rule_exists_ips INPUT "-p tcp.*--dport 80.*-j ACCEPT"

    # Flush for maintenance
    "$APF" -f

    # After flush, policies are ACCEPT (safe state)
    local policy
    policy=$(iptables -L INPUT -n | head -1)
    echo "$policy" | grep -q "ACCEPT"

    # Restart — state restores from rules files
    "$APF" -s

    # Trust entries restored from files
    assert_rule_exists_ips TALLOW "192.0.2.50"
    assert_rule_exists_ips TDENY "198.51.100.10"
}

# ============================================================
# CLI symmetry: every form -d accepts, -u must also accept
# ============================================================

@test "UAT-014: CLI trust symmetry — all -d forms removable via -u" {
    # Simple IP
    "$APF" -d 198.51.100.77 "sym test" || fail "deny IP failed"
    run "$APF" -u 198.51.100.77
    assert_success

    # CIDR
    "$APF" -d 198.51.100.0/24 "sym cidr" || fail "deny CIDR failed"
    run "$APF" -u 198.51.100.0/24
    assert_success

    # Advanced IP syntax
    "$APF" -d "tcp:in:d=22:s=198.51.100.88" "sym adv" || fail "deny advanced IP failed"
    run "$APF" -u "tcp:in:d=22:s=198.51.100.88"
    assert_success

    # Country code (simple) — requires ipset
    if ipset_available; then
        sed -i 's/^USE_IPSET=.*/USE_IPSET="1"/' "$APF_DIR/conf.apf"
        export GEOIP_CURL_BIN="/bin/false"
        export GEOIP_WGET_BIN="/bin/false"
        mkdir -p "$APF_DIR/geoip"
        printf '192.0.2.0/24\n' > "$APF_DIR/geoip/ZZ.4"
        "$APF" -d ZZ "sym cc" || fail "deny CC failed"
        run "$APF" -u ZZ
        assert_success
        # Verify removed from rules file
        run grep -c '^ZZ$' "$APF_DIR/cc_deny.rules"
        assert_output "0"

        # Country code (advanced syntax) — UAT-001 regression
        "$APF" -d "tcp:in:d=22:s=ZZ" "sym cc adv" || fail "deny advanced CC failed"
        run "$APF" -u "tcp:in:d=22:s=ZZ"
        assert_success
        # Verify removed from rules file
        run grep -c "^tcp:in:d=22:s=ZZ$" "$APF_DIR/cc_deny.rules"
        assert_output "0"

        # Clean up CC state
        sed -i '/^[^#]/d' "$APF_DIR/cc_deny.rules" 2>/dev/null || true
        sed -i '/^# added /d' "$APF_DIR/cc_deny.rules" 2>/dev/null || true
        ipset destroy apf_cc4_ZZ 2>/dev/null || true
        rm -f "$APF_DIR/geoip/ZZ.4"
        sed -i 's/^USE_IPSET=.*/USE_IPSET="0"/' "$APF_DIR/conf.apf"
        unset GEOIP_CURL_BIN GEOIP_WGET_BIN
    fi
}
