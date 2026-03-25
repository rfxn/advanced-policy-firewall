#!/usr/bin/env bats
#
# 21: Regression tests for 2.0.2 refactoring (Phases 1-7)
#
# Validates behavioral correctness of subprocess-to-builtin conversions:
#   - _icmp_filter() helper (Phase 5)
#   - Port list delimiter edge cases (Phase 2)
#   - expand_port() malformed ranges (Phase 3)
#   - trust_parse_fields() edge cases (Phase 3b)
#   - NDP type collision detection (Phase 5)
#   - tosroute() mangle table rules (F-048)
#
# validate_config(), trim(), and download_url() tests are in 40-validate-config.bats
# (extracted for performance — they don't need the firewall teardown cycle).

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
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

teardown() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
}

# =====================================================================
# ICMP filtering: _icmp_filter() helper (Phase 5)
# =====================================================================

@test "ICMP 'all' keyword creates protocol-only accept rule" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "IG_ICMP_TYPES" "all"
    apf_set_config "EGF" "0"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Should have a protocol-only ACCEPT rule (no --icmp-type flag)
    run iptables -S INPUT
    local found=0
    while IFS= read -r line; do
        if echo "$line" | grep -q -- '-p icmp' && \
           echo "$line" | grep -q -- '-j ACCEPT' && \
           ! echo "$line" | grep -q -- '--icmp-type'; then
            found=1
            break
        fi
    done <<< "$output"
    [ "$found" -eq 1 ]
}
@test "ICMP mixed types and 'all' keyword processes both" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "IG_ICMP_TYPES" "3,all"
    apf_set_config "EGF" "0"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Should have icmp-type 3 rule
    assert_rule_exists INPUT "ACCEPT.*icmp.*type 3"

    # Should also have protocol-only rule (no --icmp-type)
    run iptables -S INPUT
    local found=0
    while IFS= read -r line; do
        if echo "$line" | grep -q -- '-p icmp' && \
           echo "$line" | grep -q -- '-j ACCEPT' && \
           ! echo "$line" | grep -q -- '--icmp-type'; then
            found=1
            break
        fi
    done <<< "$output"
    [ "$found" -eq 1 ]
}

@test "ICMP empty types produces no ICMP accept rules" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "IG_ICMP_TYPES" ""
    apf_set_config "EGF" "0"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # No icmp ACCEPT rules should be present in INPUT
    run iptables -S INPUT
    local count
    count=$(echo "$output" | grep -c -- '-p icmp.*-j ACCEPT' || true)
    [ "$count" -eq 0 ]
}

@test "ICMP rate limiting applied when ICMP_LIM set" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "IG_ICMP_TYPES" "8"
    apf_set_config_safe "ICMP_LIM" "5/s"
    apf_set_config "EGF" "0"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Should have limit module in the ICMP rule
    assert_rule_exists_ips INPUT "icmp.*-m limit --limit 5/s.*-j ACCEPT"

    # Restore default
    apf_set_config_safe "ICMP_LIM" "30/s"
}

@test "ICMP rate limiting disabled when ICMP_LIM=0" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "IG_ICMP_TYPES" "8"
    apf_set_config_safe "ICMP_LIM" "0"
    apf_set_config "EGF" "0"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # ICMP type 8 rule should exist but without limit module
    run iptables -S INPUT
    local icmp_rule
    icmp_rule=$(echo "$output" | grep -- '-p icmp.*icmp-type 8.*-j ACCEPT' || true)
    [ -n "$icmp_rule" ]
    # Should NOT contain -m limit
    if echo "$icmp_rule" | grep -q -- '-m limit'; then
        echo "ICMP rule should NOT have rate limit when ICMP_LIM=0" >&2
        echo "Rule: $icmp_rule" >&2
        return 1
    fi

    # Restore default
    apf_set_config_safe "ICMP_LIM" "30/s"
}

@test "EGF=1 outbound ICMP 'all' creates OUTPUT accept rule" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "EGF" "1"
    apf_set_config "EG_ICMP_TYPES" "all"
    apf_set_config "IG_ICMP_TYPES" "8"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # OUTPUT should have protocol-only ICMP accept
    run iptables -S OUTPUT
    local found=0
    while IFS= read -r line; do
        if echo "$line" | grep -q -- '-p icmp' && \
           echo "$line" | grep -q -- '-j ACCEPT' && \
           ! echo "$line" | grep -q -- '--icmp-type'; then
            found=1
            break
        fi
    done <<< "$output"
    [ "$found" -eq 1 ]

    # Cleanup
    apf_set_config "EGF" "0"
}

# =====================================================================
# IPv6 NDP collision: user-specified types overlapping hardcoded 133-136
# =====================================================================

@test "IPv6 NDP 133-136 present in INPUT when ICMPv6 types also specified" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_IPV6" "1"
    apf_set_config "IG_ICMPV6_TYPES" "128"
    apf_set_config "EGF" "0"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # NDP types always present
    assert_rule_exists_ip6 INPUT "ipv6-icmp.*type 133"
    assert_rule_exists_ip6 INPUT "ipv6-icmp.*type 134"
    assert_rule_exists_ip6 INPUT "ipv6-icmp.*type 135"
    assert_rule_exists_ip6 INPUT "ipv6-icmp.*type 136"

    # User type 128 also present
    assert_rule_exists_ip6 INPUT "ipv6-icmp.*type 128"

    apf_set_config "USE_IPV6" "0"
}

@test "IPv6 EGF=1 outbound NDP 133-136 plus user ICMPv6 types" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_IPV6" "1"
    apf_set_config "EGF" "1"
    apf_set_config "EG_ICMPV6_TYPES" "128,129"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Outbound NDP always present
    assert_rule_exists_ip6 OUTPUT "ipv6-icmp.*type 133"
    assert_rule_exists_ip6 OUTPUT "ipv6-icmp.*type 136"

    # User types also present
    assert_rule_exists_ip6 OUTPUT "ipv6-icmp.*type 128"
    assert_rule_exists_ip6 OUTPUT "ipv6-icmp.*type 129"

    # Cleanup
    apf_set_config "EGF" "0"
    apf_set_config "USE_IPV6" "0"
}

# =====================================================================
# Port list delimiter edge cases (Phase 2)
# =====================================================================

@test "port list with trailing comma handled gracefully" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_ports "22,80," "" "" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Valid ports should be open
    assert_rule_exists INPUT "ACCEPT.*tcp.*dpt:22"
    assert_rule_exists INPUT "ACCEPT.*tcp.*dpt:80"
}

@test "port list with leading comma handled gracefully" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_ports ",22,80" "" "" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists INPUT "ACCEPT.*tcp.*dpt:22"
    assert_rule_exists INPUT "ACCEPT.*tcp.*dpt:80"
}

@test "port list with double comma handled gracefully" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_ports "22,,80" "" "" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists INPUT "ACCEPT.*tcp.*dpt:22"
    assert_rule_exists INPUT "ACCEPT.*tcp.*dpt:80"
}

@test "single port in list works correctly" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_ports "443" "" "" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists INPUT "ACCEPT.*tcp.*dpt:443"
    assert_rule_not_exists INPUT "ACCEPT.*tcp.*dpt:22"
}

# =====================================================================
# expand_port() malformed range handling (Phase 3)
# =====================================================================

@test "expand_port converts underscore range correctly" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_ports "22,8000_8080,443" "" "" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists INPUT "ACCEPT.*tcp.*dpt:22"
    assert_rule_exists INPUT "ACCEPT.*tcp.*dpts:8000:8080"
    assert_rule_exists INPUT "ACCEPT.*tcp.*dpt:443"
}

@test "expand_port plain port without underscore passes through" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_ports "22" "" "" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists INPUT "ACCEPT.*tcp.*dpt:22"
}

@test "UDP port range with underscore notation works" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_ports "" "1000_2000" "" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists INPUT "ACCEPT.*udp.*dpts:1000:2000"
}

# =====================================================================
# Dlist invalid entry filtering (Phase 6 -- regex validation)
# =====================================================================

@test "dlist skips entries with invalid CIDR suffix" {
    source /opt/tests/helpers/apf-config.sh
    "$APF" -f 2>/dev/null || true

    cat > "$APF_DIR/ds_hosts.rules" <<'EOF'
# DShield with invalid CIDR
192.0.2.30
192.0.2.0/33
192.0.2.31
EOF
    chmod 600 "$APF_DIR/ds_hosts.rules"

    apf_set_config "DLIST_DSHIELD" "1"
    apf_set_url "DLIST_DSHIELD_URL" "https://127.0.0.1:1/nonexistent"
    apf_set_config "DLIST_PHP" "0"
    apf_set_config "DLIST_SPAMHAUS" "0"

    "$APF" -s

    # Valid entries loaded
    assert_rule_exists_ips DSHIELD "192.0.2.30"
    assert_rule_exists_ips DSHIELD "192.0.2.31"

    # /33 is invalid CIDR — should not be loaded
    run iptables -S DSHIELD
    if echo "$output" | grep -q "192.0.2.0/33"; then
        echo "Invalid CIDR /33 should have been rejected" >&2
        return 1
    fi

    # Cleanup
    apf_set_config "DLIST_DSHIELD" "0"
}

@test "dlist skips comment lines in rules file" {
    source /opt/tests/helpers/apf-config.sh
    "$APF" -f 2>/dev/null || true

    cat > "$APF_DIR/ds_hosts.rules" <<'EOF'
# Full line comment
192.0.2.40
 # Indented comment
192.0.2.41
EOF
    chmod 600 "$APF_DIR/ds_hosts.rules"

    apf_set_config "DLIST_DSHIELD" "1"
    apf_set_url "DLIST_DSHIELD_URL" "https://127.0.0.1:1/nonexistent"
    apf_set_config "DLIST_PHP" "0"
    apf_set_config "DLIST_SPAMHAUS" "0"

    "$APF" -s

    # Only valid IPs loaded
    assert_rule_exists_ips DSHIELD "192.0.2.40"
    assert_rule_exists_ips DSHIELD "192.0.2.41"

    # Comment text should not appear as an IP
    run iptables -S DSHIELD
    if echo "$output" | grep -qi "comment"; then
        echo "Comment text should not appear in DSHIELD chain" >&2
        return 1
    fi

    apf_set_config "DLIST_DSHIELD" "0"
}

# =====================================================================
# P0 bug fix regression tests
# =====================================================================

# Check if xt_mac module is available (needed for lgate_mac)
mac_module_available() {
    iptables -A INPUT -m mac --mac-source AA:BB:CC:DD:EE:FF -j DROP 2>/dev/null || return 1
    iptables -D INPUT -m mac --mac-source AA:BB:CC:DD:EE:FF -j DROP 2>/dev/null
    return 0
}

@test "lgate_mac creates LMAC chain with VF_LGATE set" {
    if ! mac_module_available; then skip "xt_mac module not available"; fi
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "VF_LGATE" "AA:BB:CC:DD:EE:FF"

    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_chain_exists LMAC
    assert_rule_exists_ips LMAC "REJECT"

    # Cleanup
    apf_set_config "VF_LGATE" ""
}

# =====================================================================
# P1 sed dot-escape and malformed timestamp tests
# =====================================================================

@test "apf -u escapes dots in sed IP pattern" {
    source /opt/tests/helpers/apf-config.sh
    # Add target IP and a similar entry that differs only by dot vs other char
    echo "192.0.2.70" >> "$APF_DIR/allow_hosts.rules"
    echo "192X0X2X70" >> "$APF_DIR/allow_hosts.rules"

    "$APF" -f 2>/dev/null
    "$APF" -s
    "$APF" -u 192.0.2.70

    # Target should be removed
    run grep "^192\.0\.2\.70$" "$APF_DIR/allow_hosts.rules"
    assert_failure

    # Similar entry with X instead of . should be preserved
    run grep "^192X0X2X70$" "$APF_DIR/allow_hosts.rules"
    assert_success

    # Cleanup
    sed -i '/192X0X2X70/d' "$APF_DIR/allow_hosts.rules"
}

@test "expirebans handles malformed timestamp gracefully" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_EXPIRE" "60"
    apf_set_config "SET_REFRESH" "1"

    # Add a valid deny entry with proper format (old date — should expire)
    echo "198.51.100.90" >> "$APF_DIR/deny_hosts.rules"
    echo "# added 198.51.100.90 on 2020-01-01 00:00:00" >> "$APF_DIR/deny_hosts.rules"

    # Add a deny entry with malformed timestamp
    echo "198.51.100.91" >> "$APF_DIR/deny_hosts.rules"
    echo "# added 198.51.100.91 on BADDATE BADTIME" >> "$APF_DIR/deny_hosts.rules"

    "$APF" -f 2>/dev/null
    "$APF" -s
    # Trigger refresh which calls expirebans()
    run "$APF" -e
    assert_success

    # The valid old entry (2020) should have been expired (>60s ago)
    # Use ^ anchor since comment lines still contain the IP
    run grep "^198.51.100.90" "$APF_DIR/deny_hosts.rules"
    assert_failure

    # The malformed entry should be preserved (skipped by date parse failure)
    run grep "^198.51.100.91" "$APF_DIR/deny_hosts.rules"
    assert_success

    # Cleanup
    sed -i '/198\.51\.100\.9[01]/d' "$APF_DIR/deny_hosts.rules"
    apf_set_config "SET_EXPIRE" "0"
}

# =====================================================================
# tosroute() mangle table rules (F-048)
# =====================================================================

# Check if xt_TOS module is available
tos_module_available() {
    iptables -t mangle -A OUTPUT -p tcp --dport 9999 -j TOS --set-tos 8 2>/dev/null || return 1
    iptables -t mangle -D OUTPUT -p tcp --dport 9999 -j TOS --set-tos 8 2>/dev/null
    return 0
}

@test "tosroute creates mangle TOS rules for configured ports" {
    if ! tos_module_available; then skip "xt_TOS module not available"; fi
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "TOS_8" "80"

    "$APF" -s

    run iptables -t mangle -S POSTROUTING
    assert_output --partial "dport 80"
    assert_output --partial "TOS"
}
