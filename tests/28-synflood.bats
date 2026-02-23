#!/usr/bin/env bats
#
# 28: SYN flood protection (SYNFLOOD)
#
# Validates SYNFLOOD rate limiting: disabled produces no chain, enabled
# creates SYNFLOOD chain with limit/burst rules, LOG when LOG_DROP=1,
# $TCP_STOP drop, dual-stack IPv6, correct chain ordering (RETURN before
# DROP), and INPUT jump attachment.

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
    source /opt/tests/helpers/teardown-netns.sh
}

# =====================================================================
# Disabled state
# =====================================================================

@test "SYNFLOOD=0 produces no SYNFLOOD chain" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SYNFLOOD" "0"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_chain_not_exists SYNFLOOD
}

# =====================================================================
# Chain creation
# =====================================================================

@test "SYNFLOOD=1 creates SYNFLOOD chain" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SYNFLOOD" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_chain_exists SYNFLOOD
}

# =====================================================================
# Rate/burst configuration
# =====================================================================

@test "SYNFLOOD chain has limit rule with configured rate and burst" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SYNFLOOD" "1"
    apf_set_config_safe "SYNFLOOD_RATE" "100/s"
    apf_set_config "SYNFLOOD_BURST" "150"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips SYNFLOOD "tcp.*tcp-flags.*SYN.*limit.*100/sec.*burst 150.*RETURN"
}

# =====================================================================
# Drop action
# =====================================================================

@test "SYNFLOOD chain has TCP_STOP drop rule" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SYNFLOOD" "1"
    apf_set_config "TCP_STOP" "DROP"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips SYNFLOOD "tcp.*tcp-flags.*SYN.*-j DROP"
}

# =====================================================================
# IPv6 dual-stack
# =====================================================================

@test "SYNFLOOD creates IPv6 rules when USE_IPV6=1" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SYNFLOOD" "1"
    apf_set_config "USE_IPV6" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ip6s SYNFLOOD "tcp.*tcp-flags.*SYN.*RETURN"
}

# =====================================================================
# Logging
# =====================================================================

@test "SYNFLOOD LOG rule present when LOG_DROP=1" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SYNFLOOD" "1"
    apf_set_config "LOG_DROP" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips SYNFLOOD "tcp.*tcp-flags.*SYN.*LOG.*SYNFLOOD"
}

# =====================================================================
# Chain ordering — RETURN before DROP
# =====================================================================

@test "SYNFLOOD RETURN rule appears before DROP rule" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SYNFLOOD" "1"
    apf_set_config "TCP_STOP" "DROP"
    "$APF" -f 2>/dev/null
    "$APF" -s

    local rules
    rules=$(iptables -S SYNFLOOD 2>/dev/null)
    local return_line drop_line
    return_line=$(echo "$rules" | grep -n "RETURN" | head -1 | cut -d: -f1)
    drop_line=$(echo "$rules" | grep -n "\-j DROP" | head -1 | cut -d: -f1)

    [ -n "$return_line" ] || { echo "No RETURN rule found"; echo "$rules"; return 1; }
    [ -n "$drop_line" ] || { echo "No DROP rule found"; echo "$rules"; return 1; }
    [ "$return_line" -lt "$drop_line" ] || {
        echo "RETURN (line $return_line) should appear before DROP (line $drop_line)" >&2
        echo "$rules" >&2
        return 1
    }
}

# =====================================================================
# INPUT chain jump
# =====================================================================

@test "INPUT chain jumps to SYNFLOOD" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SYNFLOOD" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips INPUT "-j SYNFLOOD"
}
