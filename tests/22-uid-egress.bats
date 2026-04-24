#!/usr/bin/env bats
#
# 22: UID-based and command-based egress filtering
#
# Validates EG_TCP_UID, EG_UDP_UID (--uid-owner rules) and
# EG_DROP_CMD (--cmd-owner rules) in cports.common.

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
    apf_set_config "EGF" "1"

    # Detect --uid-owner support (always available on modern kernels)
    _UID_OWNER_OK=""
    if iptables -N _UID_TEST 2>/dev/null && \
       iptables -A _UID_TEST -m owner --uid-owner [0r] -j DROP 2>/dev/null; then
        _UID_OWNER_OK=1
        iptables -F _UID_TEST 2>/dev/null
        iptables -X _UID_TEST 2>/dev/null
    else
        iptables -F _UID_TEST 2>/dev/null
        iptables -X _UID_TEST 2>/dev/null
    fi
    export _UID_OWNER_OK

    # Detect --cmd-owner support (removed in kernel 3.x)
    _CMD_OWNER_OK=""
    if iptables -N _CMD_TEST 2>/dev/null && \
       iptables -A _CMD_TEST -m owner --cmd-owner=_test -j DROP 2>/dev/null; then
        _CMD_OWNER_OK=1
        iptables -F _CMD_TEST 2>/dev/null
        iptables -X _CMD_TEST 2>/dev/null
    else
        iptables -F _CMD_TEST 2>/dev/null
        iptables -X _CMD_TEST 2>/dev/null
    fi
    export _CMD_OWNER_OK

    # Detect --gid-owner support
    _GID_OWNER_OK=""
    if iptables -N _GID_TEST 2>/dev/null && \
       iptables -A _GID_TEST -m owner --gid-owner 0 -j DROP 2>/dev/null; then
        _GID_OWNER_OK=1
    fi
    iptables -F _GID_TEST 2>/dev/null
    iptables -X _GID_TEST 2>/dev/null
    export _GID_OWNER_OK
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

# =====================================================================
# EG_TCP_UID / EG_UDP_UID tests
# =====================================================================

@test "EG_TCP_UID creates uid-owner ACCEPT rule for TCP port" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "EG_TCP_UID" "0:22"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips OUTPUT "-p tcp.*--dport 22.*--uid-owner [0r].*ACCEPT"
}

@test "EG_TCP_UID handles multiple uid:port pairs" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "EG_TCP_UID" "0:22,33:80"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips OUTPUT "-p tcp.*--dport 22.*--uid-owner [0r].*ACCEPT"
    assert_rule_exists_ips OUTPUT "-p tcp.*--dport 80.*--uid-owner [3w].*ACCEPT"
}

@test "EG_TCP_UID with port range (underscore notation)" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "EG_TCP_UID" "0:8000_8080"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips OUTPUT "-p tcp.*--dport 8000:8080.*--uid-owner [0r].*ACCEPT"
}

@test "EG_UDP_UID creates uid-owner ACCEPT rule for UDP port" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "EG_UDP_UID" "0:53"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips OUTPUT "-p udp.*--dport 53.*--uid-owner [0r].*ACCEPT"
}

@test "EG_TCP_UID empty produces no uid-owner rules" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "EG_TCP_UID" ""
    apf_set_config "EG_UDP_UID" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    run iptables -S OUTPUT
    # No uid-owner rules should exist
    ! echo "$output" | grep -q -- "--uid-owner"
}

# =====================================================================
# EG_DROP_CMD tests
# =====================================================================

@test "EG_DROP_CMD creates DEG chain with cmd-owner rules" {
    [ -n "$_CMD_OWNER_OK" ] || skip "--cmd-owner not supported by this kernel"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "EG_DROP_CMD" "eggdrop,psybnc"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # DEG chain should exist
    assert_chain_exists DEG

    # OUTPUT should jump to DEG
    assert_rule_exists_ips OUTPUT "-j DEG"

    # DEG should have cmd-owner rules
    run iptables -S DEG
    assert_success
    echo "$output" | grep -q -- "--cmd-owner"
}

@test "EG_DROP_CMD LOG rules include cmd-owner filter" {
    [ -n "$_CMD_OWNER_OK" ] || skip "--cmd-owner not supported by this kernel"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "EG_DROP_CMD" "eggdrop"
    apf_set_config "LOG_DROP" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # LOG rule in DEG should include --cmd-owner
    run iptables -S DEG
    assert_success
    echo "$output" | grep -q "LOG.*--cmd-owner"
}

@test "EG_DROP_CMD graceful skip when --cmd-owner unsupported" {
    [ -z "$_CMD_OWNER_OK" ] || skip "--cmd-owner IS supported; testing skip path"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "EG_DROP_CMD" "eggdrop,psybnc"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # DEG chain should NOT exist
    assert_chain_not_exists DEG

    # Log should mention the skip
    run grep "cmd-owner not supported" /var/log/apf_log
    assert_success
}

@test "EG_DROP_CMD empty produces no DEG chain" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "EG_DROP_CMD" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_chain_not_exists DEG
}

# =====================================================================
# SMTP_BLOCK tests
# =====================================================================

@test "SMTP_BLOCK=0 produces no SMTP_BLK chain" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SMTP_BLOCK" "0"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_chain_not_exists SMTP_BLK
}

@test "SMTP_BLOCK=1 creates SMTP_BLK chain" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SMTP_BLOCK" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_chain_exists SMTP_BLK
    # OUTPUT should jump to SMTP_BLK
    assert_rule_exists_ips OUTPUT "-j SMTP_BLK"
}

@test "SMTP_BLK allows root (UID 0)" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SMTP_BLOCK" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips SMTP_BLK "-p tcp.*--dports 25,465,587.*--uid-owner [0r].*ACCEPT"
}

@test "SMTP_ALLOWUSER allows listed user" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SMTP_BLOCK" "1"
    apf_set_config "SMTP_ALLOWUSER" "nobody"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips SMTP_BLK "-p tcp.*--dports.*--uid-owner nobody.*ACCEPT"
}

@test "SMTP_ALLOWGROUP allows listed group" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    [ -n "$_GID_OWNER_OK" ] || skip "--gid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SMTP_BLOCK" "1"
    apf_set_config "SMTP_ALLOWGROUP" "mail"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips SMTP_BLK "-p tcp.*--dports.*--gid-owner mail.*ACCEPT"
}

@test "SMTP_BLK has DROP/REJECT rule at end" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SMTP_BLOCK" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Should have a DROP or REJECT rule for SMTP ports
    run iptables -S SMTP_BLK
    assert_success
    echo "$output" | grep -qE -- "--dports 25,465,587 -j (DROP|REJECT)"
}

@test "SMTP_BLK applies to custom SMTP_PORTS" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SMTP_BLOCK" "1"
    apf_set_config "SMTP_PORTS" "25,587"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips SMTP_BLK "--dports 25,587"
    # Should NOT have port 465
    run iptables -S SMTP_BLK
    ! echo "$output" | grep -q "465"
}

@test "SMTP_BLOCK works with EGF=0" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "EGF" "0"
    apf_set_config "SMTP_BLOCK" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # SMTP_BLK chain should exist even with EGF=0
    assert_chain_exists SMTP_BLK
    assert_rule_exists_ips OUTPUT "-j SMTP_BLK"
}

@test "SMTP_BLK LOG rule when LOG_DROP=1" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SMTP_BLOCK" "1"
    apf_set_config "LOG_DROP" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips SMTP_BLK "LOG.*SMTP_BLK"
}

@test "SMTP_BLK no LOG rule when LOG_DROP=0" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SMTP_BLOCK" "1"
    apf_set_config "LOG_DROP" "0"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Chain should still exist with ACCEPT and DROP/REJECT rules
    assert_chain_exists SMTP_BLK
    assert_rule_exists_ips SMTP_BLK "--uid-owner [0r].*ACCEPT"
    run iptables -S SMTP_BLK
    assert_success
    echo "$output" | grep -qE -- "--dports 25,465,587 -j (DROP|REJECT)"
    # LOG rule must be absent
    ! echo "$output" | grep -q "LOG"
}

@test "SMTP_BLOCK=1 with empty SMTP_PORTS produces no chain" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SMTP_BLOCK" "1"
    apf_set_config "SMTP_PORTS" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_chain_not_exists SMTP_BLK
}

@test "SMTP_BLK creates IPv6 rules when USE_IPV6=1" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SMTP_BLOCK" "1"
    apf_set_config "USE_IPV6" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # IPv6 SMTP_BLK chain should exist with root ACCEPT and DROP/REJECT
    assert_rule_exists_ip6s SMTP_BLK "-p tcp.*--dports 25,465,587.*--uid-owner [0r].*ACCEPT"
    run ip6tables -S SMTP_BLK
    assert_success
    echo "$output" | grep -qE -- "--dports 25,465,587 -j (DROP|REJECT)"
}

@test "SMTP_ALLOWUSER with multiple comma-separated users" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SMTP_BLOCK" "1"
    apf_set_config "SMTP_ALLOWUSER" "nobody,daemon"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips SMTP_BLK "-p tcp.*--dports.*--uid-owner nobody.*ACCEPT"
    assert_rule_exists_ips SMTP_BLK "-p tcp.*--dports.*--uid-owner daemon.*ACCEPT"
}

@test "SMTP_BLOCK=1 with EGF=1 and SMTP port in EG_TCP_CPORTS" {
    [ -n "$_UID_OWNER_OK" ] || skip "--uid-owner not supported"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "EGF" "1"
    apf_set_config "EG_TCP_CPORTS" "25,80,443"
    apf_set_config "SMTP_BLOCK" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # SMTP_BLK chain still exists (created regardless of EGF)
    assert_chain_exists SMTP_BLK
    assert_rule_exists_ips OUTPUT "-j SMTP_BLK"
    # Note: EG_TCP_CPORTS ACCEPT for port 25 fires before SMTP_BLK jump
    # in OUTPUT chain, so SMTP blocking is effectively bypassed for port 25.
    # This is a documented configuration conflict (see conf.apf).
}
