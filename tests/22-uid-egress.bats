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
