#!/usr/bin/env bats
#
# 02: Chain structure after firewall start

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    apf_set_config "PKT_SANITY" "1"
    apf_set_config "BLK_MCATNET" "0"
    apf_set_config "BLK_PRVNET" "0"
    apf_set_config "EGF" "0"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

@test "TALLOW chain exists" {
    assert_chain_exists TALLOW
}

@test "TDENY chain exists" {
    assert_chain_exists TDENY
}

@test "TGALLOW chain exists" {
    assert_chain_exists TGALLOW
}

@test "TGDENY chain exists" {
    assert_chain_exists TGDENY
}

@test "REFRESH_TEMP chain exists" {
    assert_chain_exists REFRESH_TEMP
}

@test "RESET chain exists" {
    assert_chain_exists RESET
}

@test "PROHIBIT chain exists" {
    assert_chain_exists PROHIBIT
}

@test "P2P chain exists" {
    assert_chain_exists P2P
}

@test "INPUT references TALLOW chain" {
    assert_rule_exists INPUT "TALLOW"
}

@test "INPUT references TDENY chain" {
    assert_rule_exists INPUT "TDENY"
}

@test "OUTPUT references TALLOW chain" {
    assert_rule_exists OUTPUT "TALLOW"
}

@test "OUTPUT references TDENY chain" {
    assert_rule_exists OUTPUT "TDENY"
}

@test "INPUT references REFRESH_TEMP chain" {
    assert_rule_exists INPUT "REFRESH_TEMP"
}

@test "loopback ACCEPT rule in INPUT" {
    assert_rule_exists INPUT "ACCEPT.*lo"
}

@test "loopback ACCEPT rule in OUTPUT" {
    assert_rule_exists OUTPUT "ACCEPT.*lo"
}

@test "default INPUT ends with DROP" {
    # The last rule(s) should be DROP targets
    local rules
    rules=$(iptables -L INPUT -n | tail -3)
    echo "$rules" | grep -q "DROP"
}

@test "default OUTPUT has ACCEPT when EGF=0" {
    # With EGF=0, OUTPUT policy is ACCEPT and an explicit ACCEPT-all rule exists
    assert_chain_policy OUTPUT ACCEPT
}

@test "MSS clamping rule in OUTPUT" {
    assert_rule_exists OUTPUT "TCPMSS.*clamp"
}
