#!/usr/bin/env bats
#
# 07: Packet sanity — IN_SANITY/OUT_SANITY, PZERO, FRAG_UDP, MCAST

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
    apf_set_config "PKT_SANITY_INV" "1"
    apf_set_config "PKT_SANITY_FUDP" "1"
    apf_set_config "PKT_SANITY_PZERO" "1"
    apf_set_config "BLK_MCATNET" "1"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

@test "IN_SANITY chain exists" {
    assert_chain_exists IN_SANITY
}

@test "OUT_SANITY chain exists" {
    assert_chain_exists OUT_SANITY
}

# TCP flag tests: three iptables output formats exist:
#   nft backend:        flags:0xNN/0xNN
#   legacy backend:     SYN,FIN SYN,FIN (symbolic)
#   very old legacy:    tcpflags: 0xNN/0xNN (CentOS 6, Ubuntu 12.04)
# Use alternation pattern for cross-backend portability.

@test "IN_SANITY blocks SYN,FIN pair" {
    assert_rule_exists IN_SANITY "(SYN,FIN.*SYN,FIN|flags:.*0x03/0x03)"
}

@test "IN_SANITY blocks ALL NONE (null scan)" {
    assert_rule_exists IN_SANITY "(FIN,SYN,RST,PSH,ACK,URG.*NONE|flags:.*0x3F/0x00)"
}

@test "IN_SANITY blocks SYN,RST pair" {
    assert_rule_exists IN_SANITY "(SYN,RST.*SYN,RST|flags:.*0x06/0x06)"
}

@test "OUT_SANITY blocks SYN,FIN pair" {
    assert_rule_exists OUT_SANITY "(SYN,FIN.*SYN,FIN|flags:.*0x03/0x03)"
}

@test "INPUT references IN_SANITY" {
    assert_rule_exists INPUT "IN_SANITY"
}

@test "OUTPUT references OUT_SANITY" {
    assert_rule_exists OUTPUT "OUT_SANITY"
}

@test "PZERO chain exists" {
    assert_chain_exists PZERO
}

@test "PZERO blocks TCP dst port 0" {
    assert_rule_exists PZERO "tcp.*dpt:0"
}

@test "PZERO blocks UDP dst port 0" {
    assert_rule_exists PZERO "udp.*dpt:0"
}

@test "PZERO blocks TCP src port 0" {
    assert_rule_exists PZERO "tcp.*spt:0"
}

@test "PZERO blocks UDP src port 0" {
    assert_rule_exists PZERO "udp.*spt:0"
}

@test "FRAG_UDP chain exists" {
    assert_chain_exists FRAG_UDP
}

@test "MCAST chain exists and blocks 224.0.0.0/8" {
    assert_chain_exists MCAST
    assert_rule_exists MCAST "224.0.0.0/8"
}

@test "PKT_SANITY_INV adds INVALID state blocking to IN_SANITY" {
    assert_rule_exists IN_SANITY "INVALID"
}

@test "PKT_SANITY_INV adds INVALID state blocking to OUT_SANITY" {
    assert_rule_exists OUT_SANITY "INVALID"
}
