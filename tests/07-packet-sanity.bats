#!/usr/bin/env bats
#
# 07: Packet sanity — IN_SANITY/OUT_SANITY, PZERO, FRAG_UDP, MCAST

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/install-apf.sh
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

# TCP flag tests: nft backend shows flags as hex (0xNN/0xNN)
# FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 URG=0x20
# SYN,FIN=0x03  SYN,RST=0x06  ALL=0x3F  NONE=0x00

@test "IN_SANITY blocks SYN,FIN pair" {
    # SYN,FIN SYN,FIN → mask 0x03 match 0x03
    assert_rule_exists IN_SANITY "flags:0x03/0x03"
}

@test "IN_SANITY blocks ALL NONE (null scan)" {
    # ALL NONE → mask 0x3F match 0x00
    assert_rule_exists IN_SANITY "flags:0x3F/0x00"
}

@test "IN_SANITY blocks SYN,RST pair" {
    # SYN,RST SYN,RST → mask 0x06 match 0x06
    assert_rule_exists IN_SANITY "flags:0x06/0x06"
}

@test "OUT_SANITY blocks SYN,FIN pair" {
    assert_rule_exists OUT_SANITY "flags:0x03/0x03"
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
