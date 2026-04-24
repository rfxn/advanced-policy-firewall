#!/usr/bin/env bats
#
# 03: Inbound/outbound port rules and egress filtering

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    apf_set_ports "22,80,443" "53" "21,25,80,443,43" "20,21,53"
    apf_set_config "EGF" "0"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

@test "inbound TCP port 22 is open" {
    assert_rule_exists INPUT "ACCEPT.*tcp.*dpt:22"
}

@test "inbound TCP port 80 is open" {
    assert_rule_exists INPUT "ACCEPT.*tcp.*dpt:80"
}

@test "inbound TCP port 443 is open" {
    assert_rule_exists INPUT "ACCEPT.*tcp.*dpt:443"
}

@test "inbound UDP port 53 is open" {
    assert_rule_exists INPUT "ACCEPT.*udp.*dpt:53"
}

@test "ICMP types accepted" {
    # Type 8 (echo-request) should be accepted
    assert_rule_exists INPUT "ACCEPT.*icmp.*type 8"
}

@test "no inbound rule for unconfigured port 3306" {
    assert_rule_not_exists INPUT "ACCEPT.*tcp.*dpt:3306"
}

@test "EGF=0 OUTPUT has blanket ACCEPT" {
    local last_rules
    last_rules=$(iptables -L OUTPUT -n | tail -2)
    echo "$last_rules" | grep -q "ACCEPT.*0.0.0.0/0.*0.0.0.0/0"
}

@test "EGF=1 creates egress port rules and OUTPUT ends with DROP" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "EGF" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Egress TCP port 80 should be open
    assert_rule_exists OUTPUT "ACCEPT.*tcp.*dpt:80"

    # OUTPUT should end with DROP
    local last_rules
    last_rules=$(iptables -L OUTPUT -n | tail -3)
    echo "$last_rules" | grep -q "DROP"

    # Cleanup: restore EGF=0
    apf_set_config "EGF" "0"
    "$APF" -f 2>/dev/null
    "$APF" -s
}


@test "duplicate ports in IG_TCP_CPORTS produce no duplicate rules" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_ports "22,80,443,80,443" "53" "" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Port 80 should appear exactly once in INPUT ACCEPT rules
    local count
    count=$(iptables -S INPUT 2>/dev/null | grep -c '\-\-dport 80 -j ACCEPT' || true)
    [ "$count" -eq 1 ]

    # Port 443 should appear exactly once in INPUT ACCEPT rules
    count=$(iptables -S INPUT 2>/dev/null | grep -c '\-\-dport 443 -j ACCEPT' || true)
    [ "$count" -eq 1 ]

    # Cleanup
    apf_set_ports "22,80,443" "53" "21,25,80,443,43" "20,21,53"
    "$APF" -f 2>/dev/null
    "$APF" -s
}
