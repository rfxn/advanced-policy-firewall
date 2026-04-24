#!/usr/bin/env bats
# 09-port-filtering.bats -- APF Port Filtering UAT
# Verifies: IG_TCP_CPORTS, IG_UDP_CPORTS, EG_TCP_CPORTS configuration
# and that the resulting iptables rules match configured ports.
# Uses high ports (50000+) to avoid conflict with container services.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-apf'
load '../helpers/assert-iptables'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_apf_install
    source /opt/tests/helpers/setup-netns.sh
    uat_apf_set_interface "veth-pub"
    # Configure known port sets before starting firewall
    uat_apf_set_port_config "IG_TCP_CPORTS" "50080,50443"
    uat_apf_set_port_config "IG_UDP_CPORTS" "50053"
    # Enable egress filtering (disabled by default) so EG_TCP_CPORTS take effect
    uat_apf_set_config "EGF" "1"
    uat_apf_set_port_config "EG_TCP_CPORTS" "50080,50443,50025"
    apf -s
}

teardown_file() {
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

# bats test_tags=uat,uat:port-filtering
@test "UAT: inbound TCP ports have iptables ACCEPT rules" {
    # IG_TCP_CPORTS should produce multiport rules in the INPUT chain area
    run iptables -S 2>/dev/null
    assert_success
    assert_output --partial "50080"
    assert_output --partial "50443"
}

# bats test_tags=uat,uat:port-filtering
@test "UAT: inbound UDP port has iptables ACCEPT rule" {
    run iptables -S 2>/dev/null
    assert_success
    assert_output --partial "50053"
    assert_output --partial "udp"
}

# bats test_tags=uat,uat:port-filtering
@test "UAT: egress TCP ports have iptables ACCEPT rules" {
    run iptables -S 2>/dev/null
    assert_success
    assert_output --partial "50025"
}

# bats test_tags=uat,uat:port-filtering
@test "UAT: changing port config and restarting applies new ports" {
    uat_apf_set_port_config "IG_TCP_CPORTS" "50080,50443,51234"
    uat_capture "port-filter" apf -r
    assert_success
    run iptables -S 2>/dev/null
    assert_success
    assert_output --partial "51234"
}

# bats test_tags=uat,uat:port-filtering
@test "UAT: removed port is no longer in iptables after restart" {
    # 50025 was in EG_TCP but we changed only IG_TCP above -- verify
    # egress still has its configured ports
    uat_apf_set_port_config "EG_TCP_CPORTS" "50080,50443"
    uat_capture "port-filter" apf -r
    assert_success
    run iptables -S 2>/dev/null
    refute_output --partial "50025"
}

# bats test_tags=uat,uat:port-filtering
@test "UAT: info command reflects configured interface" {
    uat_capture "port-filter" apf --info
    assert_success
    assert_output --partial "veth-pub"
}
