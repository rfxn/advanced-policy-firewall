#!/usr/bin/env bats
#
# 15: RAB (Reactive Address Blocking) — chain structure and portscan rules
#
# RAB requires the xt_recent or ipt_recent kernel module. Docker containers
# may not have this module available. Tests skip gracefully when unavailable.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

# Check if xt_recent/ipt_recent is available
rab_available() {
    modprobe --dry-run xt_recent 2>/dev/null || modprobe --dry-run ipt_recent 2>/dev/null
}

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/install-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""

    if rab_available; then
        apf_set_config "RAB" "1"
        apf_set_config "RAB_PSCAN_LEVEL" "1"
        apf_set_config "RAB_LOG_HIT" "1"
        apf_set_config "RAB_LOG_TRIP" "1"
    fi

    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

@test "RAB disabled when xt_recent module unavailable" {
    if rab_available; then
        skip "xt_recent is available — RAB is enabled"
    fi
    # When module is unavailable, RAB should be force-disabled
    # and RABPSCAN chain should not exist
    run iptables -L RABPSCAN -n 2>/dev/null
    assert_failure
}

@test "RAB trip rule exists in INPUT" {
    if ! rab_available; then
        skip "xt_recent module not available"
    fi
    # RAB adds a --rcheck or --update rule to INPUT with xt_recent
    assert_rule_exists_ips INPUT "recent"
}

@test "RABPSCAN chain exists when RAB_PSCAN_LEVEL set" {
    if ! rab_available; then
        skip "xt_recent module not available"
    fi
    assert_chain_exists RABPSCAN
}

@test "RABPSCAN chain attached to INPUT" {
    if ! rab_available; then
        skip "xt_recent module not available"
    fi
    assert_rule_exists_ips INPUT "RABPSCAN"
}

@test "RABPSCAN has port monitoring rules" {
    if ! rab_available; then
        skip "xt_recent module not available"
    fi
    # RAB_PSCAN_LEVEL=1 monitors ports from RAB_PSCAN_LEVEL_1
    # Check that TCP and UDP rules with --recent --set exist
    local rules
    rules=$(iptables -S RABPSCAN 2>/dev/null)
    echo "$rules" | grep -q -- "-p tcp"
    echo "$rules" | grep -q -- "-p udp"
}

@test "RABPSCAN has log rules when RAB_LOG_HIT=1" {
    if ! rab_available; then
        skip "xt_recent module not available"
    fi
    assert_rule_exists_ips RABPSCAN "LOG.*RABHIT"
}

@test "RAB trip log rule exists when RAB_LOG_TRIP=1" {
    if ! rab_available; then
        skip "xt_recent module not available"
    fi
    assert_rule_exists_ips INPUT "LOG.*RABTRIP"
}
