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
    source /opt/tests/helpers/reset-apf.sh
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

@test "RAB_LOG_HIT=1 installs RABHIT rule with LOG_DROP=0 (decoupled)" {
    # Regression: RAB_LOG_HIT is a per-feature opt-in independent of LOG_DROP.
    # Prior OR-gate (LOG_DROP=1 || RAB_LOG_HIT=1) was structurally similar
    # but kept LOG_DROP entangled; explicit decoupling confirms LOG_DROP=0
    # does not silently force-suppress when per-feature flag is on.
    if ! rab_available; then
        skip "xt_recent module not available"
    fi
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "LOG_DROP" "0"
    apf_set_config "RAB_LOG_HIT" "1"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    assert_rule_exists_ips RABPSCAN "LOG.*RABHIT"
}

@test "RAB_LOG_HIT=0 LOG_DROP=1 no longer installs RABHIT rule (was OR-gated)" {
    # Behavior change: previously LOG_DROP=1 force-enabled RAB logs even with
    # RAB_LOG_HIT=0 (documented as "LOG_DROP=1 overrides to force logging").
    # Now per-feature opt-in is the sole gate. Operators relying on the prior
    # OR-semantic must set RAB_LOG_HIT=1 explicitly.
    if ! rab_available; then
        skip "xt_recent module not available"
    fi
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "LOG_DROP" "1"
    apf_set_config "RAB_LOG_HIT" "0"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    run iptables -S RABPSCAN 2>/dev/null
    if echo "$output" | grep -qE "LOG.*RABHIT"; then
        echo "expected no RABHIT LOG rule with RAB_LOG_HIT=0; got:" >&2
        echo "$output" >&2
        return 1
    fi

    # Restore for any subsequent tests
    apf_set_config "RAB_LOG_HIT" "1"
    apf_set_config "LOG_DROP" "0"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
}
