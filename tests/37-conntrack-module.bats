#!/usr/bin/env bats
#
# 37: Conntrack module migration (STATE_MATCH) — verify xt_conntrack usage
#     on modern kernels and correct firewall rule generation.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash
source /opt/tests/helpers/capability-detect.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

@test "internals.conf defines STATE_MATCH variable" {
    # Verify the variable definition exists in the source file
    grep -q 'STATE_MATCH=' "$APF_DIR/internals/internals.conf"
}

@test "STATE_MATCH detection logic uses xt_conntrack or state fallback" {
    # Verify the detection block exists
    grep -q 'xt_conntrack' "$APF_DIR/internals/internals.conf"
    grep -q 'conntrack --ctstate' "$APF_DIR/internals/internals.conf"
    grep -q 'state --state' "$APF_DIR/internals/internals.conf"
}

@test "firewall rules use conntrack or state match for ESTABLISHED" {
    # After start, state tracking rules should exist in iptables -S output
    run iptables -S INPUT
    assert_success
    assert_output --partial "ESTABLISHED"
}

@test "firewall starts correctly with STATE_MATCH" {
    # Verify the firewall loaded successfully (chains exist)
    assert_chain_exists "TALLOW"
    assert_chain_exists "TDENY"
    assert_chain_exists "TGALLOW"
    assert_chain_exists "TGDENY"
}
