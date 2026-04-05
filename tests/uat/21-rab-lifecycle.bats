#!/usr/bin/env bats
# 21-rab-lifecycle.bats — RAB (Reactive Address Blocking) Operator Workflows
# Validates: RAB enable/disable, PSCAN level variants, TRIP modes,
# HITCOUNT auto-promote, SANITY integration, restart persistence.
#
# Does NOT duplicate tests/15-rab.bats (7 tests covering basic chain/rule
# presence). This file tests config-to-behavior mapping from the operator
# perspective — changing RAB config values and verifying observable effects.
#
# Requires: xt_recent kernel module (skip-guarded).

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-apf'
load '../helpers/assert-iptables'
load '../infra/lib/uat-helpers'

rab_available() {
    modprobe --dry-run xt_recent 2>/dev/null || modprobe --dry-run ipt_recent 2>/dev/null
}

setup_file() {
    uat_setup
    uat_apf_install
    source /opt/tests/helpers/setup-netns.sh
    uat_apf_set_interface "veth-pub"
    uat_apf_set_port_config "IG_TCP_CPORTS" "22,80,443"
    uat_apf_set_port_config "EG_TCP_CPORTS" "22,80,443"
    uat_apf_set_config "EGF" "1"
}

teardown_file() {
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

setup() {
    # Flush between tests so each gets a clean rule state
    apf -f 2>/dev/null || true  # safe: may not be running
    rm -f "$APF_INSTALL/lock.utime"
}

# =========================================================================
# UAT-RL01: RAB=1 activation log
# Scenario: Sysadmin enables RAB and checks log for confirmation
# =========================================================================

# bats test_tags=uat,uat:rab
@test "UAT: RAB=1 start logs activation message" {
    if ! rab_available; then skip "xt_recent module not available"; fi
    uat_apf_set_config "RAB" "1"
    uat_apf_set_config "RAB_PSCAN_LEVEL" "1"
    uat_apf_set_config "RAB_LOG_HIT" "1"
    truncate -s 0 /var/log/apf_log

    apf -s
    grep -q "set active RAB" /var/log/apf_log
}

# =========================================================================
# UAT-RL02: RAB=0 — no RAB artifacts
# Scenario: Sysadmin verifies RAB is completely off
# =========================================================================

# bats test_tags=uat,uat:rab
@test "UAT: RAB=0 start creates no RABPSCAN chain" {
    uat_apf_set_config "RAB" "0"
    truncate -s 0 /var/log/apf_log

    apf -s
    assert_chain_not_exists RABPSCAN
    ! grep -q "set active RAB" /var/log/apf_log
}

# =========================================================================
# UAT-RL03: PSCAN_LEVEL=2 medium security ports
# Scenario: Sysadmin increases scan detection sensitivity
# =========================================================================

# bats test_tags=uat,uat:rab
@test "UAT: RAB_PSCAN_LEVEL=2 monitors medium security ports" {
    if ! rab_available; then skip "xt_recent module not available"; fi
    uat_apf_set_config "RAB" "1"
    uat_apf_set_config "RAB_PSCAN_LEVEL" "2"

    apf -s
    assert_chain_exists RABPSCAN
    # Level 2 includes finger (79) — a medium-risk port not in level 1
    assert_rule_exists_ips RABPSCAN "dport 79"
}

# =========================================================================
# UAT-RL04: PSCAN_LEVEL=3 high security ports
# Scenario: Sysadmin sets maximum scan detection
# =========================================================================

# bats test_tags=uat,uat:rab
@test "UAT: RAB_PSCAN_LEVEL=3 monitors high security ports" {
    if ! rab_available; then skip "xt_recent module not available"; fi
    uat_apf_set_config "RAB" "1"
    uat_apf_set_config "RAB_PSCAN_LEVEL" "3"

    apf -s
    assert_chain_exists RABPSCAN
    # Level 3 includes port 666 — a high-risk port not in levels 1 or 2
    assert_rule_exists_ips RABPSCAN "dport 666"
}

# =========================================================================
# UAT-RL05: RAB_TRIP=0 uses --rcheck (no timer reset)
# Scenario: Sysadmin configures fixed-duration blocks
# =========================================================================

# bats test_tags=uat,uat:rab
@test "UAT: RAB_TRIP=0 uses --rcheck flag" {
    if ! rab_available; then skip "xt_recent module not available"; fi
    uat_apf_set_config "RAB" "1"
    uat_apf_set_config "RAB_TRIP" "0"
    uat_apf_set_config "RAB_PSCAN_LEVEL" "1"

    apf -s
    # --rcheck means block duration is fixed (no extension on re-offense)
    run iptables -S INPUT
    assert_output --partial "rcheck"
}

# =========================================================================
# UAT-RL06: RAB_TRIP=1 uses --update (timer resets)
# Scenario: Sysadmin configures extending blocks on repeat offense
# =========================================================================

# bats test_tags=uat,uat:rab
@test "UAT: RAB_TRIP=1 uses --update flag" {
    if ! rab_available; then skip "xt_recent module not available"; fi
    uat_apf_set_config "RAB" "1"
    uat_apf_set_config "RAB_TRIP" "1"
    uat_apf_set_config "RAB_PSCAN_LEVEL" "1"

    apf -s
    # --update means block timer resets on each new violation
    run iptables -S INPUT
    assert_output --partial "update"
}

# =========================================================================
# UAT-RL07: RAB_HITCOUNT=0 auto-promotes to 1
# Scenario: Sysadmin sets hitcount=0, APF auto-corrects to 1
# =========================================================================

# bats test_tags=uat,uat:rab
@test "UAT: RAB_HITCOUNT=0 auto-promotes to hitcount 1" {
    if ! rab_available; then skip "xt_recent module not available"; fi
    uat_apf_set_config "RAB" "1"
    uat_apf_set_config "RAB_HITCOUNT" "0"
    uat_apf_set_config "RAB_PSCAN_LEVEL" "1"

    apf -s
    # hitcount 0 is invalid — APF promotes to 1
    run iptables -S INPUT
    assert_output --partial "hitcount 1"
}

# =========================================================================
# UAT-RL08: RAB_SANITY=1 injects recent tracking into packet sanity
# Scenario: Sysadmin enables sanity-violation tracking
# =========================================================================

# bats test_tags=uat,uat:rab
@test "UAT: RAB_SANITY=1 adds recent tracking to packet sanity rules" {
    if ! rab_available; then skip "xt_recent module not available"; fi
    uat_apf_set_config "RAB" "1"
    uat_apf_set_config "RAB_SANITY" "1"
    uat_apf_set_config "PKT_SANITY" "1"
    uat_apf_set_config "RAB_PSCAN_LEVEL" "1"

    apf -s
    # Packet sanity chain should include "recent --set" for RAB tracking
    run iptables -S IN_SANITY
    assert_output --partial "recent --set"
}

# =========================================================================
# UAT-RL09: RAB survives restart
# Scenario: Sysadmin restarts firewall, RAB remains configured
# =========================================================================

# bats test_tags=uat,uat:rab
@test "UAT: RAB survives restart with same configuration" {
    if ! rab_available; then skip "xt_recent module not available"; fi
    uat_apf_set_config "RAB" "1"
    uat_apf_set_config "RAB_PSCAN_LEVEL" "1"

    apf -s
    assert_chain_exists RABPSCAN

    apf -f
    rm -f "$APF_INSTALL/lock.utime"
    apf -s

    assert_chain_exists RABPSCAN
    # RABPSCAN should be attached to INPUT
    assert_rule_exists_ips INPUT "RABPSCAN"
}
