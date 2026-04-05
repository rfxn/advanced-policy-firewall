#!/usr/bin/env bats
# 17-cron-refresh.bats — APF Cron Job & Refresh Management UAT
# Validates: cron job creation on start, removal on flush, refresh behavior,
# DEVEL_MODE cron lifecycle, SET_REFRESH=0 skips cron.

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
    # Ensure no stale cron jobs
    rm -f /etc/cron.d/refresh.apf
    rm -f /etc/cron.d/apf_develmode
}

teardown_file() {
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

# =========================================================================
# UAT-CR01: Start with SET_REFRESH > 0 creates refresh cron
# Scenario: Sysadmin expects auto-refresh of trust chains
# =========================================================================

# bats test_tags=uat,uat:cron-refresh
@test "UAT: start with SET_REFRESH=10 creates refresh cron job" {
    uat_apf_set_config "SET_REFRESH" "10"

    uat_capture "cron-refresh" apf -s
    assert_success

    # Cron symlink/file must exist
    [ -e /etc/cron.d/refresh.apf ]
}

# bats test_tags=uat,uat:cron-refresh
@test "UAT: refresh cron job contains correct interval" {
    # The cron file should reference the refresh interval
    run cat /etc/cron.d/refresh.apf
    assert_success
    # Cron content should include */10 for 10-minute interval
    assert_output --partial "10"
}

# =========================================================================
# UAT-CR02: Flush removes cron jobs
# Scenario: Sysadmin flushes firewall — automated tasks must stop
# =========================================================================

# bats test_tags=uat,uat:cron-refresh
@test "UAT: flush removes refresh cron job" {
    # Precondition: cron exists
    [ -e /etc/cron.d/refresh.apf ]

    uat_capture "cron-refresh" apf -f
    assert_success

    # Cron must be gone after flush
    [ ! -e /etc/cron.d/refresh.apf ]
}

# =========================================================================
# UAT-CR03: SET_REFRESH=0 creates no cron
# Scenario: Sysadmin disables auto-refresh
# =========================================================================

# bats test_tags=uat,uat:cron-refresh
@test "UAT: start with SET_REFRESH=0 creates no refresh cron" {
    uat_apf_set_config "SET_REFRESH" "0"

    uat_capture "cron-refresh" apf -s
    assert_success

    # No cron job should exist
    [ ! -e /etc/cron.d/refresh.apf ]
}

# bats test_tags=uat,uat:cron-refresh
@test "UAT: --info shows SET_REFRESH disabled" {
    uat_capture "cron-refresh" apf --info
    assert_success
    # Info should indicate refresh is disabled
    assert_output --partial "disabled"
}

# =========================================================================
# UAT-CR04: DEVEL_MODE creates its own cron job
# Scenario: Sysadmin enables devel mode — auto-flush cron is critical safety net
# =========================================================================

# bats test_tags=uat,uat:cron-devel
@test "UAT: DEVEL_MODE=1 creates devel mode cron for auto-flush" {
    apf -f 2>/dev/null
    uat_apf_set_config "DEVEL_MODE" "1"
    uat_apf_set_config "SET_REFRESH" "0"

    uat_capture "cron-devel" apf -s
    assert_success

    # Devel mode cron should exist
    [ -e /etc/cron.d/apf_develmode ]
}

# bats test_tags=uat,uat:cron-refresh
@test "UAT: restart recreates cron jobs" {
    apf -f 2>/dev/null
    uat_apf_set_config "DEVEL_MODE" "0"
    uat_apf_set_config "SET_REFRESH" "10"

    uat_capture "cron-refresh" apf -s
    assert_success
    [ -e /etc/cron.d/refresh.apf ]

    # Flush (removes cron)
    apf -f 2>/dev/null
    [ ! -e /etc/cron.d/refresh.apf ]

    # Restart (recreates cron)
    uat_capture "cron-refresh" apf -r
    assert_success
    [ -e /etc/cron.d/refresh.apf ]
}

# =========================================================================
# UAT-CR05: Transition from DEVEL_MODE=1 to 0 cleans devel cron
# =========================================================================

# bats test_tags=uat,uat:cron-devel
@test "UAT: switching DEVEL_MODE=0 and restarting removes devel cron" {
    apf -f 2>/dev/null
    uat_apf_set_config "DEVEL_MODE" "1"
    apf -s 2>/dev/null

    # Devel cron exists
    [ -e /etc/cron.d/apf_develmode ]

    # Switch to production
    uat_apf_set_config "DEVEL_MODE" "0"
    uat_capture "cron-devel" apf -r
    assert_success

    # Devel cron must be gone
    [ ! -e /etc/cron.d/apf_develmode ]
}

# =========================================================================
# UAT-CR06: Manual refresh works without cron
# Scenario: Sysadmin runs apf -e manually even when SET_REFRESH=0
# =========================================================================

# bats test_tags=uat,uat:cron-refresh
@test "UAT: manual refresh (apf -e) works regardless of SET_REFRESH setting" {
    # Add a trust entry
    apf -a 192.0.2.180 "refresh test" 2>/dev/null
    assert_rule_exists_ips TALLOW "192.0.2.180"

    # Manual refresh
    uat_capture "cron-refresh" apf -e
    assert_success

    # Entry must survive
    assert_rule_exists_ips TALLOW "192.0.2.180"

    apf -u 192.0.2.180 2>/dev/null || true  # cleanup
}
