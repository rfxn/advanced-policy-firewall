#!/usr/bin/env bats
# 10-devel-mode.bats -- APF DEVEL_MODE UAT
# Verifies: devel mode warning in output, cron entry for auto-flush,
# transition from devel to production mode, status display.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-apf'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_apf_install
    source /opt/tests/helpers/setup-netns.sh
    uat_apf_set_interface "veth-pub"
}

teardown_file() {
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

# bats test_tags=uat,uat:devel-mode
@test "UAT: DEVEL_MODE=1 start shows development mode warning" {
    uat_apf_set_config "DEVEL_MODE" "1"
    uat_capture "devel-mode" apf -s
    assert_success
    assert_output --partial "DEVELOPMENT MODE ENABLED"
}

# bats test_tags=uat,uat:devel-mode
@test "UAT: DEVEL_MODE=1 creates cron auto-flush entry" {
    # devm() creates /etc/cron.d/apf_develmode with a */5 flush schedule
    run cat /etc/cron.d/apf_develmode
    assert_success
    assert_output --partial "*/5"
    assert_output --partial "apf -f"
}

# bats test_tags=uat,uat:devel-mode
@test "UAT: info shows DEVEL_MODE ON when enabled" {
    uat_capture "devel-mode" apf --info
    assert_success
    assert_output --partial "DEVEL_MODE:"
    assert_output --partial "ON"
}

# bats test_tags=uat,uat:devel-mode
@test "UAT: transition to production mode removes cron and shows off" {
    apf -f 2>/dev/null || true  # flush: safe if not running
    uat_apf_set_config "DEVEL_MODE" "0"
    uat_capture "devel-mode" apf -s
    assert_success
    # Cron file should be removed
    run test -f /etc/cron.d/apf_develmode
    assert_failure
    # Info should show devel mode off
    run apf --info
    assert_output --partial "DEVEL_MODE:"
    assert_output --partial "off"
}
