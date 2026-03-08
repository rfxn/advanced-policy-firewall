#!/usr/bin/env bats
# 12-error-paths.bats -- APF Error Path UAT
# Verifies: clean error messages and appropriate exit codes for
# invalid IP, bad config, locked state, empty host argument.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-apf'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_apf_install
    source /opt/tests/helpers/setup-netns.sh
    uat_apf_set_interface "veth-pub"
    apf -s
}

teardown_file() {
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

# bats test_tags=uat,uat:error-paths
@test "UAT: invalid IP address to apf -a shows clean error" {
    uat_capture "error-paths" apf -a "999.999.999.999" "bad IP"
    assert_failure
    assert_output --partial "Invalid host"
}

# bats test_tags=uat,uat:error-paths
@test "UAT: empty host argument to apf -a shows error" {
    uat_capture "error-paths" apf -a "" "no host"
    assert_failure
    assert_output --partial "required"
}

# bats test_tags=uat,uat:error-paths
@test "UAT: invalid IP to apf -d shows clean error" {
    uat_capture "error-paths" apf -d "not-an-ip" "bad input"
    assert_failure
    assert_output --partial "Invalid host"
}

# bats test_tags=uat,uat:error-paths
@test "UAT: bad config value causes validate to report error" {
    # Set an invalid stop target
    uat_apf_set_config "TCP_STOP" "INVALID_TARGET"
    uat_capture "error-paths" apf --validate
    assert_failure
    assert_output --partial "TCP_STOP"
    # Restore valid config
    uat_apf_set_config "TCP_STOP" "DROP"
}

# bats test_tags=uat,uat:error-paths
@test "UAT: validate catches empty IFACE_UNTRUSTED" {
    uat_apf_set_config "IFACE_UNTRUSTED" ""
    uat_capture "error-paths" apf --validate
    assert_failure
    assert_output --partial "IFACE_UNTRUSTED"
    # Restore valid config
    uat_apf_set_config "IFACE_UNTRUSTED" "veth-pub"
}

# bats test_tags=uat,uat:error-paths
@test "UAT: unknown CLI flag exits non-zero with usage" {
    uat_capture "error-paths" apf --nonexistent-flag
    assert_failure
    assert_output --partial "usage"
}
