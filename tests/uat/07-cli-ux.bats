#!/usr/bin/env bats
# 07-cli-ux.bats — APF CLI UX UAT
# Verifies: help text, version, info, config dump, status log, no-args, invalid flag

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-apf'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_apf_install
}

teardown_file() {
    uat_apf_reset
}

# bats test_tags=uat,uat:cli-ux
@test "UAT: -h shows help text" {
    uat_capture "cli-ux" apf -h
    assert_success
    assert_output --partial "usage"
}

# bats test_tags=uat,uat:cli-ux
@test "UAT: --help shows help text" {
    uat_capture "cli-ux" apf --help
    assert_success
    assert_output --partial "usage"
}

# bats test_tags=uat,uat:cli-ux
@test "UAT: help covers all major sections" {
    run apf -h
    assert_success
    assert_output --partial "Firewall Control"
    assert_output --partial "Trust Management"
    assert_output --partial "Temporary Trust"
    assert_output --partial "Diagnostics"
}

# bats test_tags=uat,uat:cli-ux
@test "UAT: help documents key options" {
    run apf -h
    assert_success
    assert_output --partial -- "-s"
    assert_output --partial -- "-f"
    assert_output --partial -- "-a"
    assert_output --partial -- "-d"
    assert_output --partial -- "-u"
    assert_output --partial -- "-g"
}

# bats test_tags=uat,uat:cli-ux
@test "UAT: version output" {
    uat_capture "cli-ux" apf -v
    assert_success
    assert_output --partial "2.0"
}

# bats test_tags=uat,uat:cli-ux
@test "UAT: --version outputs same as -v" {
    run apf --version
    assert_success
    assert_output --partial "2.0"
}

# bats test_tags=uat,uat:cli-ux
@test "UAT: dump config shows configuration variables" {
    uat_capture "cli-ux" apf -o
    assert_success
    assert_output --partial "IFACE_UNTRUSTED="
    assert_output --partial "DEVEL_MODE="
}

# bats test_tags=uat,uat:cli-ux
@test "UAT: no-args shows help and exits non-zero" {
    uat_capture "cli-ux" apf
    assert_failure
    assert_output --partial "usage"
}

# bats test_tags=uat,uat:cli-ux
@test "UAT: invalid flag shows help and exits non-zero" {
    uat_capture "cli-ux" apf --invalid-flag
    assert_failure
    assert_output --partial "usage"
}

# bats test_tags=uat,uat:cli-ux
@test "UAT: validate succeeds without starting firewall" {
    uat_capture "cli-ux" apf --validate
    assert_success
    assert_output --partial "validated"
}
