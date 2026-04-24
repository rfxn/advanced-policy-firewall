#!/usr/bin/env bats
#
# 39: Dispatch and help functions for CLI subcommand restructure (Phase 1)
#
# Tests that _dispatch_<group>() and _<group>_help() functions exist in their
# respective sub-libraries and produce expected help output. These functions
# are pure additions that do not require firewall startup for help testing.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/install-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

# --- _trust_help ---

@test "dispatch: _trust_help shows usage and verbs" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; _trust_help"
    assert_success
    assert_output --partial "usage: apf trust"
    assert_output --partial "add HOST"
    assert_output --partial "deny HOST"
    assert_output --partial "remove HOST"
    assert_output --partial "list"
    assert_output --partial "lookup HOST"
    assert_output --partial "refresh"
}

# --- _trust_temp_help ---

@test "dispatch: _trust_temp_help shows usage and verbs" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; _trust_temp_help"
    assert_success
    assert_output --partial "usage: apf trust temp"
    assert_output --partial "add HOST TTL"
    assert_output --partial "deny HOST TTL"
    assert_output --partial "remove HOST"
    assert_output --partial "list"
    assert_output --partial "flush"
}

# --- _dispatch_trust with no args shows help ---

@test "dispatch: _dispatch_trust with no args shows trust help" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; _dispatch_trust"
    assert_success
    assert_output --partial "usage: apf trust"
}

@test "dispatch: _dispatch_trust --help shows trust help" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; _dispatch_trust --help"
    assert_success
    assert_output --partial "usage: apf trust"
}

@test "dispatch: _dispatch_trust invalid verb returns 1" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; _dispatch_trust badverb"
    assert_failure
    assert_output --partial "unknown verb"
}

# --- _cc_help ---

@test "dispatch: _cc_help shows usage and verbs" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; source $APF_DIR/internals/apf_geoip.sh; _cc_help"
    assert_success
    assert_output --partial "usage: apf cc"
    assert_output --partial "info"
    assert_output --partial "lookup"
    assert_output --partial "update"
}

# --- _dispatch_cc with --help ---

@test "dispatch: _dispatch_cc --help shows cc help" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; source $APF_DIR/internals/apf_geoip.sh; _dispatch_cc --help"
    assert_success
    assert_output --partial "usage: apf cc"
}

# --- _ct_help ---

@test "dispatch: _ct_help shows usage and verbs" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; source $APF_DIR/internals/apf_ctlimit.sh; _ct_help"
    assert_success
    assert_output --partial "usage: apf ct"
    assert_output --partial "scan"
    assert_output --partial "status"
}

# --- _dispatch_ct with --help ---

@test "dispatch: _dispatch_ct --help shows ct help" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; source $APF_DIR/internals/apf_ctlimit.sh; _dispatch_ct --help"
    assert_success
    assert_output --partial "usage: apf ct"
}

@test "dispatch: _dispatch_ct with no args shows status" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; source $APF_DIR/internals/apf_ctlimit.sh; _dispatch_ct"
    assert_success
}

# --- _ipset_help ---

@test "dispatch: _ipset_help shows usage and verbs" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; _ipset_help"
    assert_success
    assert_output --partial "usage: apf ipset"
    assert_output --partial "update"
    assert_output --partial "status"
}

# --- _dispatch_ipset with --help ---

@test "dispatch: _dispatch_ipset --help shows ipset help" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; _dispatch_ipset --help"
    assert_success
    assert_output --partial "usage: apf ipset"
}

# --- _gre_help ---

@test "dispatch: _gre_help shows usage and verbs" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; _gre_help"
    assert_success
    assert_output --partial "usage: apf gre"
    assert_output --partial "up"
    assert_output --partial "down"
    assert_output --partial "status"
}

# --- _dispatch_gre with --help ---

@test "dispatch: _dispatch_gre --help shows gre help" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; _dispatch_gre --help"
    assert_success
    assert_output --partial "usage: apf gre"
}

@test "dispatch: _dispatch_gre with no args shows status" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; _dispatch_gre"
    assert_success
}

# --- _cli_trust_remove_with_output exists ---

@test "dispatch: _cli_trust_remove_with_output function exists" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; declare -f _cli_trust_remove_with_output > /dev/null"
    assert_success
}
