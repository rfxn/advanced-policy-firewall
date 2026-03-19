#!/usr/bin/env bats
#
# 34: elog_lib integration — audit trail, eout compat, source guard
#
# Validates elog_lib.sh integration in APF: audit log creation, JSONL
# event writing, eout() backward compatibility, and source guard behavior.
# Does not require a running firewall — sources the library directly.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

APF_DIR="/opt/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/install-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
}

teardown_file() {
    "$APF_DIR/apf" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

setup() {
    # Clean audit log before each test
    export ELOG_LOG_DIR="/tmp/elog-test-$$"
    export ELOG_AUDIT_FILE="${ELOG_LOG_DIR}/audit.log"
    rm -rf "$ELOG_LOG_DIR"
}

teardown() {
    rm -rf "$ELOG_LOG_DIR"
    unset ELOG_LOG_DIR ELOG_AUDIT_FILE
}

@test "elog_lib.sh can be sourced without errors" {
    run bash -c ". '$APF_DIR/internals/elog_lib.sh'"
    assert_success
}

@test "elog_lib.sh source guard prevents double loading" {
    run bash -c "
        _ELOG_LIB_LOADED=1
        . '$APF_DIR/internals/elog_lib.sh'
        # If source guard worked, ELOG_LIB_VERSION stays unset
        [ -z \"\${ELOG_LIB_VERSION:-}\" ]
    "
    assert_success
}

@test "elog_init creates audit log directory and file" {
    run bash -c "
        export ELOG_APP='apf'
        export ELOG_LOG_DIR='$ELOG_LOG_DIR'
        export ELOG_AUDIT_FILE='$ELOG_AUDIT_FILE'
        export ELOG_LOG_FILE='${ELOG_LOG_DIR}/apf.log'
        . '$APF_DIR/internals/elog_lib.sh'
        elog_init
        [ -d '$ELOG_LOG_DIR' ] && [ -f '$ELOG_AUDIT_FILE' ]
    "
    assert_success
}

@test "elog_event writes valid JSONL to audit log" {
    run bash -c "
        export ELOG_APP='apf'
        export ELOG_LOG_DIR='$ELOG_LOG_DIR'
        export ELOG_AUDIT_FILE='$ELOG_AUDIT_FILE'
        export ELOG_LOG_FILE='${ELOG_LOG_DIR}/apf.log'
        . '$APF_DIR/internals/elog_lib.sh'
        elog_init
        elog_event 'test_event' 'info' '{glob} test message' 'key1=val1'
        # Verify JSONL contains expected fields
        grep -q '\"type\":\"test_event\"' '$ELOG_AUDIT_FILE' && \
        grep -q '\"key1\":\"val1\"' '$ELOG_AUDIT_FILE'
    "
    assert_success
}

@test "eout writes to log file (backward compat, no force-stdout)" {
    run bash -c "
        export ELOG_APP='apf'
        export ELOG_LOG_DIR='$ELOG_LOG_DIR'
        export ELOG_LOG_FILE='${ELOG_LOG_DIR}/apf.log'
        export ELOG_AUDIT_FILE='$ELOG_AUDIT_FILE'
        export ELOG_STDOUT='never'
        . '$APF_DIR/internals/elog_lib.sh'
        elog_init
        # Source eout from apf.lib.sh via sed extraction
        eval \"\$(sed -n '/^eout()/,/^}/p' '$APF_DIR/internals/apf.lib.sh')\"
        eout '{glob} test log line'
        grep -q 'test log line' '${ELOG_LOG_DIR}/apf.log'
    "
    assert_success
}

@test "eout force-stdout with arg2=1 (backward compat)" {
    run bash -c "
        export ELOG_APP='apf'
        export ELOG_LOG_DIR='$ELOG_LOG_DIR'
        export ELOG_LOG_FILE='${ELOG_LOG_DIR}/apf.log'
        export ELOG_AUDIT_FILE='$ELOG_AUDIT_FILE'
        export ELOG_STDOUT='flag'
        . '$APF_DIR/internals/elog_lib.sh'
        elog_init
        elog_output_enable 'stdout' 2>/dev/null || true
        eval \"\$(sed -n '/^eout()/,/^}/p' '$APF_DIR/internals/apf.lib.sh')\"
        output=\$(eout '{glob} forced stdout' 1)
        echo \"\$output\" | grep -q 'forced stdout'
    "
    assert_success
}

@test "ELOG_LOG_DIR and ELOG_AUDIT_FILE set by internals.conf" {
    # Verify the variables are defined in internals.conf (not only in apf)
    run grep 'ELOG_LOG_DIR=' "$APF_DIR/internals/internals.conf"
    assert_success
    assert_output --partial '/var/log/apf'

    run grep 'ELOG_AUDIT_FILE=' "$APF_DIR/internals/internals.conf"
    assert_success
    assert_output --partial 'audit.log'
}

@test "firewall subprocess inherits elog audit path via internals.conf" {
    # Simulate the firewall subprocess sourcing chain: conf.apf -> internals.conf
    # Verify ELOG_AUDIT_FILE is set without files/apf
    run bash -c "
        source '$APF_DIR/conf.apf'
        [ -n \"\$ELOG_AUDIT_FILE\" ] && echo \"\$ELOG_AUDIT_FILE\"
    "
    assert_success
    assert_output --partial "audit.log"
}
