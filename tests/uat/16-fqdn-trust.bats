#!/usr/bin/env bats
# 16-fqdn-trust.bats — APF FQDN Trust Workflow UAT
# Validates: add hostname to trust, DNS resolution, metadata in file,
# live iptables rule, remove FQDN, refresh re-resolution.
# Uses /etc/hosts entries for deterministic resolution in Docker.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-apf'
load '../helpers/assert-iptables'
load '../infra/lib/uat-helpers'

FQDN_TEST_HOST="uat-test.example.com"
FQDN_TEST_IP="192.0.2.200"

setup_file() {
    uat_setup
    uat_apf_install
    source /opt/tests/helpers/setup-netns.sh
    uat_apf_set_interface "veth-pub"

    # Create a deterministic DNS entry via /etc/hosts
    # This avoids network dependency in CI
    if ! grep -q "$FQDN_TEST_HOST" /etc/hosts; then
        echo "$FQDN_TEST_IP $FQDN_TEST_HOST" >> /etc/hosts
    fi

    apf -s
}

teardown_file() {
    # Clean up /etc/hosts entry
    sed -i "/$FQDN_TEST_HOST/d" /etc/hosts
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

# =========================================================================
# UAT-FQ01: Add FQDN to allow list
# Scenario: Sysadmin trusts a hostname — APF resolves and adds the IP
# =========================================================================

# bats test_tags=uat,uat:fqdn-trust
@test "UAT: allow FQDN resolves hostname and adds to trust file" {
    uat_capture "fqdn-trust" apf -a "$FQDN_TEST_HOST" "UAT FQDN allow"
    assert_success

    # Trust file must contain the resolved IP
    run grep "$FQDN_TEST_IP" /opt/apf/allow_hosts.rules
    assert_success

    # Trust file should contain resolution metadata
    run grep "resolved=" /opt/apf/allow_hosts.rules
    assert_success
    assert_output --partial "$FQDN_TEST_HOST"
}

# bats test_tags=uat,uat:fqdn-trust
@test "UAT: FQDN-resolved IP is live in iptables TALLOW chain" {
    assert_rule_exists_ips TALLOW "$FQDN_TEST_IP"
}

# bats test_tags=uat,uat:fqdn-trust
@test "UAT: lookup FQDN shows allow status with resolved addresses" {
    uat_capture "fqdn-trust" apf --lookup "$FQDN_TEST_HOST"
    assert_success
    assert_output --partial "ALLOW"
}

# =========================================================================
# UAT-FQ02: FQDN survives restart (loaded from file metadata)
# =========================================================================

# bats test_tags=uat,uat:fqdn-trust
@test "UAT: FQDN trust entry survives restart" {
    uat_capture "fqdn-trust" apf -r
    assert_success

    # Resolved IP must be back in iptables after restart
    assert_rule_exists_ips TALLOW "$FQDN_TEST_IP"
}

# =========================================================================
# UAT-FQ03: Refresh re-resolves FQDN entries
# =========================================================================

# bats test_tags=uat,uat:fqdn-trust
@test "UAT: refresh re-resolves FQDN and preserves trust entry" {
    # Verify entry exists before refresh
    assert_rule_exists_ips TALLOW "$FQDN_TEST_IP"

    uat_capture "fqdn-trust" apf -e
    assert_success

    # Entry must survive refresh cycle
    assert_rule_exists_ips TALLOW "$FQDN_TEST_IP"
}

# =========================================================================
# UAT-FQ04: Remove FQDN cleans up both file and iptables
# =========================================================================

# bats test_tags=uat,uat:fqdn-trust
@test "UAT: remove FQDN cleans trust file and iptables" {
    uat_capture "fqdn-trust" apf -u "$FQDN_TEST_HOST"
    assert_success

    # File must not contain the FQDN or resolved IP
    run grep "$FQDN_TEST_HOST" /opt/apf/allow_hosts.rules
    assert_failure
    run grep "$FQDN_TEST_IP" /opt/apf/allow_hosts.rules
    assert_failure

    # iptables must not contain the resolved IP
    run iptables -S TALLOW 2>/dev/null
    refute_output --partial "$FQDN_TEST_IP"
}

# =========================================================================
# UAT-FQ05: FQDN deny works the same way
# =========================================================================

# bats test_tags=uat,uat:fqdn-trust
@test "UAT: deny FQDN resolves and adds to deny trust file" {
    uat_capture "fqdn-trust" apf -d "$FQDN_TEST_HOST" "FQDN deny test"
    assert_success

    run grep "$FQDN_TEST_IP" /opt/apf/deny_hosts.rules
    assert_success
    assert_rule_exists_ips TDENY "$FQDN_TEST_IP"

    # Cleanup
    apf -u "$FQDN_TEST_HOST" 2>/dev/null || true  # cleanup
}

# =========================================================================
# UAT-FQ06: Invalid hostname rejected cleanly
# =========================================================================

# bats test_tags=uat,uat:fqdn-trust
@test "UAT: invalid hostname that fails resolution shows clean error" {
    uat_capture "fqdn-trust" apf -a "nonexistent.invalid.tld" "should fail"
    assert_failure
}
