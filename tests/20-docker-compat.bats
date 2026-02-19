#!/usr/bin/env bats
#
# 20: Docker/container compatibility mode — surgical flush
#
# Validates that DOCKER_COMPAT=1 preserves external chains (Docker, k8s, etc.)
# while properly flushing only APF-owned chains.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"

# Create fake Docker chains to simulate container runtime iptables footprint
create_docker_chains() {
    # filter table: DOCKER-USER chain with FORWARD jump
    iptables -N DOCKER-USER 2>/dev/null || true
    iptables -A DOCKER-USER -j RETURN
    iptables -A FORWARD -j DOCKER-USER

    # nat table: DOCKER chain with PREROUTING jump + MASQUERADE
    iptables -t nat -N DOCKER 2>/dev/null || true
    iptables -t nat -A PREROUTING -j DOCKER
    iptables -t nat -A POSTROUTING -s 172.17.0.0/16 -j MASQUERADE

    # Set FORWARD policy to DROP (Docker default)
    iptables -P FORWARD DROP
}

# Verify Docker chains still exist
assert_docker_chains_intact() {
    # DOCKER-USER chain exists in filter
    assert_chain_exists DOCKER-USER
    # FORWARD has jump to DOCKER-USER
    assert_rule_exists_ips FORWARD "DOCKER-USER"
    # nat DOCKER chain exists
    assert_chain_exists DOCKER nat
    # nat PREROUTING has jump to DOCKER
    assert_rule_exists_ips PREROUTING "DOCKER" nat
    # nat POSTROUTING has MASQUERADE
    assert_rule_exists_ips POSTROUTING "172.17.0.0/16.*MASQUERADE" nat
    # FORWARD policy is still DROP
    assert_chain_policy FORWARD DROP
}

# Clean up Docker chains
remove_docker_chains() {
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -D FORWARD -j DOCKER-USER 2>/dev/null || true
    iptables -F DOCKER-USER 2>/dev/null || true
    iptables -X DOCKER-USER 2>/dev/null || true
    iptables -t nat -D PREROUTING -j DOCKER 2>/dev/null || true
    iptables -t nat -F DOCKER 2>/dev/null || true
    iptables -t nat -X DOCKER 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s 172.17.0.0/16 -j MASQUERADE 2>/dev/null || true
}

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    remove_docker_chains
    source /opt/tests/helpers/teardown-netns.sh
}

teardown() {
    "$APF" -f 2>/dev/null || true
    remove_docker_chains
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DOCKER_COMPAT" "0"
}

@test "DOCKER_COMPAT=1 start preserves DOCKER-USER chain in filter" {
    create_docker_chains
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DOCKER_COMPAT" "1"

    "$APF" -s

    assert_docker_chains_intact
}

@test "DOCKER_COMPAT=1 start preserves nat table rules" {
    create_docker_chains
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DOCKER_COMPAT" "1"

    "$APF" -s

    # nat DOCKER chain intact
    assert_chain_exists DOCKER nat
    assert_rule_exists_ips POSTROUTING "172.17.0.0/16.*MASQUERADE" nat
}

@test "DOCKER_COMPAT=1 start still creates APF chains" {
    create_docker_chains
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DOCKER_COMPAT" "1"

    "$APF" -s

    assert_chain_exists TALLOW
    assert_chain_exists TDENY
    assert_chain_exists RESET
    assert_chain_exists PROHIBIT
}

@test "DOCKER_COMPAT=1 flush preserves Docker chains" {
    create_docker_chains
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DOCKER_COMPAT" "1"

    "$APF" -s
    "$APF" -f

    assert_docker_chains_intact
}

@test "DOCKER_COMPAT=1 flush removes APF chains" {
    create_docker_chains
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DOCKER_COMPAT" "1"

    "$APF" -s
    assert_chain_exists TALLOW

    "$APF" -f

    # APF chains should be gone
    assert_chain_not_exists TALLOW
    assert_chain_not_exists TDENY
    assert_chain_not_exists RESET
    assert_chain_not_exists PROHIBIT
}

@test "DOCKER_COMPAT=1 flush resets INPUT/OUTPUT policy to ACCEPT" {
    create_docker_chains
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DOCKER_COMPAT" "1"

    "$APF" -s
    "$APF" -f

    assert_chain_policy INPUT ACCEPT
    assert_chain_policy OUTPUT ACCEPT
}

@test "DOCKER_COMPAT=1 restart preserves Docker chains" {
    create_docker_chains
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DOCKER_COMPAT" "1"

    "$APF" -r

    assert_docker_chains_intact
    # APF chains recreated after restart
    assert_chain_exists TALLOW
    assert_chain_exists TDENY
}

@test "DOCKER_COMPAT=0 flush still does nuclear wipe" {
    create_docker_chains
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DOCKER_COMPAT" "0"

    "$APF" -s
    "$APF" -f

    # Docker chains should be destroyed by nuclear flush
    assert_chain_not_exists DOCKER-USER
    # FORWARD policy should be ACCEPT (nuclear resets everything)
    assert_chain_policy FORWARD ACCEPT
}

@test "DOCKER_COMPAT=1 skips fast load snapshot save" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DOCKER_COMPAT" "1"
    apf_set_config "SET_FASTLOAD" "1"
    # Remove any snapshot from prior tests
    rm -f "/opt/apf/internals/.apf.restore"

    "$APF" -s

    # No snapshot should be saved when DOCKER_COMPAT=1
    [ ! -f "/opt/apf/internals/.apf.restore" ]
}

@test "DOCKER_COMPAT=1 start preserves external INPUT rules" {
    # Simulate Docker Swarm adding an INPUT rule before APF starts
    iptables -A INPUT -p tcp --dport 2377 -j ACCEPT
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DOCKER_COMPAT" "1"

    "$APF" -s

    # External INPUT rule should survive APF start
    run iptables -S INPUT
    assert_output --partial -- "--dport 2377"
}

@test "DOCKER_COMPAT=1 flush preserves external INPUT rules" {
    iptables -A INPUT -p tcp --dport 2377 -j ACCEPT
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DOCKER_COMPAT" "1"

    "$APF" -s
    "$APF" -f

    # External rule survives flush
    run iptables -S INPUT
    assert_output --partial -- "--dport 2377"
}

@test "DOCKER_COMPAT=1 restart preserves external INPUT rules" {
    iptables -A INPUT -p tcp --dport 2377 -j ACCEPT
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DOCKER_COMPAT" "1"

    "$APF" -r

    run iptables -S INPUT
    assert_output --partial -- "--dport 2377"
    # APF chains also exist
    assert_chain_exists TALLOW
}

@test "DOCKER_COMPAT=1 flush clears mangle but not nat" {
    create_docker_chains
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DOCKER_COMPAT" "1"

    "$APF" -s
    "$APF" -f

    # nat table should still have rules (MASQUERADE)
    local nat_rules
    nat_rules=$(iptables -t nat -S | grep -c '^-A' || true)
    [ "$nat_rules" -gt 0 ]

    # mangle PREROUTING should be empty (APF-owned)
    local mangle_rules
    mangle_rules=$(iptables -t mangle -S PREROUTING | grep -c '^-A' || true)
    [ "$mangle_rules" -eq 0 ]
}
