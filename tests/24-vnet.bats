#!/usr/bin/env bats
#
# 24: VNET subsystem tests
#
# Validates SET_VNET behavior: disabled message, rule file generation
# via vnetgen, per-IP rule loading, and VNET port overrides.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"
# Secondary IP to add to veth-pub for VNET testing
VNET_IP="203.0.113.50"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    # Remove secondary IP
    ip addr del "$VNET_IP/24" dev veth-pub 2>/dev/null || true
    # Clean up any VNET rule files we created
    rm -f "$APF_DIR/vnet/$VNET_IP.rules"
    source /opt/tests/helpers/teardown-netns.sh
}

# =====================================================================
# SET_VNET=0 tests
# =====================================================================

@test "SET_VNET=0 logs 'virtual net subsystem disabled'" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_VNET" "0"
    > /var/log/apf_log
    "$APF" -f 2>/dev/null
    "$APF" -s

    run grep "virtual net subsystem disabled" /var/log/apf_log
    assert_success

    "$APF" -f 2>/dev/null
}

# =====================================================================
# SET_VNET=1 tests
# =====================================================================

@test "SET_VNET=1 with no .rules files does not crash" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_VNET" "1"
    # Remove any existing vnet rule files
    rm -f "$APF_DIR/vnet/"*.rules
    > /var/log/apf_log
    "$APF" -f 2>/dev/null
    "$APF" -s

    run grep "virtual network enabled" /var/log/apf_log
    assert_success

    # Firewall should still be running
    assert_chain_exists TALLOW

    "$APF" -f 2>/dev/null
    apf_set_config "SET_VNET" "0"
}

@test "vnetgen creates .rules file for secondary IP" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_VNET" "1"

    # Add a secondary IP to veth-pub
    ip addr add "$VNET_IP/24" dev veth-pub 2>/dev/null || true

    # Remove any existing rule file for this IP
    rm -f "$APF_DIR/vnet/$VNET_IP.rules"

    # Run vnetgen
    "$APF_DIR/vnet/vnetgen"

    # Should have created a .rules file
    [ -f "$APF_DIR/vnet/$VNET_IP.rules" ]

    # File should have proper permissions (600)
    local perms
    perms=$(stat -c '%a' "$APF_DIR/vnet/$VNET_IP.rules")
    [ "$perms" == "600" ]

    # Cleanup
    apf_set_config "SET_VNET" "0"
}

@test "SET_VNET=1 loads rules for bound IP" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_VNET" "1"

    # Ensure secondary IP is bound
    ip addr add "$VNET_IP/24" dev veth-pub 2>/dev/null || true

    # Run vnetgen first to create the rules file
    "$APF_DIR/vnet/vnetgen"

    > /var/log/apf_log
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Should log loading the vnet rules
    run grep "virtual network enabled" /var/log/apf_log
    assert_success

    # The IP should have per-IP rules (cports.common loaded for this VNET IP)
    # Default config should create INPUT ACCEPT rules for IG_TCP_CPORTS on this IP
    # Use -S format (consistent across nft/legacy backends)
    assert_rule_exists_ips INPUT "$VNET_IP.*-p tcp.*--dport 22.*ACCEPT"

    "$APF" -f 2>/dev/null
    apf_set_config "SET_VNET" "0"
}

@test "SET_VNET=1 skips unbound IP with log message" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_VNET" "1"

    # Create a rules file for an IP that is NOT bound
    local fake_ip="203.0.113.99"
    touch "$APF_DIR/vnet/$fake_ip.rules"
    chmod 600 "$APF_DIR/vnet/$fake_ip.rules"

    > /var/log/apf_log
    "$APF" -f 2>/dev/null
    "$APF" -s

    run grep "$fake_ip not bound" /var/log/apf_log
    assert_success

    # Cleanup
    rm -f "$APF_DIR/vnet/$fake_ip.rules"
    "$APF" -f 2>/dev/null
    apf_set_config "SET_VNET" "0"
}

@test "VNET per-IP port override applies different ports" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_VNET" "1"

    # Ensure secondary IP is bound
    ip addr add "$VNET_IP/24" dev veth-pub 2>/dev/null || true

    # Create a custom VNET rules file with different ports
    cat > "$APF_DIR/vnet/$VNET_IP.rules" <<VNETRULE
eout "{glob} loading $VNET_IP.rules"
VNET="$VNET_IP"
IG_TCP_CPORTS="8080,9090"
IG_UDP_CPORTS=""
. $APF_DIR/internals/cports.common
VNETRULE

    "$APF" -f 2>/dev/null
    "$APF" -s

    # Should have rules for port 8080 on the VNET IP (use -S format)
    assert_rule_exists_ips INPUT "$VNET_IP.*-p tcp.*--dport 8080.*ACCEPT"
    assert_rule_exists_ips INPUT "$VNET_IP.*-p tcp.*--dport 9090.*ACCEPT"

    "$APF" -f 2>/dev/null
    apf_set_config "SET_VNET" "0"
}
