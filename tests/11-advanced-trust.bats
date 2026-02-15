#!/usr/bin/env bats
#
# 11: Advanced trust syntax — proto:flow:port:ip format in allow/deny_hosts
#
# Tests the multi-format trust entries that allow_hosts() and deny_hosts()
# parse from rules files. These are completely untested in the base suite.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/install-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    apf_set_config "EGF" "1"
    apf_set_config "EG_TCP_CPORTS" "80,443"
    apf_set_config "EG_UDP_CPORTS" "53"
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

# Clean trust files before each test
setup() {
    # Remove test entries from trust files
    for pattern in "192.0.2" "198.51.100" "2001:db8"; do
        sed -i "/${pattern}/d" "$APF_DIR/allow_hosts.rules" 2>/dev/null || true
        sed -i "/${pattern}/d" "$APF_DIR/deny_hosts.rules" 2>/dev/null || true
    done
}

@test "simple trust: d=PORT:s=IP creates port ACCEPT rules" {
    echo "d=8080:s=192.0.2.50" >> "$APF_DIR/allow_hosts.rules"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    # Should create multiport rules for both TCP and UDP
    # multiport module normalizes --dport to --dports in iptables -S output
    assert_rule_exists_ips TALLOW "192.0.2.50.*--dports 8080"
}

@test "direction trust: in:d=PORT:s=IP creates INPUT rule" {
    echo "in:d=80:s=192.0.2.50" >> "$APF_DIR/allow_hosts.rules"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    # Direction-based rules use INPUT/OUTPUT chains via TALLOW
    assert_rule_exists_ips TALLOW "192.0.2.50.*--dports 80"
}

@test "protocol trust: tcp:in:d=PORT:s=IP creates TCP-only rule" {
    echo "tcp:in:d=443:s=192.0.2.50" >> "$APF_DIR/allow_hosts.rules"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    # iptables -S output order: -s IP -p proto -m multiport --dports PORT
    assert_rule_exists_ips TALLOW "192.0.2.50.*-p tcp.*--dports 443"
}

@test "port range trust: d=PORT_PORT:s=IP uses colon range" {
    echo "d=8000_8100:s=192.0.2.50" >> "$APF_DIR/allow_hosts.rules"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    # Underscore notation is converted to colon range
    assert_rule_exists_ips TALLOW "192.0.2.50.*--dports 8000:8100"
}

@test "UDP trust: udp:in:d=PORT:s=IP creates UDP rule" {
    echo "udp:in:d=53:s=192.0.2.50" >> "$APF_DIR/allow_hosts.rules"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    assert_rule_exists_ips TALLOW "192.0.2.50.*-p udp.*--dports 53"
}

@test "outbound trust: out:s=PORT:d=IP creates OUTPUT-targeted rule" {
    echo "out:s=3306:d=192.0.2.50" >> "$APF_DIR/allow_hosts.rules"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    assert_rule_exists_ips TALLOW "192.0.2.50.*--sports 3306"
}

@test "deny advanced syntax: d=PORT:s=IP in deny_hosts creates DROP" {
    echo "d=22:s=192.0.2.51" >> "$APF_DIR/deny_hosts.rules"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    assert_rule_exists_ips TDENY "192.0.2.51.*--dports 22"
}

@test "plain IP in allow_hosts creates src+dst ACCEPT" {
    echo "192.0.2.50" >> "$APF_DIR/allow_hosts.rules"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    assert_rule_exists_ips TALLOW "-s 192.0.2.50.*ACCEPT"
    assert_rule_exists_ips TALLOW "-d 192.0.2.50.*ACCEPT"
}

@test "CIDR in allow_hosts creates src+dst ACCEPT" {
    echo "198.51.100.0/24" >> "$APF_DIR/allow_hosts.rules"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    assert_rule_exists_ips TALLOW "-s 198.51.100.0/24.*ACCEPT"
    assert_rule_exists_ips TALLOW "-d 198.51.100.0/24.*ACCEPT"
}

@test "IPv6 in allow_hosts.rules: deferred (Phase 16)" {
    # allow_hosts() uses `grep -v ":"` to separate plain IPs from advanced
    # trust syntax, which excludes all IPv6 addresses. IPv6 trust via
    # allow_hosts.rules/deny_hosts.rules is deferred to Phase 16.
    # CLI trust (apf -a IPv6) works because it calls cli_trust() directly.
    skip "IPv6 in trust files not yet supported (Phase 16)"
}
