#!/usr/bin/env bats
#
# 11: Advanced trust syntax — proto:flow:port:ip format in allow/deny_hosts
#
# Tests the multi-format trust entries that allow_hosts() and deny_hosts()
# parse from rules files.
#
# Performance: all trust entries are pre-populated in setup_file() and the
# firewall is started once. Each @test runs assertions only (~5s total
# instead of ~60s with per-test flush+start cycles).

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    apf_set_config "USE_IPV6" "1"
    apf_set_config "EGF" "1"
    apf_set_config "EG_TCP_CPORTS" "80,443"
    apf_set_config "EG_UDP_CPORTS" "53"

    # Pre-populate all trust entries — distinct IPs to avoid collisions
    cat >> "$APF_DIR/allow_hosts.rules" <<'ALLOW'
d=8080:s=192.0.2.50
in:d=80:s=192.0.2.53
tcp:in:d=443:s=192.0.2.54
d=8000_8100:s=192.0.2.56
udp:in:d=53:s=192.0.2.57
out:s=3306:d=192.0.2.58
192.0.2.52
198.51.100.0/24
2001:db8::50
d=8080:s=[2001:db8::55]
in:d=443:s=[2001:db8::60]
tcp:in:d=22:s=[2001:db8::70]
d=80:s=[2001:db8::/32]
d=8080:s=192.0.2.55
d=8080:s=[2001:db8::80]
ALLOW

    cat >> "$APF_DIR/deny_hosts.rules" <<'DENY'
d=22:s=192.0.2.51
2001:db8::51
d=22:s=[2001:db8::52]
DENY

    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

@test "simple trust: d=PORT:s=IP creates port ACCEPT rules" {
    # multiport module normalizes --dport to --dports in iptables -S output
    assert_rule_exists_ips TALLOW "192.0.2.50.*--dports 8080"
}

@test "direction trust: in:d=PORT:s=IP creates INPUT rule" {
    assert_rule_exists_ips TALLOW "192.0.2.53.*--dports 80"
}

@test "protocol trust: tcp:in:d=PORT:s=IP creates TCP-only rule" {
    # iptables -S output order: -s IP -p proto -m multiport --dports PORT
    assert_rule_exists_ips TALLOW "192.0.2.54.*-p tcp.*--dports 443"
}

@test "port range trust: d=PORT_PORT:s=IP uses colon range" {
    # Underscore notation is converted to colon range
    assert_rule_exists_ips TALLOW "192.0.2.56.*--dports 8000:8100"
}

@test "UDP trust: udp:in:d=PORT:s=IP creates UDP rule" {
    assert_rule_exists_ips TALLOW "192.0.2.57.*-p udp.*--dports 53"
}

@test "outbound trust: out:s=PORT:d=IP creates OUTPUT-targeted rule" {
    assert_rule_exists_ips TALLOW "192.0.2.58.*--sports 3306"
}

@test "deny advanced syntax: d=PORT:s=IP in deny_hosts creates DROP" {
    assert_rule_exists_ips TDENY "192.0.2.51.*--dports 22"
}

@test "plain IP in allow_hosts creates src+dst ACCEPT" {
    assert_rule_exists_ips TALLOW "-s 192.0.2.52.*ACCEPT"
    assert_rule_exists_ips TALLOW "-d 192.0.2.52.*ACCEPT"
}

@test "CIDR in allow_hosts creates src+dst ACCEPT" {
    assert_rule_exists_ips TALLOW "-s 198.51.100.0/24.*ACCEPT"
    assert_rule_exists_ips TALLOW "-d 198.51.100.0/24.*ACCEPT"
}

@test "IPv6 plain address in allow_hosts creates ip6tables rules" {
    assert_rule_exists_ip6s TALLOW "-s 2001:db8::50.*ACCEPT"
    assert_rule_exists_ip6s TALLOW "-d 2001:db8::50.*ACCEPT"
}

@test "IPv6 plain address in deny_hosts creates ip6tables rules" {
    assert_rule_exists_ip6s TDENY "2001:db8::51"
}

@test "IPv6 bracket syntax: d=PORT:s=[IPv6] creates ip6tables rules" {
    assert_rule_exists_ip6s TALLOW "2001:db8::55.*--dports 8080"
}

@test "IPv6 bracket direction: in:d=PORT:s=[IPv6] creates ip6tables rules" {
    assert_rule_exists_ip6s TALLOW "2001:db8::60.*--dports 443"
}

@test "IPv6 bracket full syntax: tcp:in:d=PORT:s=[IPv6] creates ip6tables TCP rule" {
    assert_rule_exists_ip6s TALLOW "2001:db8::70.*-p tcp.*--dports 22"
}

@test "IPv6 bracket deny: d=PORT:s=[IPv6] in deny_hosts creates ip6tables rules" {
    assert_rule_exists_ip6s TDENY "2001:db8::52.*--dports 22"
}

@test "IPv6 bracket with CIDR: d=PORT:s=[IPv6/mask] creates ip6tables rules" {
    assert_rule_exists_ip6s TALLOW "2001:db8::/32.*--dports 80"
}

@test "IPv4 advanced trust still works alongside IPv6 entries" {
    assert_rule_exists_ips TALLOW "192.0.2.55.*--dports 8080"
    assert_rule_exists_ip6s TALLOW "2001:db8::80.*--dports 8080"
}
