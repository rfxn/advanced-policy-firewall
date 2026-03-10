#!/usr/bin/env bats
#
# 10: Input validation functions — valid_host(), valid_ip_cidr(), is_fqdn()
#
# These are security-gate functions. They require no firewall startup;
# we source functions.apf directly and test return codes.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

setup_file() {
    # Source the validation functions directly — they have no dependencies
    # We only need the functions, extracted inline to avoid sourcing
    # the full functions.apf which requires conf.apf variables.
    eval "$(sed -n '/^valid_ip_cidr()/,/^}/p' /opt/apf/internals/functions.apf)"
    eval "$(sed -n '/^valid_host()/,/^}/p' /opt/apf/internals/functions.apf)"
    eval "$(sed -n '/^is_fqdn()/,/^}/p' /opt/apf/internals/functions.apf)"
    export -f valid_ip_cidr valid_host is_fqdn
}

# --- valid_ip_cidr ---

@test "valid_ip_cidr accepts 1.2.3.4" {
    run valid_ip_cidr "1.2.3.4"
    assert_success
}

@test "valid_ip_cidr accepts 10.0.0.0/8" {
    run valid_ip_cidr "10.0.0.0/8"
    assert_success
}

@test "valid_ip_cidr accepts 192.168.1.0/24" {
    run valid_ip_cidr "192.168.1.0/24"
    assert_success
}

@test "valid_ip_cidr accepts 0.0.0.0/0" {
    run valid_ip_cidr "0.0.0.0/0"
    assert_success
}

@test "valid_ip_cidr accepts 255.255.255.255/32" {
    run valid_ip_cidr "255.255.255.255/32"
    assert_success
}

@test "valid_ip_cidr rejects 999.1.2.3 (octet > 255)" {
    run valid_ip_cidr "999.1.2.3"
    assert_failure
}

@test "valid_ip_cidr rejects 0.0.0.256 (octet > 255)" {
    run valid_ip_cidr "0.0.0.256"
    assert_failure
}

@test "valid_ip_cidr rejects 1.2.3.4/33 (mask > 32)" {
    run valid_ip_cidr "1.2.3.4/33"
    assert_failure
}

@test "valid_ip_cidr rejects abc (not an IP)" {
    run valid_ip_cidr "abc"
    assert_failure
}

@test "valid_ip_cidr rejects empty string" {
    run valid_ip_cidr ""
    assert_failure
}

@test "valid_ip_cidr rejects 1.2.3 (incomplete)" {
    run valid_ip_cidr "1.2.3"
    assert_failure
}

# --- valid_host ---

@test "valid_host accepts IPv4 1.2.3.4" {
    run valid_host "1.2.3.4"
    assert_success
}

@test "valid_host accepts IPv6 2001:db8::1" {
    run valid_host "2001:db8::1"
    assert_success
}

@test "valid_host accepts IPv6 ::1 (loopback)" {
    run valid_host "::1"
    assert_success
}

@test "valid_host accepts IPv6 ::/0 (any address)" {
    run valid_host "::/0"
    assert_success
}

@test "valid_host accepts IPv6 with CIDR 2001:db8::/32" {
    run valid_host "2001:db8::/32"
    assert_success
}

@test "valid_host accepts CIDR 10.0.0.0/8" {
    run valid_host "10.0.0.0/8"
    assert_success
}

@test "valid_host accepts FQDN example.com" {
    run valid_host "example.com"
    assert_success
}

@test "valid_host accepts FQDN sub.example.com" {
    run valid_host "sub.example.com"
    assert_success
}

@test "valid_host rejects single-label name localhost" {
    run valid_host "localhost"
    assert_failure
}

@test "valid_host rejects empty string" {
    run valid_host ""
    assert_failure
}

@test "valid_host rejects double dot .." {
    run valid_host ".."
    assert_failure
}

@test "valid_host rejects bare number 1234" {
    run valid_host "1234"
    assert_failure
}

@test "valid_host rejects shell injection ; rm -rf /" {
    run valid_host "; rm -rf /"
    assert_failure
}

@test "valid_host rejects command substitution" {
    run valid_host '$(whoami)'
    assert_failure
}

@test "valid_host rejects invalid IPv6 ff (single hex group)" {
    run valid_host "ff"
    assert_failure
}

@test "valid_host rejects invalid IPv6 gggg::1 (non-hex)" {
    run valid_host "gggg::1"
    assert_failure
}

@test "valid_host rejects 999.1.2.3 (IPv4 octet > 255)" {
    run valid_host "999.1.2.3"
    assert_failure
}

@test "valid_host rejects 1.2.3.4/33 (IPv4 CIDR mask > 32)" {
    run valid_host "1.2.3.4/33"
    assert_failure
}

@test "valid_host rejects 2001:db8::/999 (IPv6 CIDR mask > 128)" {
    run valid_host "2001:db8::/999"
    assert_failure
}

# --- is_fqdn ---

@test "is_fqdn accepts example.com" {
    run is_fqdn "example.com"
    assert_success
}

@test "is_fqdn accepts sub.example.com" {
    run is_fqdn "sub.example.com"
    assert_success
}

@test "is_fqdn accepts numeric-prefix FQDN 1.2.3.4.xip.io (5 labels, not IPv4)" {
    run is_fqdn "1.2.3.4.xip.io"
    assert_success
}

@test "is_fqdn rejects IPv4 47.221.144.145" {
    run is_fqdn "47.221.144.145"
    assert_failure
}

@test "is_fqdn rejects IPv4 1.2.3.4" {
    run is_fqdn "1.2.3.4"
    assert_failure
}

@test "is_fqdn rejects IPv4 CIDR 10.0.0.0/8" {
    run is_fqdn "10.0.0.0/8"
    assert_failure
}

@test "is_fqdn rejects IPv6 2001:db8::1" {
    run is_fqdn "2001:db8::1"
    assert_failure
}

@test "is_fqdn rejects single-label localhost (no dot)" {
    run is_fqdn "localhost"
    assert_failure
}

@test "is_fqdn rejects empty string" {
    run is_fqdn ""
    assert_failure
}
