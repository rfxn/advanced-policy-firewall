#!/bin/bash
#
# Custom BATS assertions for iptables rule verification.
# Uses -L -nv for rule matching (shows interface names, protocol names).

# Assert a chain exists in iptables (IPv4)
# Usage: assert_chain_exists CHAIN [TABLE]
assert_chain_exists() {
    local chain="$1"
    local table="${2:-filter}"
    run iptables -t "$table" -L "$chain" -n 2>/dev/null
    if [ "$status" -ne 0 ]; then
        echo "Expected chain '$chain' to exist in table '$table' (iptables)" >&2
        return 1
    fi
}

# Assert a chain exists in ip6tables (IPv6)
# Usage: assert_chain_exists_ip6 CHAIN [TABLE]
assert_chain_exists_ip6() {
    local chain="$1"
    local table="${2:-filter}"
    run ip6tables -t "$table" -L "$chain" -n 2>/dev/null
    if [ "$status" -ne 0 ]; then
        echo "Expected chain '$chain' to exist in table '$table' (ip6tables)" >&2
        return 1
    fi
}

# Assert a chain does NOT exist in iptables
# Usage: assert_chain_not_exists CHAIN [TABLE]
assert_chain_not_exists() {
    local chain="$1"
    local table="${2:-filter}"
    run iptables -t "$table" -L "$chain" -n 2>/dev/null
    if [ "$status" -eq 0 ]; then
        echo "Expected chain '$chain' NOT to exist in table '$table'" >&2
        return 1
    fi
}

# Assert a rule matching PATTERN exists in a chain
# Uses -L -nv which shows interface names (in/out columns) and protocol names
# Usage: assert_rule_exists CHAIN PATTERN [TABLE]
assert_rule_exists() {
    local chain="$1"
    local pattern="$2"
    local table="${3:-filter}"
    local rules
    rules=$(iptables -t "$table" -L "$chain" -nv 2>/dev/null)
    if ! echo "$rules" | grep -qE "$pattern"; then
        echo "Expected rule matching '$pattern' in chain '$chain' table '$table'" >&2
        echo "Actual rules:" >&2
        echo "$rules" >&2
        return 1
    fi
}

# Assert a rule matching PATTERN exists in ip6tables chain
# Uses -L -nv for consistent output with interface names
# Usage: assert_rule_exists_ip6 CHAIN PATTERN [TABLE]
assert_rule_exists_ip6() {
    local chain="$1"
    local pattern="$2"
    local table="${3:-filter}"
    local rules
    rules=$(ip6tables -t "$table" -L "$chain" -nv 2>/dev/null)
    if ! echo "$rules" | grep -qE "$pattern"; then
        echo "Expected rule matching '$pattern' in chain '$chain' table '$table' (ip6tables)" >&2
        echo "Actual rules:" >&2
        echo "$rules" >&2
        return 1
    fi
}

# Assert a chain's default policy
# Usage: assert_chain_policy CHAIN POLICY
assert_chain_policy() {
    local chain="$1"
    local policy="$2"
    local actual
    actual=$(iptables -L "$chain" -n 2>/dev/null | head -1 | grep -oP '\(policy \K[A-Z]+')
    if [ "$actual" != "$policy" ]; then
        echo "Expected chain '$chain' policy '$policy', got '$actual'" >&2
        return 1
    fi
}

# Assert a chain's default policy in ip6tables
# Usage: assert_chain_policy_ip6 CHAIN POLICY
assert_chain_policy_ip6() {
    local chain="$1"
    local policy="$2"
    local actual
    actual=$(ip6tables -L "$chain" -n 2>/dev/null | head -1 | grep -oP '\(policy \K[A-Z]+')
    if [ "$actual" != "$policy" ]; then
        echo "Expected ip6tables chain '$chain' policy '$policy', got '$actual'" >&2
        return 1
    fi
}

# Assert a rule matching PATTERN does NOT exist in a chain
# Usage: assert_rule_not_exists CHAIN PATTERN [TABLE]
assert_rule_not_exists() {
    local chain="$1"
    local pattern="$2"
    local table="${3:-filter}"
    local rules
    rules=$(iptables -t "$table" -L "$chain" -nv 2>/dev/null)
    if echo "$rules" | grep -qE "$pattern"; then
        echo "Expected NO rule matching '$pattern' in chain '$chain' table '$table'" >&2
        echo "Matching rules:" >&2
        echo "$rules" | grep -E "$pattern" >&2
        return 1
    fi
}
