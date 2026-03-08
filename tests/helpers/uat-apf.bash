#!/bin/bash
# uat-apf.bash — APF-specific UAT helper
# Provides install verification, reset, and configuration for UAT scenarios.
# Load in UAT .bats files with: load '../helpers/uat-apf'

APF_INSTALL="/opt/apf"
APF_SRC="/opt/apf-src"
APF_CMD="/usr/local/sbin/apf"

# uat_apf_install — Verify APF is installed and configured for Docker UAT.
# Idempotent — safe to call multiple times from setup_file().
# APF is pre-installed in the Docker image; this verifies state and
# configures for UAT (no network downloads, no kernel modules, etc.)
uat_apf_install() {
    if [ -x "$APF_CMD" ]; then
        # Already installed — just ensure clean state
        uat_apf_reset
        return 0
    fi

    # Fallback: install from source if missing (should not happen in CI)
    cd "$APF_SRC" && INSTALL_PATH="$APF_INSTALL" bash install.sh > /dev/null 2>&1

    local conf="$APF_INSTALL/conf.apf"

    # Docker environment: skip kernel modules, disable network features
    sed -i 's/^SET_MONOKERN=.*/SET_MONOKERN="1"/' "$conf"
    sed -i 's/^DEVEL_MODE=.*/DEVEL_MODE="0"/' "$conf"
    sed -i 's/^VF_ROUTE=.*/VF_ROUTE="0"/' "$conf"
    sed -i 's/^DLIST_PHP=.*/DLIST_PHP="0"/' "$conf"
    sed -i 's/^DLIST_SPAMHAUS=.*/DLIST_SPAMHAUS="0"/' "$conf"
    sed -i 's/^DLIST_DSHIELD=.*/DLIST_DSHIELD="0"/' "$conf"
    sed -i 's/^DLIST_RESERVED=.*/DLIST_RESERVED="0"/' "$conf"
    sed -i 's/^DLIST_ECNSHAME=.*/DLIST_ECNSHAME="0"/' "$conf"
    sed -i 's/^USE_RGT=.*/USE_RGT="0"/' "$conf"
    sed -i 's/^RAB=.*/RAB="0"/' "$conf"
    sed -i 's/^SET_FASTLOAD=.*/SET_FASTLOAD="0"/' "$conf"
    sed -i 's/^SET_REFRESH=.*/SET_REFRESH="0"/' "$conf"
    sed -i 's/^BLK_RESNET=.*/BLK_RESNET="0"/' "$conf"
    sed -i 's/^USE_IPSET=.*/USE_IPSET="0"/' "$conf"
    sed -i 's/^USE_GRE=.*/USE_GRE="0"/' "$conf"

    # Save clean state for reset
    for rf in "$APF_INSTALL/allow_hosts.rules" "$APF_INSTALL/deny_hosts.rules"; do
        if [ -f "$rf" ]; then
            sed '/^[^#]/d' "$rf" > "$rf.clean"
        fi
    done
    cp "$conf" "${conf}.clean"

    uat_apf_reset
}

# uat_apf_reset — Reset APF state between scenario files.
# Restores clean config and trust files, flushes iptables, clears temp trust.
# Call from setup_file() or teardown_file().
uat_apf_reset() {
    [ -d "$APF_INSTALL" ] || return 0

    # Flush iptables rules — safe even if APF is not running
    iptables -F 2>/dev/null || true   # flush: safe to ignore if no rules
    iptables -X 2>/dev/null || true   # delete chains: may fail if chains have refs
    ip6tables -F 2>/dev/null || true  # flush IPv6: safe to ignore
    ip6tables -X 2>/dev/null || true  # delete IPv6 chains: may fail if chains have refs

    # Restore clean trust files
    if [ -f "$APF_INSTALL/allow_hosts.rules.clean" ]; then
        cp "$APF_INSTALL/allow_hosts.rules.clean" "$APF_INSTALL/allow_hosts.rules"
    fi
    if [ -f "$APF_INSTALL/deny_hosts.rules.clean" ]; then
        cp "$APF_INSTALL/deny_hosts.rules.clean" "$APF_INSTALL/deny_hosts.rules"
    fi

    # Restore clean config
    if [ -f "$APF_INSTALL/conf.apf.clean" ]; then
        cp "$APF_INSTALL/conf.apf.clean" "$APF_INSTALL/conf.apf"
    fi

    # Restore hook scripts
    if [ -f "$APF_INSTALL/hook_pre.sh.clean" ]; then
        cp "$APF_INSTALL/hook_pre.sh.clean" "$APF_INSTALL/hook_pre.sh"
    fi
    if [ -f "$APF_INSTALL/hook_post.sh.clean" ]; then
        cp "$APF_INSTALL/hook_post.sh.clean" "$APF_INSTALL/hook_post.sh"
    fi

    # Clear internal state files
    rm -f "$APF_INSTALL/internals/.apf.restore" \
          "$APF_INSTALL/internals/.apf6.restore" \
          "$APF_INSTALL/internals/.last.full" \
          "$APF_INSTALL/internals/.apf.restore.backend" \
          "$APF_INSTALL/internals/.localaddrs" \
          "$APF_INSTALL/internals/.localaddrs6" \
          "$APF_INSTALL/internals/.ipset.timestamps" \
          "$APF_INSTALL/internals/.block_history" \
          "$APF_INSTALL/internals/.md5.cores" \
          "$APF_INSTALL/internals/.md5.cores.new" \
          "$APF_INSTALL/internals/.last.vars" \
          "$APF_INSTALL/internals/.last.vars.new" \
          "$APF_INSTALL/internals/.trusts.md5"

    # Ensure log file exists
    touch /var/log/apf_log
    chmod 600 /var/log/apf_log
}

# uat_apf_set_config VAR VALUE — Set a config variable in conf.apf
# Convenience wrapper for UAT tests
uat_apf_set_config() {
    local var="$1"
    local val="$2"
    sed -i "s/^${var}=.*/${var}=\"${val}\"/" "$APF_INSTALL/conf.apf"
}

# uat_apf_teardown — Robust teardown for UAT scenarios that start APF.
# Ensures firewall is flushed and orphaned processes are cleaned up even
# if a test failure leaves APF in an unexpected state.
# Call from teardown_file() in any scenario that runs apf -s or apf -r.
uat_apf_teardown() {
    # Flush firewall — safe even if already stopped (exits 0 either way)
    apf -f 2>/dev/null || true  # flush: safe if apf not running or not installed
    # Kill any orphaned apf processes left by failed tests
    uat_cleanup_processes apf
    # Reset state files and config to clean baseline
    uat_apf_reset
}

# uat_apf_set_interface IFACE — Set the untrusted interface for APF
uat_apf_set_interface() {
    uat_apf_set_config "IFACE_UNTRUSTED" "$1"
}
