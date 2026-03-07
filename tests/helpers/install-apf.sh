#!/bin/bash
#
# Installs APF from source with Docker-appropriate patches.
# Must be sourced or called after setup-netns.sh.

APF_SRC="/opt/apf-src"
APF_INSTALL="/opt/apf"

install_apf() {
    cd "$APF_SRC"
    INSTALL_PATH="$APF_INSTALL" bash install.sh

    # Prevent cross-test contamination: importconf copies old *_hosts.rules
    # from backup, which may contain entries from previous test runs.
    # Strip all non-comment, non-blank lines from trust files.
    for rf in "$APF_INSTALL/allow_hosts.rules" "$APF_INSTALL/deny_hosts.rules"; do
        if [ -f "$rf" ]; then
            sed -i '/^[^#]/d' "$rf"
        fi
    done

    # Patch conf.apf for Docker environment
    local conf="$APF_INSTALL/conf.apf"

    # Skip modprobe — Docker shares host kernel
    sed -i 's/^SET_MONOKERN=.*/SET_MONOKERN="1"/' "$conf"

    # No auto-flush cron
    sed -i 's/^DEVEL_MODE=.*/DEVEL_MODE="0"/' "$conf"

    # Skip route validation on synthetic interfaces
    sed -i 's/^VF_ROUTE=.*/VF_ROUTE="0"/' "$conf"

    # No internet downloads — deterministic tests
    sed -i 's/^DLIST_PHP=.*/DLIST_PHP="0"/' "$conf"
    sed -i 's/^DLIST_SPAMHAUS=.*/DLIST_SPAMHAUS="0"/' "$conf"
    sed -i 's/^DLIST_DSHIELD=.*/DLIST_DSHIELD="0"/' "$conf"
    sed -i 's/^DLIST_RESERVED=.*/DLIST_RESERVED="0"/' "$conf"
    sed -i 's/^DLIST_ECNSHAME=.*/DLIST_ECNSHAME="0"/' "$conf"
    sed -i 's/^USE_RGT=.*/USE_RGT="0"/' "$conf"

    # Disable RAB (requires xt_recent kernel module)
    sed -i 's/^RAB=.*/RAB="0"/' "$conf"

    # Disable fast load for predictable test behavior
    sed -i 's/^SET_FASTLOAD=.*/SET_FASTLOAD="0"/' "$conf"

    # Disable refresh cron
    sed -i 's/^SET_REFRESH=.*/SET_REFRESH="0"/' "$conf"

    # Disable reserved network blocking (we use RFC 5737 test addresses)
    sed -i 's/^BLK_RESNET=.*/BLK_RESNET="0"/' "$conf"

    # Disable ipset block lists (tests enable individually)
    sed -i 's/^USE_IPSET=.*/USE_IPSET="0"/' "$conf"

    # Disable GRE tunnels (tests enable individually)
    sed -i 's/^USE_GRE=.*/USE_GRE="0"/' "$conf"

    # Disable Docker compat (tests enable individually)
    sed -i 's/^DOCKER_COMPAT=.*/DOCKER_COMPAT="0"/' "$conf"

    # Ensure log file exists
    touch /var/log/apf_log
    chmod 600 /var/log/apf_log

    # Save clean state for reset-apf.sh (used by subsequent test files)
    for rf in "$APF_INSTALL/allow_hosts.rules" "$APF_INSTALL/deny_hosts.rules"; do
        sed '/^[^#]/d' "$rf" > "$rf.clean"
    done
    cp "$APF_INSTALL/conf.apf" "$APF_INSTALL/conf.apf.clean"
    cp "$APF_INSTALL/hook_pre.sh" "$APF_INSTALL/hook_pre.sh.clean"
    cp "$APF_INSTALL/hook_post.sh" "$APF_INSTALL/hook_post.sh.clean"
    cp "$APF_INSTALL/silent_ips.rules" "$APF_INSTALL/silent_ips.rules.clean"
}

install_apf
