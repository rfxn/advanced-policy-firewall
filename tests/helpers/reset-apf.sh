#!/bin/bash
#
# Resets APF to clean state for testing. APF is pre-installed during
# Docker build; this script restores config and trust files to their
# pristine post-install state. Much faster than re-running install.sh.

APF_INSTALL="${APF_INSTALL:-/opt/apf}"

reset_apf() {
    cp "$APF_INSTALL/conf.apf.clean" "$APF_INSTALL/conf.apf"
    cp "$APF_INSTALL/allow_hosts.rules.clean" "$APF_INSTALL/allow_hosts.rules"
    cp "$APF_INSTALL/deny_hosts.rules.clean" "$APF_INSTALL/deny_hosts.rules"
    rm -f "$APF_INSTALL/internals/.apf.restore" \
          "$APF_INSTALL/internals/.apf6.restore" \
          "$APF_INSTALL/internals/.last.full" \
          "$APF_INSTALL/internals/.apf.restore.backend" \
          "$APF_INSTALL/internals/.localaddrs" \
          "$APF_INSTALL/internals/.localaddrs6" \
          "$APF_INSTALL/internals/.ipset.timestamps"
    # Reset hook scripts and silent IPs to pristine state
    cp "$APF_INSTALL/hook_pre.sh.clean" "$APF_INSTALL/hook_pre.sh" 2>/dev/null || true
    chmod 640 "$APF_INSTALL/hook_pre.sh" 2>/dev/null || true
    cp "$APF_INSTALL/hook_post.sh.clean" "$APF_INSTALL/hook_post.sh" 2>/dev/null || true
    chmod 640 "$APF_INSTALL/hook_post.sh" 2>/dev/null || true
    cp "$APF_INSTALL/silent_ips.rules.clean" "$APF_INSTALL/silent_ips.rules" 2>/dev/null || true
    touch /var/log/apf_log
    chmod 600 /var/log/apf_log
}

reset_apf
