#!/bin/bash
#
# Helper functions for configuring APF in tests.

APF_INSTALL="${APF_INSTALL:-/opt/apf}"

# Set a config variable in conf.apf
# Usage: apf_set_config VAR VALUE
apf_set_config() {
    local var="$1"
    local val="$2"
    sed -i "s/^${var}=.*/${var}=\"${val}\"/" "$APF_INSTALL/conf.apf"
}

# Set the untrusted/trusted interfaces
# Usage: apf_set_interface IFACE_UNTRUSTED [IFACE_TRUSTED]
apf_set_interface() {
    apf_set_config "IFACE_UNTRUSTED" "$1"
    if [ -n "$2" ]; then
        apf_set_config "IFACE_TRUSTED" "$2"
    fi
}

# Set inbound/outbound ports
# Usage: apf_set_ports IG_TCP IG_UDP [EG_TCP] [EG_UDP]
apf_set_ports() {
    apf_set_config "IG_TCP_CPORTS" "$1"
    apf_set_config "IG_UDP_CPORTS" "$2"
    if [ -n "$3" ]; then
        apf_set_config "EG_TCP_CPORTS" "$3"
    fi
    if [ -n "$4" ]; then
        apf_set_config "EG_UDP_CPORTS" "$4"
    fi
}
