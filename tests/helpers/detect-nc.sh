#!/bin/bash
#
# Cross-distro netcat portability helper.
# Debian/Ubuntu use netcat-openbsd; Rocky/RHEL use nmap-ncat.
# Source this file in tests that need nc for traffic verification.

# Detect which netcat variant is available
if command -v ncat >/dev/null 2>&1; then
    NC_BIN="ncat"
else
    NC_BIN="nc"
fi

# Start a listening server on a port (runs in current namespace).
# Usage: nc_listen PORT
# The listener PID is available via $!
nc_listen() {
    local port="$1"
    $NC_BIN -l "$port" </dev/null &
}

# Build the nc connect command for use with ip netns exec.
# Usage: nc_connect_cmd TIMEOUT HOST PORT
# Returns the command string for use with: ip netns exec NS $(nc_connect_cmd ...)
nc_connect_cmd() {
    local timeout="$1"
    local host="$2"
    local port="$3"
    echo "$NC_BIN -z -w $timeout $host $port"
}
