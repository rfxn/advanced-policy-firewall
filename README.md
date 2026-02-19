# Advanced Policy Firewall (APF) v2.0.1

> (C) 2002-2026, R-fx Networks \<proj@rfxn.com\>
> (C) 2026, Ryan MacDonald \<ryan@rfxn.com\>

*For a plain text version of this document, see [README](README).*

APF is licensed under the GNU General Public License v2. See [COPYING.GPL](COPYING.GPL) for details.

---

## Contents

- [1. Introduction](#1-introduction)
  - [1.1 Supported Systems & Requirements](#11-supported-systems--requirements)
- [2. Installation](#2-installation)
  - [2.1 Boot Loading](#21-boot-loading)
- [3. Configuration](#3-configuration)
  - [3.1 Basic Options](#31-basic-options)
  - [3.2 Advanced Options](#32-advanced-options)
  - [3.3 Reactive Address Blocking](#33-reactive-address-blocking)
  - [3.4 Virtual Network Files](#34-virtual-network-files)
  - [3.5 Global Variables & Custom Rules](#35-global-variables--custom-rules)
  - [3.6 Docker/Container Compatibility](#36-dockercontainer-compatibility)
  - [3.7 ipset Block Lists](#37-ipset-block-lists)
  - [3.8 GRE Tunnels](#38-gre-tunnels)
  - [3.9 Remote Block Lists](#39-remote-block-lists)
  - [3.10 Logging & Control](#310-logging--control)
  - [3.11 Implicit Blocking](#311-implicit-blocking)
- [4. General Usage](#4-general-usage)
  - [4.1 Trust System](#41-trust-system)
  - [4.2 Global Trust System](#42-global-trust-system)
  - [4.3 Advanced Trust Syntax](#43-advanced-trust-syntax)
- [5. License](#5-license)
- [6. Support Information](#6-support-information)

---

## 1. Introduction

Advanced Policy Firewall (APF) is an iptables(netfilter) based firewall system designed around the essential needs of today's Internet deployed servers and the unique needs of custom deployed Linux installations. The configuration of APF is designed to be very informative and present the user with an easy to follow process, from top to bottom of the configuration file. The management of APF on a day-to-day basis is conducted from the command line with the `apf` command, which includes detailed usage information and all the features one would expect from a current and forward thinking firewall solution.

The technical side of APF is such that it embraces the latest stable features put forward by the iptables(netfilter) project to provide a very robust and powerful firewall. The filtering performed by APF is three fold:

1. **Static rule based policies** (not to be confused with a "static firewall")
2. **Connection based stateful policies**
3. **Sanity based policies**

**Static rule based policies** is the most traditional method of firewalling. This is when the firewall has an unchanging set of instructions (rules) on how traffic should be handled in certain conditions. An example of a static rule based policy would be when you allow/deny an address access to the server with the trust system or open a new port with conf.apf. So the short of it is rules that infrequently or never change while the firewall is running.

**Connection based stateful policies** is a means to distinguish legitimate packets for different types of connections. Only packets matching a known connection will be allowed by the firewall; others will be rejected. An example of this would be FTP data transfers, in an older era of firewalling you would have to define a complex set of static policies to allow FTP data transfers to flow without a problem. That is not so with stateful policies, the firewall can see that an address has established a connection to port 21 then "relate" that address to the data transfer portion of the connection and dynamically alter the firewall to allow the traffic.

**Sanity based policies** is the ability of the firewall to match various traffic patterns to known attack methods or scrutinize traffic to conform to Internet standards. An example of this would be when a would-be attacker attempts to forge the source IP address of data they are sending to you, APF can simply discard this traffic or optionally log it then discard it. To the same extent another example would be when a broken router on the Internet begins to relay malformed packets to you, APF can simply discard them or in other situations reply to the router and have it stop sending you new packets (TCP Reset).

These three key filtering methods employed by APF are simply a generalization of how the firewall is constructed on a technical design level, there are a great many more features in APF that can be put to use. For a detailed description of all APF features you should review the configuration file `conf.apf` (under your install path) which has well outlined captions above all options. Below is a point form summary of most APF features for reference and review:

- Detailed and well commented configuration file
- Granular inbound and outbound network filtering
- User id based outbound network filtering
- Application based network filtering
- Trust based rule files with an optional advanced syntax
- Global trust system where rules can be downloaded from a central management server
- **Reactive address blocking (RAB)**, in-line intrusion prevention with automatic address blocking on sanity violations and port scan detection
- Debug mode provided for testing new features and configuration setups
- **Fast load** feature that allows for 1000+ rules to load in under 1 second
- Inbound and outbound network interfaces can be independently configured
- Global TCP/UDP port & ICMP type filtering with multiple methods of executing filters (drop, reject, prohibit)
- Configurable policies for each IP on the system with convenience variables to import settings
- Packet flow rate limiting that prevents abuse on the most widely abused protocol, ICMP
- Prerouting and postrouting rules for optimal network performance
- DShield.org block list support to ban networks exhibiting suspicious activity
- Spamhaus Don't Route Or Peer List support to ban known "hijacked zombie" IP blocks
- Any number of additional interfaces may be configured as firewalled (untrusted) or trusted (not firewalled)
- Additional firewalled interfaces can have their own unique firewall policies applied
- Intelligent route verification to prevent embarrassing configuration errors
- Advanced packet sanity checks to make sure traffic coming and going meets the strictest of standards
- Filter attacks such as fragmented UDP, port zero floods, stuffed routing, ARP poisoning and more
- Configurable type of service options to dictate the priority of different types of network traffic
- Intelligent default settings to meet every day server setups
- Dynamic configuration of your server's local DNS resolvers into the firewall
- Optional filtering of common P2P applications
- Optional filtering of private & reserved IP address space
- Optional implicit blocks of the ident service
- Configurable connection tracking settings to scale the firewall to the size of your network
- Configurable kernel hooks (ties) to harden the system further to syn-flood attacks & routing abuses
- Advanced network control such as explicit congestion notification and overflow control
- Special chains that are aware of the state of FTP DATA and SSH connections to prevent client side issues
- Control over the rate of logged events
- Logging subsystem that allows for logging data to user space programs or standard syslog files
- Logging that details every rule added and a comprehensive set of error checks to prevent config errors
- If you are familiar with netfilter you can create your own rules in any of the policy files
- Pluggable and ready advanced use of QoS algorithms provided by the Linux kernel
- **IPv6 dual-stack support**: automatic ip6tables rules alongside iptables when `USE_IPV6` is enabled, including ICMPv6 filtering and NDP
- Input validation on all trust system entries (IPv4, IPv6, CIDR, FQDN)
- **nft backend detection** with safe fast load across iptables backend changes
- **Docker/container compatibility mode** for coexistence with Docker, Podman, Kubernetes, and containerd without destroying external chains
- **ipset block list support** for kernel-level high-performance IP matching with O(1) lookup; one iptables rule per list instead of one rule per IP
- **GRE tunnel management** with dedicated chains, protocol 47 rules, lifecycle controls (`--gre-up`/`--gre-down`/`--gre-status`), and persist-across-flush support
- **Automatic dependency checking** at startup with OS-aware install hints for missing packages (apt-get, yum, dnf)
- **ICMPv6 type filtering** (`IG_ICMPV6_TYPES`/`EG_ICMPV6_TYPES`) with automatic NDP protection for types 133-136
- **Adaptive connection tracking scaling** that auto-grows conntrack_max when usage exceeds 80%, with configurable ceiling and hash table sizing
- **IPv6 sysctl hardening**: disables accept_source_route, accept_redirects, and accept_ra when `USE_IPV6=1`
- systemd service unit for modern init management
- 3rd party add-on projects that complement APF features

### 1.1 Supported Systems & Requirements

The APF package is designed to run on Linux based operating systems that have an operational version of the iptables (netfilter) package installed. Both the traditional iptables-legacy and the newer iptables-nft backends are supported. You can find out more details on the netfilter project at: https://www.netfilter.org/

Most modern Linux distributions include all required iptables/netfilter modules by default. If you are building a custom kernel, ensure the following modules are available (built-in or modular):

```
iptable_filter
iptable_mangle
nf_conntrack
nf_conntrack_ftp
nf_conntrack_irc
xt_state (or nf_conntrack with CT target)
xt_multiport
xt_limit
xt_recent
xt_LOG (or nf_log_syslog)
xt_REJECT (ipt_REJECT / ip6t_REJECT)
xt_ecn
xt_length
xt_mac
xt_owner
xt_TCPMSS
```

For IPv6 support (`USE_IPV6=1`), also ensure:

```
ip6table_filter
ip6table_mangle
nf_conntrack_ipv6 (on kernels < 4.19; merged into nf_conntrack on 4.19+)
```

APF will attempt to load each module at startup and report any that are missing. You can check available modules with:

```bash
ls /lib/modules/$(uname -r)/kernel/net/netfilter/
```

**Supported platforms:**

- RHEL / Rocky Linux / AlmaLinux 8, 9
- CentOS 7 (legacy support)
- Debian 10, 11, 12
- Ubuntu 20.04, 22.04, 24.04
- Fedora (current releases)

APF will generally run on any Linux distribution that provides iptables (legacy or nft backend) and a bash shell with standard GNU utilities (grep, awk, sed, etc.).

APF includes automatic dependency checking at startup. Critical dependencies (iptables, ip, modprobe, ip6tables when `USE_IPV6=1`) will prevent the firewall from starting if missing. Optional dependencies (wget, iptables-save, iptables-restore, diff, ipset) produce warnings but allow startup to continue. Install hints are OS-aware and suggest the correct package manager command (apt-get, yum, or dnf) for your distribution.

---

## 2. Installation

The installation setup of APF is very straight forward, there is an included `install.sh` script that will perform all the tasks of installing APF for you.

```bash
# Default install
sh install.sh

# Custom install path
INSTALL_PATH=/etc/yourpath sh install.sh
```

If one so desires they may customize the setup of APF by editing the variables inside the `install.sh` script followed by also editing the path variables in the `conf.apf` and `internals.conf` files. This is however not recommended and the default paths should meet all user needs, they are:

- **Install Path:** `/etc/apf`
- **Bin Path:** `/usr/local/sbin/apf`

The package includes two convenience scripts, the first is `importconf` which will import all the variable settings from your previous version of APF into the new installation. The second is `get_ports`, a script which will output the system's currently in use 'server' ports for the user during the installation process in an effort to aid in configuring port settings.

All previous versions of APF are saved upon the installation of newer versions and stored in `/etc/apf.bkDDMMYY-UTIME` format (e.g., `/etc/apf.bk190226-1708456789`). In addition, there is a `/etc/apf.bk.last` sym-link created to the last version of APF you had installed.

After installation is completed the documentation and convenience scripts are copied to `/etc/apf/doc` and `/etc/apf/extras` respectively.

### 2.1 Boot Loading

On installation APF will install a systemd service unit (`apf.service`) on systems with systemd, or an init script to `/etc/init.d/apf` on older systems, and configure it to load on boot. If you are setting up APF in a more custom situation then you may follow the below instructions.

There are three modes of operation for having APF firewall your system and each has no real benefit except tailoring itself to your needs.

**The first and recommended approach** on modern systems is systemd:

```bash
systemctl enable apf
systemctl start apf
```

On older systems without systemd, use chkconfig (done by default during install on SysV-init systems):

```bash
chkconfig --add apf
chkconfig --level 345 apf on
```

**Secondly**, you can add the following string to the bottom of the `/etc/rc.local` file:

```bash
sh -c "/etc/apf/apf -s" &
```

It is **NOT** recommended that you use multiple startup methods together.

**The third and final approach** is to simply run APF in an on-demand fashion. That is, enable it with the `apf -s` command when desired and disable it with the `apf -f` when desired.

---

## 3. Configuration

On your first installation of APF it ships with minimal preconfigured options, and this is intentional. The most common issue with many firewalls is that they come configured with so many options that a user may never use or disable, that it leaves systems riddled with firewall holes.

Now with that said, APF comes configured with only a single incoming port enabled by default and that is port 22 SSH. Along with a set of common practice filtering options preset in the most compatible fashion for all users. All the real advanced options APF has to offer are by default disabled including outbound (egress) port filtering, reactive address blocking (RAB) and the virtual network subsystem to name a few.

The main APF configuration file is `conf.apf` (under your install path, `/etc/apf` by default) and has detailed usage information above all configuration variables. The file uses integer based values for setting configuration options and they are:

- `0` = disabled
- `1` = enabled

All configuration options use this integer value system unless otherwise indicated in the description of that option.

You should put aside 5 minutes and review the configuration file from top to bottom taking the time to read all the captions for the options that are provided. This may seem like a daunting task but a firewall is only as good as it is configured and that requires you, the administrator, to take a few minutes to understand what it is you are setting up.

### 3.1 Basic Options

This section will cover some of the basic configuration options found inside of the `conf.apf` configuration file. These options, despite how basic, are the most vital in the proper operation of your firewall.

**`DEVEL_MODE`** - This tells APF to run in a development mode which in short means that the firewall will shut itself off every 5 minutes from a cronjob. When you install any version of APF, upgrade or new install, this feature is by default enabled to make sure the user does not lock themselves out of the system with configuration errors. Once you are satisfied that you have the firewall configured and operating as intended then you must disable it.

**`INSTALL_PATH`** - As it implies, this is the installation path for APF and unless you have become a brave surgeon it is unlikely you will ever need to reconfigure this option.

**`IFACE_UNTRUSTED`** - This variable controls the interface that firewall rules are applied against. This interface is commonly the Internet facing interface or any interface that faces the main network of untrusted communication (WAN).

**`IFACE_TRUSTED`** - It is common that you may want to set a specific interface as trusted to be excluded from the firewall, these may be administrative private links, virtualized VPN interfaces or a local area network that contains trusted resources. This feature is similar to what some term a demilitarized zone or DMZ for short; any interfaces set in this option will be exempt from all firewall rules with an implicit trust rule set early in the firewall load.

**`SET_VERBOSE`** - This option tells the apf script to print very detailed event logs to the screen as you are conducting firewall operations from the command line. This will allow for easier trouble shooting of firewall issues or to assist the user in better understanding what the firewall is doing rule-by-rule.

**`USE_IPV6`** - This option enables IPv6 dual-stack support for APF. When enabled, APF will load IPv6 kernel modules and apply ip6tables rules alongside all iptables rules. This includes IPv6 chain creation, port filtering, trust system support, packet sanity checks, and ICMPv6 filtering. NDP (Neighbor Discovery Protocol) types 133-136 are always permitted for IPv6 connectivity. The VNET subsystem does not currently support IPv6.

When `USE_IPV6` is enabled, the following additional configuration variables become active:

- `IG_ICMPV6_TYPES` - inbound ICMPv6 types to accept (default: `1,2,3,4,128,129`)
- `EG_ICMPV6_TYPES` - outbound ICMPv6 types to accept (default: `all`)

NDP types 133-136 are always permitted regardless of these settings, as they are required for IPv6 connectivity.

IPv6 sysctl hardening is also applied when `USE_IPV6=1` and `SYSCTL_ROUTE=1`: accept_source_route, accept_redirects, and accept_ra are disabled on all interfaces and the untrusted interface specifically. IPv6 forwarding is disabled unless the system is configured as a router.

IPv6 addresses in the advanced trust syntax ([section 4.3](#43-advanced-trust-syntax)) use bracket notation to protect colons from the field delimiter, e.g., `d=22:s=[2001:db8::1]`.

**`SET_FASTLOAD`** - This tells APF to use a special feature to take saved snapshots of the running firewall. Instead of regenerating every single firewall rule when we stop/start the firewall, APF will use these snapshots to "fast load" the rules in bulk. There are internal features in APF that will detect when configuration has changed and then expire the snapshot forcing a full reload of the firewall. APF also detects changes between iptables backends (legacy vs nft) and will force a full reload if the backend has changed since the snapshot was taken, preventing restore errors from incompatible formats.

**`SET_VNET`** - To put it briefly, this option controls the virtual network subsystem of APF also known as VNET. This is a subsystem that generates policy files for all aliased addresses on the IFACE_IN/OUT interfaces. In general this option is not needed for the normal operation of APF but is provided should you want to easily configure unique policies for the aliased addresses on an interface. Please see [section 3.4](#34-virtual-network-files) for more advanced details.

**`SET_ADDIFACE`** - This allows you to have additional untrusted interfaces firewalled by APF and this is done through the VNET system. Please see [section 3.4](#34-virtual-network-files) for more advanced details.

**Port filtering variables:**

- **`IG_TCP_CPORTS`** - TCP ports allowed for incoming traffic ("server" or "listening" ports)
- **`IG_UDP_CPORTS`** - UDP ports allowed for incoming traffic
- **`IG_ICMP_TYPES`** - ICMP types allowed for incoming traffic
- **`EGF`** - Top level toggle for outbound (egress) filtering. It is recommended that you enable this for a robust level of protection.
- **`EG_TCP_CPORTS`** - TCP ports allowed for outgoing traffic ("client side" ports)
- **`EG_UDP_CPORTS`** - UDP ports allowed for outgoing traffic
- **`EG_ICMP_TYPES`** - ICMP types allowed for outgoing traffic

**`EG_DROP_CMD`** - A comma-separated list of executable names that are blocked from making outbound network connections (e.g., `"eggdrop,psybnc,bitchx"`). Uses the iptables `--cmd-owner` match to identify the originating process. Requires outbound filtering (`EGF="1"`) to be enabled. This feature depends on kernel support for xt_owner command matching, which APF detects at runtime and skips gracefully if unavailable.

**`LOG_DROP`** - Enables detailed firewall logging of filtered packets. Typically left disabled on production systems as it can get very noisy in the log files.

### 3.2 Advanced Options

The advanced options, although not required, are those which afford the firewall the ability to be a more robust and encompassing solution in protecting a host. These options should be reviewed on a case-by-case basis and enabled only as you determine their merit to meet a particular need on a host or network.

**`SET_MONOKERN`** - This option tells the system that instead of looking for iptables modules, that we should expect them to be compiled directly into the kernel. Unless you have a custom compiled kernel with modular support disabled, you should not enable this option.

**`VF_ROUTE`** - This option will make sure that the IP addresses associated to the IFACE_* variables do actually have route entries. If a route entry can not be found then APF will not load as it is likely a configuration error has been made.

**`VF_LGATE`** - This option will make sure that all traffic coming into this host is going through this defined MAC address. Useful for servers behind a NAT/MASQ gateway.

**`TCP_STOP`, `UDP_STOP`, `ALL_STOP`** - These options tell the firewall in which way to go about filtering traffic. Supported values:

- **DROP** (default) - Silently discard packets with no reply. Saves system resources during DoS attacks but experienced attackers may detect the firewall.
- **RESET** - Reply with TCP RST to terminate connections. More in-line with TCP/IP standards but expends system resources to reply.
- **REJECT** - Reply with an error message. Appears as a closed/unavailable port rather than a firewall.
- **PROHIBIT** - Reply with ICMP error messages only. Good alternative that does not load the system as much during aggressive attacks.

**`PKT_SANITY`** - Controls packet scrutiny as they flow through the firewall. Makes sure that all packets conform to strict TCP/IP standards, making it very difficult for attackers to inject raw/custom packets. See `conf.apf` for detailed sub-options.

**Type of Service (TOS)** - The `TOS_*` settings provide a simple classification system to dictate traffic priority based on port numbers. Default settings improve throughput and reliability for FTP, HTTP, SMTP, POP3 and IMAP.

**Traceroute (`TCR_*`)** - Controls if and how traceroute traffic is handled. `TCR_PASS` controls acceptance and `TCR_PORTS` defines the UDP port range used for detection.

**Kernel Tuning** - APF applies kernel-level network hardening via sysctl when the firewall starts. These settings are controlled by the `SYSCTL_*` variables in `conf.apf`:

| Variable | Purpose |
|----------|---------|
| `SYSCTL_CONNTRACK` | Connection tracking table size (default 131072) |
| `SYSCTL_CONNTRACK_ADAPTIVE` | Auto-scale conntrack_max at 80% usage |
| `SYSCTL_TCP` | TCP performance/security tweaks (timestamps, SACK) |
| `SYSCTL_TCP_NOSACK` | Disable TCP SACK (CVE-2019 mitigations) |
| `SYSCTL_SYN` | Syn-flood mitigation (backlog, retry, timeout) |
| `SYSCTL_ROUTE` | Spoofing/redirect protection (rp_filter, etc.) |
| `SYSCTL_LOGMARTIANS` | Log impossible source addresses |
| `SYSCTL_ECN` | Explicit Congestion Notification |
| `SYSCTL_SYNCOOKIES` | SYN cookie flood protection |
| `SYSCTL_OVERFLOW` | Overflow control |

See `conf.apf` for detailed descriptions of each setting and their sub-options.

### 3.3 Reactive Address Blocking

The Reactive Address Blocking (RAB) system provides in-line intrusion prevention by automatically blocking addresses that trigger sanity violations or port scan detection. RAB is configured through the `RAB_*` variables in `conf.apf`.

**`RAB`** - Top level toggle for the reactive address blocking system.

**`RAB_SANITY`** - Enables RAB for sanity violations (address spoofing, packet flag modification). Offending addresses are temporarily banned for the `RAB_TIMER` duration.

**`RAB_PSCAN_LEVEL`** - Enables RAB for port scan violations. Values: `0` (disabled), `1` (low), `2` (medium), `3` (high security).

**`RAB_HITCOUNT`** - Number of violation hits before an address is blocked. Keep very low to prevent evasive measures. Default is 0 or 1 (instant block).

**`RAB_TIMER`** - Block duration in seconds (default: 300s / 5 minutes). Maximum: 43200 seconds (12 hours).

**`RAB_TRIP`** - Resets the block timer to 0 if a blocked address attempts ANY subsequent communication. This cuts off attacks at the legs before they mount into something tangible.

**`RAB_LOG_HIT`** - Log all violation hits. Recommended for insightful log data on probing attempts. `LOG_DROP=1` overrides this to force logging.

**`RAB_LOG_TRIP`** - Log all subsequent traffic from blocked addresses. Can generate a lot of logs but provides valuable information about attacker intent. `LOG_DROP=1` overrides this to force logging.

### 3.4 Virtual Network Files

When `SET_VNET=1`, APF generates per-IP policy files under the `vnet/` directory for each aliased address on the `IFACE_UNTRUSTED` interface. Each file (e.g., `vnet/192.168.1.100.rules`) can override the global port filtering variables (`IG_TCP_CPORTS`, `EG_TCP_CPORTS`, etc.) for that specific IP address. This allows fine-grained control over which ports are open on each address. Run `apf -s` after editing VNET files to apply changes. Note that the VNET subsystem operates on IPv4 addresses only.

### 3.5 Global Variables & Custom Rules

All variables defined in `conf.apf` are available for use in VNET per-IP rule files, allowing you to import global settings and selectively override them. For custom iptables rules beyond what `conf.apf` provides, you can add rules directly to the `preroute.rules` file which is loaded early in the firewall chain. Any valid iptables syntax can be used in these files, as they are sourced directly into the firewall's bash execution environment.

### 3.6 Docker/Container Compatibility

When running APF alongside Docker, Podman, Kubernetes, or other container runtimes, the default flush behavior (which wipes all iptables rules and chains) will destroy the container runtime's networking rules. The `DOCKER_COMPAT` option solves this by switching APF to a surgical flush mode.

**`DOCKER_COMPAT`** - When set to `"1"`, APF's flush operation only removes APF-owned chains from the filter table, leaving all external chains intact. Specifically:

- FORWARD chain policy and rules are preserved (Docker routing)
- nat table is left untouched (Docker port mapping and MASQUERADE rules)
- raw table is left untouched
- External INPUT and OUTPUT rules (non-APF) are saved before flush and restored afterward, protecting rules from Docker Swarm, kube-proxy, Calico CNI, and similar tools
- DOCKER, DOCKER-USER, DOCKER-ISOLATION, and container-runtime chains in all tables are preserved
- mangle PREROUTING/POSTROUTING are still flushed (APF-managed)

When `DOCKER_COMPAT` is enabled, `SET_FASTLOAD` is automatically disabled because iptables-restore would overwrite the external chains that `DOCKER_COMPAT` is designed to protect. Snapshot saving is also skipped in compat mode.

Enable this option if you see Docker containers losing network connectivity after running `apf -s` or `apf -r`.

### 3.7 ipset Block Lists

The ipset subsystem uses kernel-level hash tables for high-performance IP matching. Instead of creating one iptables rule per blocked IP address (which scales linearly), ipset creates a single iptables rule per block list that references a kernel hash set, providing O(1) lookup performance regardless of list size.

**`USE_IPSET`** - Set to `"1"` to enable ipset block list support. Requires the `ipset` utility to be installed (`apt-get install ipset` / `yum install ipset`). When disabled or ipset is not installed, the `ipset.rules` file is ignored.

**`IPSET_LOG_RATE`** - Default log rate limit (per minute) for ipset blocklist matches. Individual lists can control their own logging via the log field in `ipset.rules`.

The block lists are defined in the `ipset.rules` file. Each line defines a set with the format:

```
name:flow:ipset_type:log:file_or_url
```

Where:
- `name` - unique list name (used for ipset set and iptables chain naming)
- `flow` - `src` or `dst` (match source or destination address)
- `ipset_type` - `ip` or `net` (`hash:ip` or `hash:net`)
- `log` - `0` or `1` (per-list logging, rate governed by `IPSET_LOG_RATE`)
- `file_or_url` - local file path or URL (`https://` for remote download)

Examples:
```
firehol_level2:src:net:1:https://iplists.firehol.org/files/firehol_level2.netset
my_blacklist:src:ip:0:/etc/apf/my_blacklist.txt
```

Run `apf --ipset-update` to hot-reload all ipset block lists without restarting the firewall. A cron job (`cron.d.apf_ipset`) is installed automatically to perform periodic updates.

### 3.8 GRE Tunnels

APF can manage GRE (Generic Routing Encapsulation) point-to-point tunnels with dedicated firewall chains and protocol 47 rules. This is useful for servers that need encrypted or encapsulated links to remote endpoints.

**`USE_GRE`** - Set to `"1"` to enable GRE tunnel management. Requires the `ip` utility (iproute2 package). When disabled, `gre.rules` is ignored.

**`GRE_PERSIST`** - When set to `"1"`, tunnel interfaces are kept alive when the firewall is flushed or stopped. Only firewall rules are removed. When set to `"0"`, tunnel interfaces are also torn down on flush. Default is `"1"`.

**`GRE_KEEPALIVE`** - Keepalive interval (seconds) and retry count before declaring a tunnel dead. Format: `"interval retries"` (e.g., `"10 3"`). Set to `"0 0"` to disable. Requires kernel >= 3.x.

**`GRE_MTU`** - Tunnel MTU. Leave empty for auto-calculation (parent interface MTU minus 24 bytes GRE overhead). Set explicitly for double-encapsulation scenarios (e.g., `"1400"`).

**`GRE_TTL`** - IP TTL for GRE tunnel packets. Default is `"255"`.

Tunnels are defined in the `gre.rules` file, which is a bash script sourced during firewall startup. Each tunnel is created by setting a role variable and calling the `create_gretun` function:

```bash
role="source"  # or "target"
create_gretun LINKID LOCAL_IP REMOTE_IP [IPFILE]
```

Where `LINKID` is a tunnel ID (1-99, interface = `gre${LINKID}`), `LOCAL_IP` is this host's public IP, `REMOTE_IP` is the remote endpoint, and `IPFILE` is an optional file of IPs to route through the tunnel (one per line). Addresses are auto-assigned: source=`192.168.${LINKID}.1`, target=`192.168.${LINKID}.2`.

Per-tunnel overrides can be set before each `create_gretun` call:
- `gre_keepalive="10 3"` - override `GRE_KEEPALIVE`
- `gre_mtu="1400"` - override `GRE_MTU`
- `gre_ttl="128"` - override `GRE_TTL`
- `gre_key="12345"` - GRE key for tunnel identification

See the `gre.rules` file header for complete examples.

When tunnels are created, APF automatically:
- Creates GRE_IN and GRE_OUT chains for tunnel traffic
- Adds protocol 47 (GRE) ACCEPT rules for each tunnel endpoint
- Creates per-tunnel interface ACCEPT rules in INPUT and OUTPUT
- Configures MTU, keepalive, and IP addresses as specified

CLI commands:

```bash
apf --gre-up       # bring up all tunnels defined in gre.rules
apf --gre-down     # tear down all tunnels and remove firewall rules
apf --gre-status   # show current tunnel interface status
```

### 3.9 Remote Block Lists

APF can automatically download and apply IP block lists from external sources. Each list is loaded into a dedicated iptables chain on full firewall start. The following `DLIST_*` variables in `conf.apf` control these lists:

| Variable | Description |
|----------|-------------|
| `DLIST_PHP` | Project Honey Pot harvester/spammer IPs |
| `DLIST_SPAMHAUS` | Spamhaus DROP list (stolen/zombie netblocks) |
| `DLIST_DSHIELD` | DShield top suspicious hosts |
| `DLIST_RESERVED` | ARIN reserved/unassigned networks |
| `DLIST_ECNSHAME` | ECN broken hosts (requires `SYSCTL_ECN="1"`) |

Each has a companion `_URL` variable (e.g., `DLIST_PHP_URL`) for the download source. Set the toggle to `"1"` to enable a list. Lists are validated during parsing and backed up before each download. Failed downloads restore from backup to prevent data loss. Note that `DLIST_RESERVED` interacts with `BLK_RESNET` — when both are enabled, the downloaded reserved.networks list supplements the built-in private.networks blocking.

### 3.10 Logging & Control

APF provides configurable logging of filtered packets through the `LOG_*` variables in `conf.apf`:

| Variable | Purpose |
|----------|---------|
| `LOG_DROP` | Master toggle for firewall packet logging |
| `LOG_LEVEL` | Syslog level for log entries (default: `crit`) |
| `LOG_TARGET` | `LOG` (kernel syslog) or `ULOG` (ulogd userspace) |
| `LOG_IA` | Log interactive access (SSH/Telnet, requires `LOG_DROP="1"`) |
| `LOG_LGATE` | Log foreign gateway traffic |
| `LOG_EXT` | Extended logging (TCP/IP options in output) |
| `LOG_RATE` | Max logged events per minute (default: 30) |
| `LOG_APF` | Path to APF status log (default: `/var/log/apf_log`) |

For iptables concurrency control, `IPT_LOCK_SUPPORT` and `IPT_LOCK_TIMEOUT` configure the `-w` lock flag behavior for iptables >= 1.4.20. This prevents concurrent iptables modifications from corrupting rule state.

### 3.11 Implicit Blocking

The `BLK_*` variables in `conf.apf` control implicit blocking of specific traffic patterns without explicit port rules. These apply globally to all interfaces:

| Variable | Purpose |
|----------|---------|
| `BLK_P2P_PORTS` | Block common P2P protocol ports (e.g., BitTorrent, Kazaa, eDonkey) |
| `BLK_PORTS` | Silently drop common attack ports (NetBIOS, RPC, etc.) without logging |
| `BLK_MCATNET` | Block multicast traffic (`224.0.0.0/4`, `ff00::/8`) |
| `BLK_PRVNET` | Block private IPv4 address space (`10/8`, `172.16/12`, `192.168/16`, etc.) on untrusted interfaces |
| `BLK_RESNET` | Block reserved/unassigned IPv4 space |
| `BLK_TCP_SACK_PANIC` | Block low-MSS TCP SACK exploit packets (CVE-2019-11477) |
| `BLK_IDENT` | REJECT ident (TCP 113) requests instead of silently dropping; some services stall without ident response |

---

## 4. General Usage

The `/usr/local/sbin/apf` command has a number of options that will ease the day-to-day use of your firewall:

```
usage /usr/local/sbin/apf [OPTION]
-s|--start ......................... load all firewall rules
-r|--restart ....................... stop (flush) & reload firewall rules
-f|--stop .......................... stop (flush) all firewall rules
-l|--list .......................... list all firewall rules
-t|--status ........................ output firewall status log
-e|--refresh ....................... refresh & resolve dns names in trust rules
-a HOST CMT|--allow HOST COMMENT ... add host (IP/IPv6/CIDR/FQDN) to
                                     allow_hosts.rules and immediately
                                     load new rule into firewall
-d HOST CMT|--deny HOST COMMENT .... add host (IP/IPv6/CIDR/FQDN) to
                                     deny_hosts.rules and immediately
                                     load new rule into firewall
-u|--remove HOST ................... remove host from [glob]*_hosts.rules
                                     and immediately remove rule from firewall
-o|--ovars ......................... output all configuration options
-v|--version ....................... output version number
--ipset-update ..................... hot-reload ipset block lists from ipset.rules
--gre-up .......................... bring up GRE tunnels from gre.rules
--gre-down ........................ tear down GRE tunnels
--gre-status ...................... show GRE tunnel status
```

Note: `--unban` is accepted as an alias for `-u|--remove`.

The **`-l|--list`** option will list all the firewall rules you currently have loaded. This is more of a feature intended for experienced users but can be insightful for any administrator.

The **`-t|--status`** option will show you page-by-page the APF status log that tracks any operations you perform with APF. If something is not working properly, this is what you want to run.

The **`-e|--refresh`** option will flush the trust system chains and reload them from the rule files. This also causes any DNS names in the rules to re-resolve. Ideal for dynamic DNS names in the trust system.

The **`-a|--allow`** and **`-d|--deny`** options let you quickly allow or deny access. The **`-u|--remove`** option removes an entry. These options are immediate in action and do NOT require the firewall to be restarted. See the sections below for more information on the trust system.

The **`-o|--ovars`** option is a debug feature that outputs all configured variables and their current values. This is useful for troubleshooting configuration issues or when reporting problems. See [section 6](#6-support-information) for support contact information.

### 4.1 Trust System

The trust system in APF is a very traditional setup with two basic trust levels: allow and deny. These two basic trust levels are also extended with two global trust levels that can be imported from a remote server to assist with central trust management in a large scale deployment.

The two basic trust level files are located at:

- `/etc/apf/allow_hosts.rules`
- `/etc/apf/deny_hosts.rules`

These files by nature are static, meaning that once you add an entry to them, they will remain in the files till you remove them yourself. The trust files accept FQDN (fully qualified domain names), IPv4 addresses, and IPv6 addresses with optional bit masking. Examples:

```
yourhost.you.com        (FQDN)
192.168.2.102           (IPv4 Address)
192.168.1.0/24          (IPv4 Address with 24 bit mask)
2001:db8::1             (IPv6 Address)
2001:db8::/32           (IPv6 Address with prefix length)
```

Common bit masks:
- `/24` (192.168.1.0 to 192.168.1.255)
- `/16` (192.168.0.0 to 192.168.255.255)

There are two methods for adding entries to the trust files. The first is by editing the files manually with an editor. The second is by using the `apf` command:

```bash
# Trust an address
apf -a ryanm.dynip.org "my home dynamic-ip"

# Deny an address
apf -d 192.168.3.111 "keeps trying to bruteforce"

# Remove an address
apf -u ryanm.dynip.org
```

Please take note that the `--remove|-u` option does not accept a comment string and will remove entries that match from allow_hosts.rules, deny_hosts.rules and the global extensions of these files.

The trust system has several operational controls in `conf.apf`:

| Variable | Purpose |
|----------|---------|
| `SET_EXPIRE` | Auto-expire deny entries after N seconds (`0` to disable). Use `"static"` or `"noexpire"` in a ban comment to exempt it. |
| `SET_REFRESH` | Refresh interval in minutes for trust rules and DNS re-resolution (default: 10) |
| `SET_REFRESH_MD5` | Skip refresh if trust files are unchanged (`1` to enable) |
| `SET_TRIM` | Max deny entries before oldest are purged (default: 250) |

### 4.2 Global Trust System

The global trust system extends the local trust files with centrally managed allow and deny lists that can be downloaded from a remote server. The files `glob_allow.rules` and `glob_deny.rules` are populated by setting the `GA_URL` and `GD_URL` variables in `conf.apf` to the URLs of your remote trust lists. Set `USE_RGT="1"` in `conf.apf` to enable automatic downloading of global trust files. APF will periodically download these lists and load them into the TGALLOW and TGDENY chains. This is useful for organizations managing multiple servers that need to share a common set of trusted or blocked addresses. The `--remove` (`-u`) option will also remove entries from the global trust files.

### 4.3 Advanced Trust Syntax

The trust rules can be made in advanced format with 4 options (`proto:flow:port:ip`):

1. **protocol** - packet protocol tcp/udp
2. **flow in/out** - packet direction, inbound or outbound
3. **s/d=port** - packet source or destination port
4. **s/d=ip(/xx)** - packet source or destination address, masking supported

Flow assumed as Input if not defined. Protocol assumed as TCP if not defined. When defining rules with protocol, flow is required.

**Syntax:**
```
proto:flow:[s/d]=port:[s/d]=ip(/mask)
s - source, d - destination, flow - packet flow in/out
```

**Examples:**

```bash
# inbound to destination port 22 from 24.202.16.11
tcp:in:d=22:s=24.202.16.11

# outbound to destination port 23 to destination host 24.2.11.9
out:d=23:d=24.2.11.9

# inbound to destination port 3306 from 24.202.11.0/24
d=3306:s=24.202.11.0/24
```

**IPv6 addresses** use bracket notation to protect colons from the field delimiter parser:

```bash
# inbound to destination port 22 from IPv6 address 2001:db8::1
d=22:s=[2001:db8::1]

# inbound to destination port 443 from IPv6 network 2001:db8::/32
tcp:in:d=443:s=[2001:db8::/32]
```

Plain (non-advanced) IPv6 addresses can be added directly without brackets:
```
2001:db8::1
```

---

## 5. License

APF is developed and supported on a volunteer basis by Ryan MacDonald [ryan@r-fx.org].

APF (Advanced Policy Firewall) is distributed under the GNU General Public License (GPL) without restrictions on usage or redistribution. The APF copyright statement, and GNU GPL, "COPYING.GPL" are included in the top-level directory of the distribution. Credit must be given for derivative works as required under GNU GPL.

---

## 6. Support Information

If you require any assistance with APF you may refer to the R-fx Networks community forums located at https://forums.rfxnetworks.com. You may also send an e-mail to proj@rfxn.com or support@r-fx.org.

The official home page for APF is located at:
https://www.rfxn.com/projects/advanced-policy-firewall/

All bugs or feature requests should be sent to proj@rfxn.com and please be sure to include as much information as possible or conceptual ideas of how you think a new feature should work. When reporting issues, include the output of `apf --ovars` with your report to help diagnose configuration problems.
