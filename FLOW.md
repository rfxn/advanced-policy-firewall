# Firewall Order of Operations

This document describes the exact order in which APF loads firewall rules
when you run `apf -s`. Understanding this order is essential for
troubleshooting and for knowing which features take precedence over others.

> **Tip:** To see which rules are active and in what order, run `apf -l`
> (equivalent to `iptables -L -nv`). For the raw rule list in insertion
> order, use `iptables -S` and `ip6tables -S`.

---

## 1. High-Level Flow

```
apf -s
 ├── Fast Load Path (SET_FASTLOAD=1, conditions met)
 │     Verify snapshot backend matches current iptables backend
 │     iptables-restore from snapshot → exit
 │
 └── Full Load Path:
       1.  Kernel Modules          (modinit)
       2.  Flush All Rules         (flush 1)
       3.  Interface & Route       Verify IFACE_UNTRUSTED / IFACE_TRUSTED routes
           Verification
       4.  Local Address Cache     Detect IPs on IFACE_UNTRUSTED (.localaddrs)
       5.  Preroute Rules          ToS PREROUTING + preroute.rules
       6.  Loopback ACCEPT         INPUT/OUTPUT on lo
       7.  Trusted Interfaces      ACCEPT all on IFACE_TRUSTED
       8.  GRE Tunnels             gre_init() — GRE_IN/GRE_OUT chains, proto 47
       9.  Helper Chains           RESET (tcp-reset + DROP), PROHIBIT (icmp-host-prohibited)
      10.  Sysctl Kernel Tuning    sysctl.rules
      11.  MSS Clamping            OUTPUT SYN,RST → TCPMSS --clamp-mss-to-pmtu
      12.  Nonroutable Blocks      BLK_MCATNET, BLK_PRVNET, BLK_RESNET network files
      13.  Trust System Chains     Create TALLOW, TDENY, TGALLOW, TGDENY, REFRESH_TEMP
      14.  Blocked Traffic         bt.rules (see detail below)
      15.  Allow Lists             glob_allow → TGALLOW, allow_hosts → TALLOW
      16.  RAB                     Trip rules, RABPSCAN chain
      17.  Log Rules               log.rules (SSH_LOG, TELNET_LOG)
      18.  VNET Per-IP Policies    main.vnet → per-IP rule files
      19.  Port Filtering          cports.common (see detail below)
      20.  State Tracking          ESTABLISHED,RELATED rules
      21.  DNS Rules               Per-nameserver INPUT/OUTPUT
      22.  Service Helpers         FTP, SSH, Traceroute
      23.  Drop Logging            Rate-limited INPUT/OUTPUT log chains
      24.  ECN Shame List          SYSCTL_ECN hosts
      25.  Postroute Rules         ToS POSTROUTING + postroute.rules
      26.  Default OUTPUT Policy   ACCEPT (EGF=0) or DROP (EGF=1)
      27.  Default INPUT Policy    DROP (tcp, udp, all)
      28.  Save Snapshot           iptables-save for next fast load
```

---

## 2. Detailed Step-by-Step

### Step 1: Kernel Modules — `modinit()`

Loads required iptables/netfilter kernel modules via `modprobe`. IPv6 modules
are loaded when `USE_IPV6=1`. Skipped when `SET_MONOKERN=1`.

- **Source:** `functions.apf` (`modinit`)
- **Config:** `SET_MONOKERN`
- **Scope:** System-wide (kernel)

### Step 2: Flush All Rules — `flush 1`

Resets all iptables chains (filter, mangle, raw tables). Sets default
policies to ACCEPT temporarily, deletes all user chains, zeros counters.
When `DOCKER_COMPAT=1`, uses surgical flush preserving external chains.

- **Source:** `functions.apf` (`flush`)
- **Config:** `DOCKER_COMPAT`
- **Chains:** All tables, all chains
- **Scope:** Dual-stack (IPv4 + IPv6)

### Step 3: Interface & Route Verification

When `VF_ROUTE=1`, verifies that `IFACE_UNTRUSTED` and `IFACE_TRUSTED`
interfaces have valid route entries. Aborts if verification fails.

- **Source:** `firewall:25-62`
- **Config:** `VF_ROUTE`, `IFACE_UNTRUSTED`, `IFACE_TRUSTED`

### Step 4: Local Address Cache

Detects all IPv4 addresses on `IFACE_UNTRUSTED` and writes them to
`.localaddrs`. When `USE_IPV6=1`, also writes `.localaddrs6`. Used by the
trust system to determine if a host is local.

- **Source:** `firewall:64-67`

### Step 5: Preroute Rules

Loads ToS (Type of Service) PREROUTING classifications and custom
`preroute.rules`.

- **Source:** `firewall:76-77`
- **Config:** `TOS_*` variables
- **Chains:** mangle PREROUTING

### Step 6: Loopback ACCEPT

Permits all traffic on the loopback interface (`lo`).

- **Source:** `firewall:80-81`
- **Chains:** INPUT, OUTPUT
- **Scope:** Dual-stack

### Step 7: Trusted Interfaces

For each interface in `IFACE_TRUSTED`, adds ACCEPT rules for all INPUT and
OUTPUT traffic. These bypass all subsequent filtering.

- **Source:** `firewall:85-96`
- **Config:** `IFACE_TRUSTED`
- **Chains:** INPUT, OUTPUT
- **Scope:** Dual-stack
- **Precedence:** Traffic on trusted interfaces is never filtered

### Step 8: GRE Tunnels — `gre_init()`

When `USE_GRE=1`, creates GRE tunnel interfaces and dedicated GRE_IN/GRE_OUT
chains. Adds protocol 47 (GRE) ACCEPT rules for each tunnel endpoint.

- **Source:** `firewall:99`, `gretunnel.sh`
- **Config:** `USE_GRE`, `gre.rules`
- **Chains:** INPUT (GRE_IN), OUTPUT (GRE_OUT)

### Step 9: Helper Chains

Creates utility chains used as jump targets throughout the firewall:

- **RESET** — sends TCP RST then DROP (for non-TCP)
- **PROHIBIT** — sends ICMP host-prohibited (IPv4) or icmp6-adm-prohibited (IPv6)

- **Source:** `firewall:102-107`
- **Scope:** Dual-stack

### Step 10: Sysctl Kernel Tuning

Applies kernel network parameters: conntrack table size, TCP settings,
SYN flood protection, routing/spoofing protection, IPv6 hardening.

- **Source:** `sysctl.rules`
- **Config:** `SYSCTL_*` variables
- **Scope:** System-wide (kernel parameters)

### Step 11: MSS Clamping

Clamps outbound TCP MSS to path MTU to prevent fragmentation issues.

- **Source:** `firewall:113`
- **Chains:** OUTPUT
- **Scope:** Dual-stack

### Step 12: Nonroutable Network Blocks

Blocks traffic from/to nonroutable address space using network list files:

- `BLK_MCATNET` — multicast networks (`224.0.0.0/4`)
- `BLK_PRVNET` — private networks (`10/8`, `172.16/12`, `192.168/16`, etc.)
- `BLK_RESNET` — reserved/unassigned networks (optionally downloaded)

- **Source:** `firewall:116-127`, `functions.apf` (`dnet`)
- **Config:** `BLK_MCATNET`, `BLK_PRVNET`, `BLK_RESNET`, `DLIST_RESERVED`
- **Chains:** INPUT, OUTPUT
- **Scope:** Address-family aware via `ipt_for_host()`

### Step 13: Trust System Chains

Creates the four trust chains and the temporary refresh chain, then jumps
to them from INPUT and OUTPUT:

- **REFRESH_TEMP** — temporary chain used during `apf -e` refresh
- **TALLOW** — local allow list (`allow_hosts.rules`)
- **TGALLOW** — global allow list (`glob_allow.rules`)
- **TDENY** — local deny list (`deny_hosts.rules`)
- **TGDENY** — global deny list (`glob_deny.rules`)

Jump order in INPUT: REFRESH_TEMP → TALLOW → TGALLOW → TDENY → TGDENY.

- **Source:** `firewall:130-144`
- **Scope:** Dual-stack
- **Precedence:** Allow lists are evaluated before deny lists

### Step 14: Blocked Traffic — `bt.rules`

This is a large phase that loads multiple blocking subsystems in order:

#### 14a. Deny Lists

Downloads and loads deny host lists into the trust chains:

- `glob_deny.rules` → TGDENY
- `deny_hosts.rules` → TDENY

**Source:** `bt.rules:4-6`

#### 14b. Remote Block Lists

Downloads and loads external IP block lists into dedicated chains:

- **Project Honey Pot** — `dlist_php` / `DLIST_PHP`
- **DShield** — `dlist_dshield` / `DLIST_DSHIELD`
- **Spamhaus DROP** — `dlist_spamhaus` / `DLIST_SPAMHAUS`

**Source:** `bt.rules:9-18` | **Config:** `DLIST_PHP`, `DLIST_DSHIELD`, `DLIST_SPAMHAUS`

#### 14c. ipset Block Lists

Loads kernel-level ipset hash tables from `ipset.rules`. Each set gets a
dedicated chain with a single `-m set --match-set` rule for O(1) lookup.

**Source:** `bt.rules:21` | **Config:** `USE_IPSET`, `ipset.rules`

#### 14d. Common Drop Ports — `cdports()`

Silently drops traffic on ports listed in `BLK_PORTS` (e.g., NetBIOS, RPC).

**Source:** `bt.rules:24` | **Config:** `BLK_PORTS`
**Chains:** INPUT, OUTPUT | **Scope:** Dual-stack

#### 14e. Gateway MAC Filter

When `VF_LGATE` is set, requires all traffic to arrive via a specific MAC
address.

**Source:** `bt.rules:28-29` | **Config:** `VF_LGATE`

#### 14f. Packet Sanity — `PKT_SANITY`

Creates IN_SANITY and OUT_SANITY chains (IPv4) and IN_SANITY6/OUT_SANITY6
(IPv6) that check for invalid TCP flag combinations:

- ALL NONE, SYN+FIN, SYN+RST, FIN+RST, ACK+FIN, ACK+URG, ACK+PSH
- ALL FIN+URG+PSH, ALL SYN+RST+ACK+FIN+URG, ALL ALL, ALL FIN

Sub-options:
- `PKT_SANITY_INV` — INVALID connection state blocking
- `PKT_SANITY_FUDP` — fragmented UDP blocking (FRAG_UDP / FRAG_UDP6)
- `PKT_SANITY_PZERO` — port zero traffic blocking (PZERO / PZERO6)

When `RAB_SANITY=1`, sanity violations also tag addresses for RAB blocking.

**Source:** `bt.rules:37-333` | **Config:** `PKT_SANITY`, `PKT_SANITY_*`
**Chains:** INPUT (IN_SANITY), OUTPUT (OUT_SANITY) | **Scope:** IPv4 + IPv6

#### 14g. IDENT Blocking

When `BLK_IDENT=1` and port 113 is not in `IG_TCP_CPORTS`, creates the
IDENT chain to REJECT ident requests (prevents service stalls).

**Source:** `bt.rules:335-360` | **Config:** `BLK_IDENT`
**Chains:** INPUT, OUTPUT | **Scope:** Dual-stack

#### 14h. Multicast Blocking

When `BLK_MCATNET=1`, creates MCAST (IPv4 `224.0.0.0/8`) and MCAST6
(IPv6 `ff00::/8`) chains. IPv6 NDP types 133-136 are exempted to preserve
neighbor discovery.

**Source:** `bt.rules:362-402` | **Config:** `BLK_MCATNET`
**Chains:** INPUT, OUTPUT | **Scope:** IPv4 + IPv6

#### 14i. P2P Blocking

When `BLK_P2P_PORTS` is set, creates the P2P chain to block common
peer-to-peer protocol ports (BitTorrent, Kazaa, eDonkey, etc.).

**Source:** `bt.rules:404-453` | **Config:** `BLK_P2P_PORTS`
**Chains:** INPUT, OUTPUT | **Scope:** Dual-stack

#### 14j. TCP SACK Panic Mitigation

When `BLK_TCP_SACK_PANIC=1`, inserts (via `-I`, first position) an INPUT
rule blocking TCP SYN packets with MSS 1-500 bytes. Mitigates
CVE-2019-11477/11478/11479.

**Source:** `bt.rules:455-459` | **Config:** `BLK_TCP_SACK_PANIC`
**Chains:** INPUT (INSERT, not APPEND) | **Scope:** Dual-stack
**Precedence:** Inserted at top of INPUT, evaluated before all appended rules

### Step 15: Allow Lists

Populates the trust chains with allow entries:

- `glob_allow.rules` → TGALLOW (after download via `glob_allow_download`)
- `allow_hosts.rules` → TALLOW

Entries can be plain IPs/CIDRs/FQDNs or advanced trust syntax.

- **Source:** `firewall:153-155`
- **Chains:** TALLOW, TGALLOW (INPUT + OUTPUT)
- **Scope:** Dual-stack via `ipt_for_host()`

### Step 16: RAB (Reactive Address Blocking)

When `RAB=1`, adds trip rules to INPUT using the `recent` module. Addresses
flagged by sanity checks or port scans are blocked for `RAB_TIMER` seconds.

When `RAB_PSCAN_LEVEL` > 0, creates the RABPSCAN chain monitoring specific
ports. DNS nameservers are exempted from portscan detection.

- **Source:** `firewall:158-208`
- **Config:** `RAB`, `RAB_*` variables
- **Chains:** INPUT, RABPSCAN

### Step 17: Log Rules — `log.rules`

When `LOG_DROP=1` and `LOG_IA=1`, creates SSH_LOG and TELNET_LOG chains
to log new interactive access attempts.

- **Source:** `log.rules`
- **Config:** `LOG_DROP`, `LOG_IA`, `HELPER_SSH_PORT`
- **Chains:** INPUT

### Step 18: VNET Per-IP Policies — `main.vnet`

When `SET_VNET=1`, loads per-IP rule files from the `vnet/` directory. Each
file can override global port filtering variables for a specific IP address,
then sources `cports.common` with the overridden values.

- **Source:** `firewall:218`, `vnet/main.vnet`
- **Config:** `SET_VNET`
- **Scope:** IPv4 only
- **Precedence:** Per-IP rules are appended before global port rules

### Step 19: Port Filtering — `cports.common`

The main port filtering engine, loaded via `main.rules`:

#### 19a. Connection Limits (connlimit)

When `IG_TCP_CLIMIT` or `IG_UDP_CLIMIT` is set, adds per-port concurrent
connection limits using `xt_connlimit`. REJECT action for immediate client
feedback. **Inserted before ACCEPT rules.**

**Config:** `IG_TCP_CLIMIT`, `IG_UDP_CLIMIT`

#### 19b. Inbound TCP/UDP Ports

Opens ports listed in `IG_TCP_CPORTS` and `IG_UDP_CPORTS` with ACCEPT rules.

**Config:** `IG_TCP_CPORTS`, `IG_UDP_CPORTS`

#### 19c. Outbound TCP/UDP Ports (EGF=1)

When egress filtering is enabled, opens ports listed in `EG_TCP_CPORTS` and
`EG_UDP_CPORTS` with ACCEPT rules.

**Config:** `EGF`, `EG_TCP_CPORTS`, `EG_UDP_CPORTS`

#### 19d. ICMP / ICMPv6

Opens ICMP types listed in `IG_ICMP_TYPES` (inbound) and `EG_ICMP_TYPES`
(outbound). IPv6 NDP types 133-136 are always permitted regardless of
configuration. ICMPv6 types controlled by `IG_ICMPV6_TYPES` and
`EG_ICMPV6_TYPES`.

**Config:** `IG_ICMP_TYPES`, `IG_ICMPV6_TYPES`, `EG_ICMP_TYPES`, `EG_ICMPV6_TYPES`

#### 19e. UID-based Egress (EGF=1)

When `EG_TCP_UID` or `EG_UDP_UID` is set, adds per-UID outbound ACCEPT
rules using `--uid-owner` match.

**Config:** `EG_TCP_UID`, `EG_UDP_UID`

#### 19f. Command-based Egress (EGF=1)

When `EG_DROP_CMD` is set, creates the DEG chain to block specific
executables from network access using `--cmd-owner` match. Runtime detection
skips gracefully if unsupported.

**Config:** `EG_DROP_CMD`

- **Source:** `cports.common`, loaded via `main.rules`
- **Chains:** INPUT, OUTPUT
- **Scope:** Dual-stack via `ipt_dst()` / `ipt_src()`

### Step 20: State Tracking

Adds connection state rules:

- INPUT: Drop non-SYN NEW TCP, ACCEPT ESTABLISHED/RELATED TCP and UDP
- OUTPUT: ACCEPT ESTABLISHED/RELATED TCP and UDP (ports 1024-65535)

- **Source:** `firewall:233-237`
- **Chains:** INPUT, OUTPUT
- **Scope:** Dual-stack

### Step 21: DNS Rules

For each nameserver in `/etc/resolv.conf`:

- When `RESV_DNS=1`: per-nameserver INPUT/OUTPUT rules with state filtering,
  routed to `ipt4` or `ipt6` by address type
- When `RESV_DNS=0`: generic DNS rules for all nameservers
- When `RESV_DNS_DROP=1`: explicit DROP for non-whitelisted DNS sport 53

- **Source:** `firewall:240-275`
- **Config:** `RESV_DNS`, `RESV_DNS_DROP`
- **Chains:** INPUT, OUTPUT
- **Scope:** IPv4 + IPv6

### Step 22: Service Helpers

Optional protocol-specific rules:

- **FTP** (`HELPER_FTP=1`): RELATED/ESTABLISHED rules for control and data channels
- **SSH** (`HELPER_SSH=1`): ESTABLISHED/RELATED return traffic from SSH port
- **Traceroute** (`TCR_PASS=1`): UDP NEW on `TCR_PORTS` range

- **Source:** `firewall:278-296`
- **Config:** `HELPER_FTP`, `HELPER_SSH`, `TCR_PASS`
- **Chains:** INPUT, OUTPUT
- **Scope:** Dual-stack

### Step 23: Drop Logging

When `LOG_DROP=1`, adds rate-limited log rules for packets reaching the end
of INPUT and OUTPUT chains (about to be dropped by default policy).

- **Source:** `firewall:299-309`
- **Config:** `LOG_DROP`, `LOG_RATE`, `LOG_LEVEL`
- **Chains:** INPUT, OUTPUT
- **Scope:** Dual-stack

### Step 24: ECN Shame List

When `SYSCTL_ECN=1`, loads the ECN shame list of hosts that break with
Explicit Congestion Notification enabled.

- **Source:** `firewall:313-316`
- **Config:** `SYSCTL_ECN`, `DLIST_ECNSHAME`

### Step 25: Postroute Rules

Loads ToS POSTROUTING classifications and custom `postroute.rules`.

- **Source:** `firewall:319-320`
- **Config:** `TOS_*` variables
- **Chains:** mangle POSTROUTING

### Step 26: Default OUTPUT Policy

- **EGF disabled** (default): `OUTPUT -j ACCEPT` — all outbound traffic allowed
- **EGF enabled**: `OUTPUT -j DROP` for tcp, udp, and all — only explicitly
  opened ports are allowed out

- **Source:** `firewall:323-331`
- **Config:** `EGF`
- **Chains:** OUTPUT
- **Scope:** Dual-stack

### Step 27: Default INPUT Policy

Appends final DROP rules for tcp, udp, and all protocols. Any packet that
has not matched a previous ACCEPT rule is dropped here.

- **Source:** `firewall:334-337`
- **Chains:** INPUT
- **Scope:** Dual-stack

### Step 28: Save Snapshot

When `DEVEL_MODE=0` and `DOCKER_COMPAT=0` and rules are active, saves
`iptables-save` snapshot for next fast load. Records iptables backend
(legacy/nft) in `.apf.restore.backend`.

- **Source:** `apf:191-204`

---

## 3. INPUT Chain Rule Order (Precedence)

This is the actual order of rules in the INPUT chain after a full load.
Packets are evaluated top-to-bottom; the first matching rule wins.

```
 #   Rule                          Source          Action
 ─── ───────────────────────────── ─────────────── ──────────
  1  TCP SYN MSS 1:500             bt.rules        DROP *
  2  Loopback (lo)                 firewall        ACCEPT
  3  Trusted interface             firewall        ACCEPT
  4  GRE_IN chain                  firewall        (per-tunnel)
  5  REFRESH_TEMP chain            firewall        (temporary)
  6  TALLOW chain                  firewall        ACCEPT
  7  TGALLOW chain                 firewall        ACCEPT
  8  TDENY chain                   firewall        DROP/REJECT
  9  TGDENY chain                  firewall        DROP/REJECT
 10  PHP blocklist chain           bt.rules        DROP
 11  DShield blocklist chain       bt.rules        DROP
 12  Spamhaus SDROP chain          bt.rules        DROP
 13  IPSET_* chains                bt.rules        DROP
 14  BLK_PORTS (common drops)      bt.rules        DROP
 15  LMAC (gateway MAC)            bt.rules        DROP
 16  IN_SANITY (packet sanity)     bt.rules        DROP
 17  FRAG_UDP (fragmented UDP)     bt.rules        DROP
 18  PZERO (port zero)             bt.rules        DROP
 19  IN_SANITY6 (IPv6 sanity)      bt.rules        DROP
 20  FRAG_UDP6 (IPv6 frag UDP)     bt.rules        DROP
 21  PZERO6 (IPv6 port zero)       bt.rules        DROP
 22  IDENT (port 113)              bt.rules        REJECT
 23  MCAST (multicast)             bt.rules        DROP
 24  MCAST6 (IPv6 multicast)       bt.rules        DROP
 25  P2P (P2P ports)               bt.rules        REJECT
 26  RAB trip (recent match)       firewall        DROP
 27  RABPSCAN chain                firewall        DROP
 28  SSH_LOG / TELNET_LOG          log.rules       LOG (cont.)
 29  VNET per-IP port rules        main.vnet       ACCEPT
 30  Connlimit REJECT              cports.common   REJECT
 31  Inbound TCP port ACCEPT       cports.common   ACCEPT
 32  Inbound UDP port ACCEPT       cports.common   ACCEPT
 33  ICMP type ACCEPT              cports.common   ACCEPT
 34  NDP 133-136 ACCEPT            cports.common   ACCEPT
 35  ICMPv6 type ACCEPT            cports.common   ACCEPT
 36  Non-SYN NEW tcp DROP          firewall        DROP
 37  ESTABLISHED,RELATED tcp       firewall        ACCEPT
 38  ESTABLISHED,RELATED udp       firewall        ACCEPT
 39  DNS (per-nameserver)          firewall        ACCEPT
 40  FTP helper                    firewall        ACCEPT
 41  SSH helper                    firewall        ACCEPT
 42  Traceroute                    firewall        ACCEPT
 43  Log (rate-limited)            firewall        LOG (cont.)
 44  Default DROP tcp              firewall        DROP
 45  Default DROP udp              firewall        DROP
 46  Default DROP all              firewall        DROP

 * BLK_TCP_SACK_PANIC uses -I (INSERT), placing it at position 1
   regardless of when it is loaded during the script.
```

> **Note:** Rules marked "LOG (cont.)" log the packet but do not terminate
> evaluation — the packet continues to the next rule.

---

## 4. Key Precedence Rules

These are the most important "what beats what" relationships:

1. **TCP SACK Panic** is inserted (`-I`) at the top of INPUT, so it is
   evaluated before everything else, even loopback and trusted interfaces.

2. **Trusted interfaces bypass ALL filtering.** Traffic on `IFACE_TRUSTED`
   is accepted immediately and never reaches trust chains, block lists, or
   port rules.

3. **Allow lists are evaluated before deny lists.** The chain jump order is
   TALLOW → TGALLOW → TDENY → TGDENY. If an address is in both allow and
   deny lists, the allow wins.

4. **Deny lists are evaluated before port rules.** A denied address is
   blocked even if the destination port is open.

5. **Remote block lists (PHP, DShield, Spamhaus) and ipset lists** are
   evaluated before port ACCEPT rules. An address on a block list cannot
   reach any open port.

6. **Packet sanity checks** run before port rules. Malformed packets are
   dropped regardless of whether the destination port is open.

7. **Connlimit REJECT runs before port ACCEPT.** A connection from a source
   IP that has exceeded the per-port limit is rejected even though the port
   is configured as open.

8. **VNET per-IP rules precede global port rules.** When `SET_VNET=1`, the
   per-IP `cports.common` rules are loaded first (via `main.vnet`), followed
   by the global `cports.common` with the primary IP's context.

9. **State tracking comes after port rules.** ESTABLISHED/RELATED packets
   for connections that were allowed by port rules are accepted. Packets
   that don't match any port rule fall through to state tracking.

10. **RAB portscan tagging** happens in the sanity checks (via
    `RAB_SANITY_FLAGS`), but the RAB trip/block rules are evaluated in the
    RAB section — after allow lists but before port rules.

11. **Default policy is DROP.** Any packet not explicitly accepted by a
    previous rule is dropped at the end of the INPUT chain.

---

## 5. Fast Load vs Full Load

APF supports two startup modes when `SET_FASTLOAD=1`:

### Fast Load

Restores a previously saved `iptables-save` / `ip6tables-save` snapshot
in a single atomic operation. This is significantly faster than rebuilding
every rule from scratch.

**Fast load is used when ALL of these conditions are true:**

- `SET_FASTLOAD=1` and `DOCKER_COMPAT=0`
- Not the first run (`.last.full` exists)
- Snapshot is less than 12 hours old
- Configuration files have not changed (MD5 check)
- `DEVEL_MODE=0`
- System uptime is greater than 10 minutes
- Snapshot backend (legacy/nft) matches current iptables backend

**Fast load is skipped (full load used instead) when ANY condition fails:**

| Condition | Log Message |
|-----------|-------------|
| First run | `fast load skipped [internals/.last.full not present]` |
| Snapshot > 12h old | `fast load snapshot more than 12h old` |
| Config changed | `config. or .rule file has changed since last full load` |
| DEVEL_MODE=1 | (triggers config change detection) |
| Uptime <= 10 min | `uptime less than 10 minutes` |
| Backend mismatch | `fast load snapshot backend mismatch` |
| Restore fails | `fast load failed (iptables-restore error)` |
| IPv6 incomplete | `fast load incomplete (IPv6 enabled but no IPv6 snapshot)` |

### Full Load

Regenerates every rule from scratch by executing the full firewall script.
This is slower but guarantees that all rules reflect the current
configuration. A new snapshot is saved at the end for the next fast load
(unless `DEVEL_MODE=1` or `DOCKER_COMPAT=1`).
