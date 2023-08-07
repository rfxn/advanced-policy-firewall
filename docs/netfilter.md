# Overview

```
 +--------+      +---------+        +------------------+
 | kernel |------| libnl   |--------| nftable frontend |
 +--------+      +---------+        +------------------+
```

### Kernel
* netlink configuration interface
* run-time rule-set evaluation

### libnl
* low level functions for communication with the kernel

### NFTable Frontend
* user interact with via nft


## List rulesets

```
# nft list ruleset
```

## Family type
```
ip
ip6
inet 
arp
bridge
```

## Create table

```
nft add table <family_type> <table_name>
```

## List table
```
nft list tables
```

## List chains and rules in a table
```
nft list table <family_type> <table_name>
```

## Delete table
```
nft delete table <family_type> <table_name>
```

## Flush table
```
nft flush table <family_type> table_name
```

## Create chain
```
nft add chain <family_type> <table_name> <chain_name>
```

## Base chain
```
nft add chain <family_type> <table_name> <chain_name> '{ type <chain_type> hook <hook_type> priority <priority_value> ; }'

chain_type can be filter, route or nat

hook_type can be prerouting, input, forward, output, postrouting

priority_value takes either a priority name or an integer value.
```


## List rules
```
nft list chain <family_type> <table_name> <chain_name>
```

## Edit a chain
```
nft chain <family_type> <table_name> <chain_name> '{ [ type <chain_type> hook <hook_type> device <device_name> priority <priority_value>; policy <policy_type> ; ] } '
```

## Delete a chain
```
nft delete chain <family_type> <table_name> <chain_name>
```

## Flush rules from a chain
```
nft flush chain <family_type> <table_name> <chain_name>
```



## Add rule to chain
The rule is appended at handle_value, which is optional. If not specified, the rule is appended to the end of the chain.

```
nft add rule <family_type> <table_name> <chain_name> handle <handle_value> statement

```

to prepend the rule to the position

```
nft insert rule <family_type> <table_name> <chain_name> handle <handle_value> statement
```


## Delete rule
```
nft delete rule <family_type> <table_name> <chain_name> handle <handle_value>
```



## Sets

Anonymous sets are embedded in rules and cannot be updated, you must delete and re-add the rule. E.g., you cannot just remove "http" from the dports set in the following
```
nft add rule ip6 filter input tcp dport {telnet, http, https} accept
```

Named sets can be updated, and can be typed and flagged
```
table ip sshguard {
       set attackers {
               type ipv4_addr
               flags interval
               elements = { 1.2.3.4 }
       }
```

To add or delete elements from the set, use:
```
nft add element ip sshguard attackers { 5.6.7.8/32 }
nft delete element ip sshguard attackers { 1.2.3.4/32 }
```


## Guidelines

```
Single machine
Flush the current ruleset:

# nft flush ruleset
Add a table:

# nft add table inet my_table
Add the input, forward, and output base chains. The policy for input and forward will be to drop. The policy for output will be to accept.

# nft add chain inet my_table my_input '{ type filter hook input priority 0 ; policy drop ; }'
# nft add chain inet my_table my_forward '{ type filter hook forward priority 0 ; policy drop ; }'
# nft add chain inet my_table my_output '{ type filter hook output priority 0 ; policy accept ; }'
Add two regular chains that will be associated with tcp and udp:

# nft add chain inet my_table my_tcp_chain
# nft add chain inet my_table my_udp_chain
Related and established traffic will be accepted:

# nft add rule inet my_table my_input ct state related,established accept
All loopback interface traffic will be accepted:

# nft add rule inet my_table my_input iif lo accept
Drop any invalid traffic:

# nft add rule inet my_table my_input ct state invalid drop
Accept ICMP and IGMP:

# nft add rule inet my_table my_input meta l4proto ipv6-icmp icmpv6 type '{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-reply, mld-listener-query, mld-listener-report, mld-listener-reduction, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, ind-neighbor-solicit, ind-neighbor-advert, mld2-listener-report }' accept
# nft add rule inet my_table my_input meta l4proto icmp icmp type '{ destination-unreachable, router-solicitation, router-advertisement, time-exceeded, parameter-problem }' accept
# nft add rule inet my_table my_input ip protocol igmp accept
New udp traffic will jump to the UDP chain:

# nft add rule inet my_table my_input meta l4proto udp ct state new jump my_udp_chain
New tcp traffic will jump to the TCP chain:

# nft add rule inet my_table my_input 'meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn ct state new jump my_tcp_chain'
Reject all traffic that was not processed by other rules:

# nft add rule inet my_table my_input meta l4proto udp reject
# nft add rule inet my_table my_input meta l4proto tcp reject with tcp reset
# nft add rule inet my_table my_input counter reject with icmpx port-unreachable
At this point you should decide what ports you want to open to incoming connections, which are handled by the TCP and UDP chains. For example to open connections for a web server add:

# nft add rule inet my_table my_tcp_chain tcp dport 80 accept
To accept HTTPS connections for a webserver on port 443:

# nft add rule inet my_table my_tcp_chain tcp dport 443 accept
To accept SSH traffic on port 22:

# nft add rule inet my_table my_tcp_chain tcp dport 22 accept
To accept incoming DNS requests:

# nft add rule inet my_table my_tcp_chain tcp dport 53 accept
# nft add rule inet my_table my_udp_chain udp dport 53 accept
Be sure to make your changes permanent when satisifed.
```


