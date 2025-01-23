# pscan

A fast, multi-threaded port scanner implementation in Rust.

This program provides command-line functionality to scan TCP and UDP ports on
specified IP addresses.

## Features

- Multi-threaded scanning for improved performance
- Support for both TCP and UDP protocols
- Customizable port ranges
- Service name resolution using IANA registries
- Filterable output based on port states

## Examples

Show the state of TCP ports `54000-60000` at address `10.0.0.44` filtering out
ports in the `filtered` and `closed` states:

```text
$ pscan 10.0.0.44 -s tcp -p 54000-60000 -i filtered -i closed

Host is up (0ms latency).
pscan report for 10.0.0.44:54000-60000
Not shown: 6000 closed ports
PORT       STATE      SERVICE
54446/tcp  open       unknown

pscan done: scanned in 0.08 seconds
```

Show the state of all UDP ports in the range `22-29` at `reddit.com`:

```text
$ pscan reddit.com -s udp -p 22-29

Host is up (12ms latency).
pscan report for reddit.com (2a04:4e42:600::396):22-29
PORT       STATE      SERVICE
22/udp     filtered   ssh
23/udp     filtered   telnet
24/udp     filtered   unknown
25/udp     filtered   smtp
26/udp     filtered   unknown
27/udp     filtered   nsw-fe
28/udp     filtered   unknown
29/udp     filtered   msg-icp

pscan done: scanned in 0.06 seconds
```
