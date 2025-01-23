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

Show the state of TCP ports `22-30` at `reddit.com`:

```text
$ pscan reddit.com -s tcp -p 22-30

Host is up (13ms latency).
pscan report for reddit.com (2a04:4e42::396):22-30
PORT       STATE      SERVICE
22/tcp     filtered   ssh
23/tcp     filtered   telnet
24/tcp     filtered   unknown
25/tcp     filtered   smtp
26/tcp     filtered   unknown
27/tcp     filtered   nsw-fe
28/tcp     filtered   unknown
29/tcp     filtered   msg-icp
30/tcp     filtered   unknown

pscan done: scanned in 0.08 seconds
```

Show the state of all UDP ports in the range `22-29` at address `10.0.0.44`:

```text
$ pscan 10.0.0.44 -s udp -p 22-29

Host is up (0ms latency).
pscan report for 10.0.0.44:22-29
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
