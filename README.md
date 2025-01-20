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

Show all opened TCP ports at address `10.0.0.44`:

```text
$ pscan 10.0.0.44 -s tcp -i filtered -i closed

pscan report for 10.0.0.44:1-65535
Not shown: 65533 closed ports
PORT       STATE      SERVICE
5900/tcp   open       rfb
54446/tcp  open       unknown

pscan done: scanned in 0.75 seconds
```

Show the state of all UDP ports in the range `22-29` at address `10.0.0.44`:

```text
$ pscan 10.0.0.44 -s udp -p 22-29

pscan report for 10.0.0.44:22-29
PORT       STATE      SERVICE
22/udp     closed     ssh
23/udp     closed     telnet
24/udp     closed     unknown
25/udp     closed     smtp
26/udp     closed     unknown
27/udp     closed     nsw-fe
28/udp     closed     unknown
29/udp     closed     msg-icp

pscan done: scanned in 0.06 seconds
```
