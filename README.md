# ft_nmap

`ft_nmap` is a raw-socket network scanner implementing a focused subset of Nmap-style TCP and UDP scan semantics for IPv4 and IPv6.

The project is organized around four explicit boundaries:

- **routing and interface selection** are delegated to the operating system;
- **packet transmission** uses raw sockets and project-owned IPv4/IPv6/TCP/UDP headers;
- **packet capture** is handled through libpcap;
- **scan policy** lives in the runtime engine, independently from packet parsing.

This separation keeps wire-format code, capture code, matching, scheduling, timing and reporting independently inspectable.

## Supported scan types

| Scan | Transport | Probe | Primary purpose |
|---|---|---|---|
| SYN | TCP | `SYN` | Distinguish open, closed and filtered TCP ports |
| ACK | TCP | `ACK` | Determine whether traffic reaches the remote TCP stack through filtering |
| NULL | TCP | no flags | Distinguish closed from open-or-filtered TCP ports |
| FIN | TCP | `FIN` | Distinguish closed from open-or-filtered TCP ports |
| XMAS | TCP | `FIN|PSH|URG` | Distinguish closed from open-or-filtered TCP ports |
| UDP | UDP | empty datagram | Distinguish UDP reply, explicit rejection and silence |

Detailed semantics are documented in [`docs/SCANNING.md`](docs/SCANNING.md).

## Platform and dependencies

The implementation is primarily Linux-oriented and uses:

- a C11 compiler;
- `libpcap`;
- POSIX threads;
- raw IPv4/IPv6 sockets;
- standard POSIX/Linux networking APIs.

Raw packet transmission and packet capture normally require elevated privileges.

## Build

```sh
make
```

Debug and profiling builds are provided by the repository Makefile.

## Usage

```sh
sudo ./ft_nmap --ip 192.0.2.10 --ports 22,80,443 --scan SYN --reason
```

Main options:

```text
--ip <host>                target host, IPv4/IPv6 address or hostname
--file <file>              read targets from a file
--ports <list|range>       ports to scan; default 1-1024
--scan <types>             SYN,NULL,FIN,XMAS,ACK,UDP
--speedup <0-250>          sender worker count
--timeout <ms>             override TCP/UDP probe timeout
--retries <count>          maximum retransmissions
--ttl <0-255>              IPv4 TTL / IPv6 Hop Limit
--no-dns                   disable reverse DNS
--os                       enable lightweight TTL/Hop-Limit fingerprinting
--short                    hide repetitive/inconclusive rows
--reason                   show the evidence behind each state
```

## Network model

Interface names are **not hardcoded**. For each destination, `ft_nmap` asks the kernel which local source address would be used, maps that address back to a live interface, then groups destinations by the resulting interface index.

Resources are shared per interface:

```text
Destination A ── kernel route ──┐
Destination B ── kernel route ──┼──► interface X
                                │      ├── libpcap capture
                                │      ├── IPv4 raw socket
                                │      └── IPv6 raw socket
Destination C ── kernel route ──┘
```

The full execution model is documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — engine, interfaces, scheduling, workers and probe lifecycle
- [`docs/SCANNING.md`](docs/SCANNING.md) — scan semantics and decision trees
- [`docs/PACKET_IO.md`](docs/PACKET_IO.md) — packet construction, libpcap capture, parsing and reply matching
- [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) — core structures, ownership and lifetime
- [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) — deliberate implementation choices, limitations and scope relative to full Nmap

The deterministic local network laboratory is documented separately in [`lab/README.md`](lab/README.md).

## Scope and implementation limits

Current compile-time limits include:

- 1024 ports per scan configuration;
- 1024 targets;
- up to 250 sender threads.

The project intentionally implements a focused scanner, not a drop-in replacement for the complete Nmap feature set. See [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md).

## Responsible use

Use packet-scanning software only on systems and networks for which you have authorization.
