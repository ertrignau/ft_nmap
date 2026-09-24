# Design decisions and scope

This document records choices that are easy to misread as accidental limitations when looking only at individual source files.

The objective is not to reproduce every subsystem in the full Nmap codebase. `ft_nmap` implements a focused raw-packet scanner with explicit, inspectable behavior.

## 1. Kernel-selected routing instead of configured interface names

**Decision:** derive the source address and outgoing interface from the operating system's route decision for each target.

**Why:** interface names, routing metrics, VPNs, multiple NICs and IPv6 scopes are host-specific. A scanner should not encode a local topology in its source code.

**Implementation:** temporary UDP `connect()` + `getsockname()`, followed by `getifaddrs()` to resolve the source address to an interface and `ifindex`.

**Consequence:** one scan can legitimately use multiple interfaces, and interface resources are created dynamically.

## 2. One capture context per interface

**Decision:** share libpcap and raw sockets across targets routed through the same interface.

**Why:** packet capture is naturally an interface-level resource. Creating one capture per destination would duplicate the same incoming traffic and complicate ownership.

**Consequence:** receive-side dispatch must identify the target and probe after capture; that work is performed by exact userspace matching.

## 3. Broad BPF filter, strict userspace validation

**Decision:** install the BPF filter `ip or ip6` instead of a filter that names every target or requires the outer source address to be a target.

**Why:** valid ICMP errors may come from intermediate routers or firewalls. A narrow outer-address filter could discard the only evidence explaining a filtered path.

**Consequence:** more IP packets can reach userspace, so the matching layer must be strict. The implementation first obtains an O(1) source-port candidate, then validates addresses, ports, transport and quoted original packet information.

## 4. libpcap owns capture transport and buffering

**Decision:** depend on libpcap's capture abstraction rather than implementing a Linux-specific packet ring directly.

**Why:** the scanner needs a selectable, non-blocking stream of captured frames and datalink metadata; libpcap already provides that contract across multiple link types.

**Consequence:** `ft_nmap` does not expose or depend on a particular kernel ring-buffer layout. Platform-specific buffering or zero-copy behavior, when available, remains an implementation detail of libpcap and its backend.

## 5. Wire parsing is separate from scan policy

**Decision:** normalize captured bytes into `t_nmap_reply` before matching/classification.

**Why:** Ethernet/VLAN/SLL/802.11 framing, IPv4 options, IPv6 extension headers and ICMP quotation are packet-format concerns. `SYN + RST -> closed` is scan policy. Combining the two makes both harder to verify.

**Consequence:** the runtime classifier operates on semantic fields instead of packet offsets.

## 6. Source-port index plus full validation

**Decision:** assign every logical probe a unique source port inside one target runtime and maintain `probe_by_src_port[65536]`.

**Why:** direct replies carry that port as their destination port; ICMP quotations carry it as the original source port. This provides O(1) candidate lookup.

**Why validation still matters:** ports alone are not a globally unique packet identity. The candidate is accepted only after target/local addresses, original protocol, target port and, when available, original TCP sequence are checked.

## 7. One logical probe survives retries

**Decision:** a retransmission returns the existing probe to `PENDING`; it does not allocate another probe object.

**Why:** the logical question has not changed: "what is the state of this `(port, scan)` pair?" Keeping one object preserves result ownership, retry accounting and source-port identity.

**Consequence:** the runtime needs explicit lifecycle states and generation IDs so queued work cannot become stale after a result or re-reservation.

## 8. Sender workers do not own policy

**Decision:** workers only execute already-selected sends.

**Why:** allowing worker threads to schedule, classify or expire probes would distribute the state machine across multiple concurrency domains and create avoidable synchronization paths.

**Consequence:** the main receive/event loop remains the authority for network evidence and retry decisions.

## 9. Generic UDP payload

**Decision:** the current UDP scanner sends an empty payload for every destination port.

**Why:** this keeps probe generation protocol-independent and deterministic.

**Trade-off:** many real UDP services respond only to a valid application request. An empty generic probe therefore produces more `open|filtered` results than a scanner with a library of protocol-specific UDP payloads.

This is one of the most important behavioral differences from a mature general-purpose scanner.

## 10. Lightweight service names, not service-version detection

**Decision:** the report maps `(port, protocol)` to conventional names from the local service database and caches that database in memory.

**Why:** this produces useful labels without opening application sessions or implementing protocol fingerprints.

**Trade-off:** a label such as `http` is a conventional port name, not proof of the service or its version. The project does not claim Nmap-style service/version detection.

## 11. Lightweight OS evidence

**Decision:** `--os` records the TTL/Hop Limit observed from the target and maps it to the nearest conventional initial value (64, 128 or 255).

**Why:** this demonstrates use of IP-layer evidence without introducing a fingerprint database and active multi-probe OS detection subsystem.

**Trade-off:** this is a heuristic, not a replacement for Nmap's full OS fingerprinting capabilities.

## 12. No IP fragment reassembly

**Decision:** ignore non-initial IPv4 fragments and non-zero-offset IPv6 fragments.

**Why:** exact probe matching requires the beginning of the TCP/UDP header. Reassembly would add a separate stateful subsystem with memory limits, fragment timeouts and overlap handling.

**Consequence:** fragmented replies that do not contain the initial transport header are not usable evidence.

## 13. IPv6 extension walking is bounded to useful chains

**Decision:** support the extension headers required to locate TCP/UDP/ICMPv6—Hop-by-Hop, Routing, Destination Options, first Fragment and AH—and reject unsupported/malformed chains.

**Why:** the scanner needs reliable upper-layer location, not a general IPv6 stack.

## 14. Scope relative to full Nmap

`ft_nmap` should be read as an implementation of selected scanning primitives, not as feature compatibility with the complete Nmap suite.

Implemented here:

- raw TCP SYN/ACK/NULL/FIN/XMAS scans;
- generic UDP scanning;
- IPv4 and IPv6 packet construction/parsing;
- route-aware multi-interface operation;
- libpcap capture and BPF filtering;
- exact direct/ICMP reply matching;
- retries, timeouts and adaptive timing elements;
- multi-target scheduling;
- conventional service-name lookup;
- lightweight TTL/Hop-Limit OS evidence.

Not implemented as full Nmap-equivalent subsystems:

- protocol-specific UDP probe database;
- service/version fingerprint engine;
- full OS fingerprint database and probe suite;
- scripting engine;
- broad collection of Nmap scan techniques and discovery modes;
- Nmap's complete host-group, timing and congestion-control machinery.

These boundaries are deliberate. The code concentrates on packet construction, capture, parsing, concurrency, matching and scan-state semantics—the parts implemented directly in this repository.
