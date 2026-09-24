# Technical documentation

This directory documents the implementation as shipped in the repository. It is intended for maintainers, reviewers and contributors who need to understand the scanner without reconstructing behavior from source files.

| Document | Scope |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Process architecture, interface grouping, event loop, scheduler, sender workers and runtime lifecycle |
| [`SCANNING.md`](SCANNING.md) | What each scan is for and how replies map to port states |
| [`PACKET_IO.md`](PACKET_IO.md) | Raw probe construction, checksums, libpcap capture, L2/IP parsing, ICMP quotation and exact reply matching |
| [`DATA_MODEL.md`](DATA_MODEL.md) | Core C structures, ownership and relationships |
| [`DESIGN_DECISIONS.md`](DESIGN_DECISIONS.md) | Deliberate trade-offs and differences from the full Nmap feature set |

The documentation names the source modules that implement each behavior. Those source references are the maintenance anchor: if behavior changes, the corresponding document should change in the same commit.
