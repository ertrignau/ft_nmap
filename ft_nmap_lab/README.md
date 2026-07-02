# ft_nmap Docker lab

This lab only manages a controlled Docker target at `172.28.0.10`.
It does not run `nmap`, `ft_nmap`, `tcpdump`, `strace`, or comparisons.
A profile defines which ports are open, closed, dropped, or rejected.
Closed ports are simply ports with no service and no firewall DROP/REJECT rule.
Use the root Makefile aliases like `make lab-tcp-many` or `make lab-udp-many`.
