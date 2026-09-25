# ft_nmap test suites

These files are designed for the existing `tools/test_runner.py`. The runner itself is not included or modified.

Prerequisites:

```sh
make
make lab-up
```

Interactive mode:

```sh
python3 tools/test_runner.py
```

Direct examples:

```sh
python3 tools/test_runner.py syn
python3 tools/test_runner.py syn 1
python3 tools/test_runner.py syn 1-3
python3 tools/test_runner.py syn all
python3 tools/test_runner.py correction all
```

`ft:` commands execute the project scanner. `nmap:` commands are visual references where a meaningful equivalent exists. The runner intentionally does not auto-diff the two tools: differences such as Nmap wording, timing policy, combined verdicts and lightweight OS hints must be interpreted by the reviewer.

The deterministic lab contract used by the suites is `lab/README.md` plus the actual `lab/configs/*.env` firewall/listener setup. IPv4 REJECT uses ICMP host-prohibited; IPv6 REJECT uses ICMPv6 administratively-prohibited.

The `correction` suite contains short semantic checks, public-option checks, long scans, multi-target/multi-interface cases, IPv6, deterministic rate-limit cases, and a concurrent-process stress test.
