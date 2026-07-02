#!/bin/sh
set -eu

mkdir -p ft_nmap_lab/configs

cat > ft_nmap_lab/Makefile <<'EOF'
.DEFAULT_GOAL := help
.RECIPEPREFIX := >

# **************************************************************************** #
#                                  DOCKER LAB                                  #
# **************************************************************************** #

COMPOSE ?= docker compose
PROFILE ?= default

# **************************************************************************** #
#                                   RULES                                      #
# **************************************************************************** #

help:
> @printf '%s\n' 'ft_nmap Docker lab'
> @printf '%s\n' ''
> @printf '%s\n' 'The lab only manages the target container state.'
> @printf '%s\n' 'It does not run nmap, ft_nmap, tcpdump, strace, or tests.'
> @printf '%s\n' ''
> @printf '%s\n' 'Commands:'
> @printf '%s\n' '  make up PROFILE=default'
> @printf '%s\n' '  make up PROFILE=tcp-many-open'
> @printf '%s\n' '  make up PROFILE=udp-many-open'
> @printf '%s\n' '  make up PROFILE=mixed'
> @printf '%s\n' '  make up PROFILE=mostly-closed'
> @printf '%s\n' '  make up PROFILE=filtered-heavy'
> @printf '%s\n' ''
> @printf '%s\n' 'Aliases:'
> @printf '%s\n' '  make default'
> @printf '%s\n' '  make tcp-many-open'
> @printf '%s\n' '  make udp-many-open'
> @printf '%s\n' '  make mixed'
> @printf '%s\n' '  make mostly-closed'
> @printf '%s\n' '  make filtered-heavy'
> @printf '%s\n' ''
> @printf '%s\n' 'Other:'
> @printf '%s\n' '  make down'
> @printf '%s\n' '  make re PROFILE=<profile>'
> @printf '%s\n' '  make logs'
> @printf '%s\n' '  make shell'
> @printf '%s\n' '  make ps'
> @printf '%s\n' '  make profiles'

profiles:
> @for file in configs/*.env; do basename "$$file" .env; done

up:
> @test -f "configs/$(PROFILE).env" || { \
> 	echo "unknown lab profile: $(PROFILE)"; \
> 	echo "available profiles:"; \
> 	for file in configs/*.env; do basename "$$file" .env; done; \
> 	exit 1; \
> }
> LAB_PROFILE=$(PROFILE) $(COMPOSE) up -d --build --force-recreate

down:
> $(COMPOSE) down

re: down up

clean:
> $(COMPOSE) down -v --remove-orphans

logs:
> $(COMPOSE) logs -f target

ps:
> $(COMPOSE) ps

shell:
> $(COMPOSE) exec target sh

default:
> $(MAKE) up PROFILE=default

tcp-many-open:
> $(MAKE) up PROFILE=tcp-many-open

udp-many-open:
> $(MAKE) up PROFILE=udp-many-open

mixed:
> $(MAKE) up PROFILE=mixed

mostly-closed:
> $(MAKE) up PROFILE=mostly-closed

filtered-heavy:
> $(MAKE) up PROFILE=filtered-heavy

profile-%:
> $(MAKE) up PROFILE=$*

.PHONY: help profiles up down re clean logs ps shell default tcp-many-open udp-many-open mixed mostly-closed filtered-heavy
EOF

cat > ft_nmap_lab/docker-compose.yml <<'EOF'
services:
  target:
    build: ./target
    container_name: ft_nmap_target
    cap_add:
      - NET_ADMIN
      - NET_RAW
    env_file:
      - ./configs/${LAB_PROFILE:-default}.env
    environment:
      LAB_PROFILE: ${LAB_PROFILE:-default}
    networks:
      ft_nmap_lab:
        ipv4_address: 172.28.0.10

networks:
  ft_nmap_lab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/24
EOF

cat > ft_nmap_lab/README.md <<'EOF'
# ft_nmap Docker lab

This lab only manages a controlled Docker target at `172.28.0.10`.
It does not run `nmap`, `ft_nmap`, `tcpdump`, `strace`, or comparisons.
A profile defines which ports are open, closed, dropped, or rejected.
Closed ports are simply ports with no service and no firewall DROP/REJECT rule.
Use the root Makefile aliases like `make lab-tcp-many` or `make lab-udp-many`.
EOF

cat > ft_nmap_lab/configs/default.env <<'EOF'
TCP_OPEN=21,22,25,53,80,110,143,443,445,993
UDP_OPEN=53,123,161,500,514

TCP_DROP=30,81,88,111,135,139,515,587,631,1021
TCP_REJECT=37,42,113,119,389

UDP_DROP=69,111,520,631,1021
UDP_REJECT=137,138,162,389,450
EOF

cat > ft_nmap_lab/configs/tcp-many-open.env <<'EOF'
TCP_OPEN=1-120,135,137-139,143,161,162,389,443,445,500,514,515,520,587,631,993,1021
UDP_OPEN=53,123,161,500,514

TCP_DROP=
TCP_REJECT=

UDP_DROP=
UDP_REJECT=
EOF

cat > ft_nmap_lab/configs/udp-many-open.env <<'EOF'
TCP_OPEN=21,22,53,80,443
UDP_OPEN=1-120,135,137-139,143,161,162,389,443,445,500,514,515,520,587,631,993,1021

TCP_DROP=
TCP_REJECT=

UDP_DROP=
UDP_REJECT=
EOF

cat > ft_nmap_lab/configs/mixed.env <<'EOF'
TCP_OPEN=21,22,25,53,80,110,143,443,445,993
UDP_OPEN=53,123,161,500,514

TCP_DROP=30,81,88,111,135,139,515,587,631,1021
TCP_REJECT=37,42,113,119,389

UDP_DROP=69,111,520,631,1021
UDP_REJECT=137,138,162,389,450
EOF

cat > ft_nmap_lab/configs/mostly-closed.env <<'EOF'
TCP_OPEN=80,443
UDP_OPEN=53

TCP_DROP=
TCP_REJECT=

UDP_DROP=
UDP_REJECT=
EOF

cat > ft_nmap_lab/configs/filtered-heavy.env <<'EOF'
TCP_OPEN=22,80,443
UDP_OPEN=53,123

TCP_DROP=1-30,81-100,111,135-139,515,587,631,993,1021
TCP_REJECT=37,42,113,119,389,445,500,514,520

UDP_DROP=1-30,69,81-100,111,137-139,520,631,1021
UDP_REJECT=37,42,113,119,162,389,450,500,514
EOF

cat > ft_nmap_lab/target/entrypoint.sh <<'EOF'
#!/bin/sh
set -eu

expand_ports() {
    spec="${1:-}"

    [ -n "$spec" ] || return 0

    old_ifs="$IFS"
    IFS=","
    set -- $spec
    IFS="$old_ifs"

    for item do
        item=$(printf '%s' "$item" | tr -d '[:space:]')

        [ -n "$item" ] || continue

        case "$item" in
            *-*)
                start=${item%-*}
                end=${item#*-}
                port=$start
                while [ "$port" -le "$end" ]; do
                    printf '%s\n' "$port"
                    port=$((port + 1))
                done
                ;;
            *)
                printf '%s\n' "$item"
                ;;
        esac
    done
}

apply_accept_rules() {
    proto="$1"
    spec="$2"

    expand_ports "$spec" | while read -r port; do
        [ -n "$port" ] || continue
        iptables -A INPUT -p "$proto" --dport "$port" -j ACCEPT
    done
}

apply_drop_rules() {
    proto="$1"
    spec="$2"

    expand_ports "$spec" | while read -r port; do
        [ -n "$port" ] || continue
        iptables -A INPUT -p "$proto" --dport "$port" -j DROP
    done
}

apply_reject_rules() {
    proto="$1"
    spec="$2"

    expand_ports "$spec" | while read -r port; do
        [ -n "$port" ] || continue
        iptables -A INPUT -p "$proto" --dport "$port" -j REJECT --reject-with icmp-host-prohibited
    done
}

iptables -F INPUT
iptables -P INPUT ACCEPT

# Open ports must win if a profile accidentally overlaps with DROP/REJECT.
apply_accept_rules tcp "${TCP_OPEN:-}"
apply_accept_rules udp "${UDP_OPEN:-}"

apply_drop_rules tcp "${TCP_DROP:-}"
apply_reject_rules tcp "${TCP_REJECT:-}"

apply_drop_rules udp "${UDP_DROP:-}"
apply_reject_rules udp "${UDP_REJECT:-}"

echo "[target] profile:             ${LAB_PROFILE:-default}"
echo "[target] static IP:           172.28.0.10"
echo "[target] TCP open:            ${TCP_OPEN:-}"
echo "[target] UDP open:            ${UDP_OPEN:-}"
echo "[target] TCP DROP filtered:   ${TCP_DROP:-}"
echo "[target] TCP REJECT filtered: ${TCP_REJECT:-}"
echo "[target] UDP DROP filtered:   ${UDP_DROP:-}"
echo "[target] UDP REJECT filtered: ${UDP_REJECT:-}"

exec python3 /service_lab.py
EOF

cat > ft_nmap_lab/target/service_lab.py <<'EOF'
#!/usr/bin/env python3
import os
import signal
import socket
import sys
import threading
import time
from typing import List, Set

SERVICE_NAMES = {
    1: "tcpmux",
    7: "echo",
    9: "discard",
    13: "daytime",
    17: "qotd",
    19: "chargen",
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    37: "time",
    42: "nameserver",
    49: "tacacs",
    53: "domain",
    67: "dhcp-server",
    68: "dhcp-client",
    69: "tftp",
    80: "http",
    81: "hosts2-ns",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    113: "ident",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    450: "checkpoint",
    500: "isakmp",
    514: "syslog",
    515: "printer",
    520: "route",
    587: "submission",
    631: "ipp",
    993: "imaps",
    1021: "exp1",
}

stop = threading.Event()

def parse_ports(value: str) -> List[int]:
    ports: Set[int] = set()

    for raw_item in value.split(","):
        item = raw_item.strip()
        if not item:
            continue

        if "-" in item:
            start_raw, end_raw = item.split("-", 1)
            start = int(start_raw)
            end = int(end_raw)
            if start > end:
                start, end = end, start
            for port in range(start, end + 1):
                if 1 <= port <= 65535:
                    ports.add(port)
        else:
            port = int(item)
            if 1 <= port <= 65535:
                ports.add(port)

    return sorted(ports)

def service_label(proto: str, port: int) -> str:
    name = SERVICE_NAMES.get(port, "unknown")
    return f"fake {name} {proto}/{port}"

def tcp_server(port: int) -> None:
    label = service_label("tcp", port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(128)
        sock.settimeout(1.0)
    except OSError as exc:
        print(f"[tcp] failed on {port}: {exc}", flush=True)
        sock.close()
        return

    print(f"[tcp] listening on {port} ({label})", flush=True)

    while not stop.is_set():
        try:
            conn, _addr = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        with conn:
            try:
                conn.sendall(f"{label}\r\n".encode())
                conn.settimeout(0.2)
                try:
                    _data = conn.recv(512)
                    conn.sendall(b"ok\r\n")
                except socket.timeout:
                    pass
            except OSError:
                pass

    sock.close()

def udp_server(port: int) -> None:
    label = service_label("udp", port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.bind(("0.0.0.0", port))
        sock.settimeout(1.0)
    except OSError as exc:
        print(f"[udp] failed on {port}: {exc}", flush=True)
        sock.close()
        return

    print(f"[udp] listening on {port} ({label})", flush=True)

    while not stop.is_set():
        try:
            _data, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break

        try:
            sock.sendto(f"{label}\n".encode(), addr)
        except OSError:
            pass

    sock.close()

def shutdown(_signum, _frame) -> None:
    stop.set()

def main() -> int:
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    profile = os.environ.get("LAB_PROFILE", "default")
    tcp_ports = parse_ports(os.environ.get("TCP_OPEN", ""))
    udp_ports = parse_ports(os.environ.get("UDP_OPEN", ""))

    print(f"[target] service profile: {profile}", flush=True)
    print(f"[target] TCP services: {len(tcp_ports)}", flush=True)
    print(f"[target] UDP services: {len(udp_ports)}", flush=True)

    for port in tcp_ports:
        threading.Thread(target=tcp_server, args=(port,), daemon=True).start()

    for port in udp_ports:
        threading.Thread(target=udp_server, args=(port,), daemon=True).start()

    while not stop.is_set():
        time.sleep(0.5)

    return 0

if __name__ == "__main__":
    sys.exit(main())
EOF

chmod +x ft_nmap_lab/target/entrypoint.sh
chmod +x ft_nmap_lab/target/service_lab.py

python3 <<'PY'
from pathlib import Path
import re

path = Path("Makefile")
text = path.read_text()

docker_title = """# **************************************************************************** #
#                                  DOCKER LAB                                  #
# **************************************************************************** #"""

dependencies_title = """# **************************************************************************** #
#                                DEPENDENCIES                                  #
# **************************************************************************** #"""

lab_rules = """# **************************************************************************** #
#                                  DOCKER LAB                                  #
# **************************************************************************** #

LAB_DIR := ft_nmap_lab

lab: lab-up

lab-up:
\t$(MAKE) -C $(LAB_DIR) up

lab-down:
\t$(MAKE) -C $(LAB_DIR) down

lab-re:
\t$(MAKE) -C $(LAB_DIR) re

lab-clean:
\t$(MAKE) -C $(LAB_DIR) clean

lab-logs:
\t$(MAKE) -C $(LAB_DIR) logs

lab-ps:
\t$(MAKE) -C $(LAB_DIR) ps

lab-shell:
\t$(MAKE) -C $(LAB_DIR) shell

lab-profiles:
\t$(MAKE) -C $(LAB_DIR) profiles

lab-default:
\t$(MAKE) -C $(LAB_DIR) up PROFILE=default

lab-tcp-many:
\t$(MAKE) -C $(LAB_DIR) up PROFILE=tcp-many-open

lab-udp-many:
\t$(MAKE) -C $(LAB_DIR) up PROFILE=udp-many-open

lab-mixed:
\t$(MAKE) -C $(LAB_DIR) up PROFILE=mixed

lab-mostly-closed:
\t$(MAKE) -C $(LAB_DIR) up PROFILE=mostly-closed

lab-filtered-heavy:
\t$(MAKE) -C $(LAB_DIR) up PROFILE=filtered-heavy

lab-profile-%:
\t$(MAKE) -C $(LAB_DIR) up PROFILE=$*
"""

if docker_title in text and dependencies_title in text:
    before, rest = text.split(docker_title, 1)
    _old_lab, after = rest.split(dependencies_title, 1)
    text = before.rstrip() + "\n\n" + dependencies_title + after

if dependencies_title not in text:
    raise SystemExit("Could not find DEPENDENCIES section in root Makefile")

text = text.replace(dependencies_title, lab_rules + "\n\n" + dependencies_title, 1)

phony_targets = [
    "lab",
    "lab-up",
    "lab-down",
    "lab-re",
    "lab-clean",
    "lab-logs",
    "lab-ps",
    "lab-shell",
    "lab-profiles",
    "lab-default",
    "lab-tcp-many",
    "lab-udp-many",
    "lab-mixed",
    "lab-mostly-closed",
    "lab-filtered-heavy",
]

match = re.search(r"^\.PHONY:\s*(.*)$", text, flags=re.MULTILINE)
if match:
    current = match.group(1).split()
    for target in phony_targets:
        if target not in current:
            current.append(target)
    text = text[:match.start()] + ".PHONY: " + " ".join(current) + text[match.end():]
else:
    text = text.rstrip() + "\n\n.PHONY: " + " ".join(phony_targets) + "\n"

path.write_text(text)
PY

printf '%s\n' '[ok] Docker lab profiles added'
printf '%s\n' '[ok] root Makefile lab aliases added'
printf '%s\n' '[ok] lab README updated'