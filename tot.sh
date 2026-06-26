#!/usr/bin/env bash
set -eu

LAB_DIR="${1:-ft_nmap_lab}"

mkdir -p "$LAB_DIR/target"

cat > "$LAB_DIR/docker-compose.yml" <<'EOF'
services:
  target:
    build: ./target
    container_name: ft_nmap_target
    cap_add:
      - NET_ADMIN
      - NET_RAW
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

cat > "$LAB_DIR/target/Dockerfile" <<'EOF'
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iptables iproute2 python3 procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY service_lab.py /service_lab.py

RUN chmod +x /entrypoint.sh /service_lab.py

ENTRYPOINT ["/entrypoint.sh"]
EOF

cat > "$LAB_DIR/target/entrypoint.sh" <<'EOF'
#!/bin/sh
set -eu

iptables -F INPUT
iptables -P INPUT ACCEPT

for p in 30 81 88 111 135 139 515 587 631 1021; do
    iptables -A INPUT -p tcp --dport "$p" -j DROP
done

for p in 37 42 113 119 389; do
    iptables -A INPUT -p tcp --dport "$p" -j REJECT --reject-with icmp-host-prohibited
done

for p in 69 111 520 631 1021; do
    iptables -A INPUT -p udp --dport "$p" -j DROP
done

for p in 137 138 162 389 450; do
    iptables -A INPUT -p udp --dport "$p" -j REJECT --reject-with icmp-host-prohibited
done

echo "[target] TCP open ports:      21 22 25 53 80 110 143 443 445 993"
echo "[target] UDP open ports:      53 123 161 500 514"
echo "[target] TCP DROP filtered:   30 81 88 111 135 139 515 587 631 1021"
echo "[target] TCP REJECT filtered: 37 42 113 119 389"
echo "[target] UDP DROP filtered:   69 111 520 631 1021"
echo "[target] UDP REJECT filtered: 137 138 162 389 450"
echo "[target] Static IP:           172.28.0.10"

exec python3 /service_lab.py
EOF

cat > "$LAB_DIR/target/service_lab.py" <<'EOF'
#!/usr/bin/env python3
import socket
import threading
import time
import signal
import sys

TCP_OPEN = {
    21: "fake ftp",
    22: "fake ssh",
    25: "fake smtp",
    53: "fake domain",
    80: "fake http",
    110: "fake pop3",
    143: "fake imap",
    443: "fake https",
    445: "fake microsoft-ds",
    993: "fake imaps",
}

UDP_OPEN = {
    53: "fake domain",
    123: "fake ntp",
    161: "fake snmp",
    500: "fake isakmp",
    514: "fake syslog",
}

stop = threading.Event()

def tcp_server(port: int, label: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(64)
    sock.settimeout(1.0)
    print(f"[tcp] listening on {port} ({label})", flush=True)

    while not stop.is_set():
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        with conn:
            try:
                conn.sendall(f"{label} on tcp/{port}\r\n".encode())
                conn.settimeout(0.2)
                try:
                    data = conn.recv(512)
                    if data:
                        conn.sendall(b"ok\r\n")
                except socket.timeout:
                    pass
            except OSError:
                pass

    sock.close()

def udp_server(port: int, label: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(1.0)
    print(f"[udp] listening on {port} ({label})", flush=True)

    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break

        try:
            sock.sendto(f"{label} on udp/{port}\n".encode(), addr)
        except OSError:
            pass

    sock.close()

def shutdown(signum, frame) -> None:
    stop.set()

def main() -> int:
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    for port, label in TCP_OPEN.items():
        threading.Thread(target=tcp_server, args=(port, label), daemon=True).start()

    for port, label in UDP_OPEN.items():
        threading.Thread(target=udp_server, args=(port, label), daemon=True).start()

    while not stop.is_set():
        time.sleep(0.5)

    return 0

if __name__ == "__main__":
    sys.exit(main())
EOF

cat > "$LAB_DIR/targets.txt" <<'EOF'
172.28.0.10
ft_nmap_target
EOF

cat > "$LAB_DIR/ports-interesting.txt" <<'EOF'
1,21,22,25,30,37,42,53,69,80,81,88,110,111,113,119,123,135,137-139,143,161,162,389,443,445,450,500,514,515,520,587,631,993,1021
EOF

cat > "$LAB_DIR/README.md" <<'EOF'
# ft_nmap target-only Docker lab

This lab starts only one Docker container: a controlled target to scan.

Your ft_nmap is launched from the host VM/Linux machine, not from Docker.

Target IP:

```txt
172.28.0.10