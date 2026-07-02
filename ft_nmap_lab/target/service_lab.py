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
