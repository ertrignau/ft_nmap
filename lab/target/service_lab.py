#!/usr/bin/env python3

import os
import selectors
import signal
import socket
import sys


selector = selectors.DefaultSelector()
running = True


def parse_ports(spec):
    ports = set()

    if not spec:
        return []

    for raw_item in spec.split(","):
        item = raw_item.strip()

        if not item:
            continue

        if "-" in item:
            if item.count("-") != 1:
                raise ValueError(
                    "invalid range: " + item
                )

            start_raw, end_raw = item.split("-", 1)

            if (
                not start_raw.isdigit()
                or not end_raw.isdigit()
            ):
                raise ValueError(
                    "invalid range: " + item
                )

            start = int(start_raw)
            end = int(end_raw)

            if start > end:
                raise ValueError(
                    "reversed range: " + item
                )

            if start < 1 or end > 65535:
                raise ValueError(
                    "port outside 1-65535: " + item
                )

            ports.update(
                range(start, end + 1)
            )
            continue

        if not item.isdigit():
            raise ValueError(
                "invalid port: " + item
            )

        port = int(item)

        if port < 1 or port > 65535:
            raise ValueError(
                "port outside 1-65535: " + item
            )

        ports.add(port)

    return sorted(ports)


def make_tcp_listener(
    family,
    port,
):
    sock = socket.socket(
        family,
        socket.SOCK_STREAM,
    )

    sock.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1,
    )

    if family == socket.AF_INET6:
        sock.setsockopt(
            socket.IPPROTO_IPV6,
            socket.IPV6_V6ONLY,
            1,
        )

    sock.setblocking(False)

    if family == socket.AF_INET:
        sock.bind(
            ("0.0.0.0", port)
        )
    else:
        sock.bind(
            ("::", port)
        )

    sock.listen(128)

    return sock


def make_udp_listener(
    family,
    port,
):
    sock = socket.socket(
        family,
        socket.SOCK_DGRAM,
    )

    if family == socket.AF_INET6:
        sock.setsockopt(
            socket.IPPROTO_IPV6,
            socket.IPV6_V6ONLY,
            1,
        )

    sock.setblocking(False)

    if family == socket.AF_INET:
        sock.bind(
            ("0.0.0.0", port)
        )
    else:
        sock.bind(
            ("::", port)
        )

    return sock


def register_tcp(
    family,
    family_name,
    port,
):
    sock = make_tcp_listener(
        family,
        port,
    )

    selector.register(
        sock,
        selectors.EVENT_READ,
        (
            family_name,
            "tcp",
            port,
        ),
    )


def register_udp(
    family,
    family_name,
    port,
):
    sock = make_udp_listener(
        family,
        port,
    )

    selector.register(
        sock,
        selectors.EVENT_READ,
        (
            family_name,
            "udp",
            port,
        ),
    )


def handle_tcp(sock):
    while True:
        try:
            conn, _addr = sock.accept()
        except BlockingIOError:
            return
        except OSError:
            return

        try:
            conn.close()
        except OSError:
            pass


def handle_udp(
    sock,
    family_name,
    port,
):
    payload = (
        "ft_nmap lab %s udp/%d\n"
        % (family_name, port)
    ).encode()

    while True:
        try:
            _data, addr = sock.recvfrom(65535)
        except BlockingIOError:
            return
        except OSError:
            return

        try:
            sock.sendto(
                payload,
                addr,
            )
        except OSError:
            pass


def stop_handler(
    _signum,
    _frame,
):
    global running
    running = False


def close_all():
    for key in list(
        selector.get_map().values()
    ):
        sock = key.fileobj

        try:
            selector.unregister(sock)
        except Exception:
            pass

        try:
            sock.close()
        except OSError:
            pass

    selector.close()


def load_ports(name):
    return parse_ports(
        os.environ.get(name, "")
    )


def register_family(
    family,
    family_name,
    tcp_ports,
    udp_ports,
):
    for port in tcp_ports:
        register_tcp(
            family,
            family_name,
            port,
        )

    for port in udp_ports:
        register_udp(
            family,
            family_name,
            port,
        )


def main():
    signal.signal(
        signal.SIGTERM,
        stop_handler,
    )

    signal.signal(
        signal.SIGINT,
        stop_handler,
    )

    target_name = os.environ.get(
        "TARGET_NAME",
        "unknown",
    )

    ipv4 = os.environ.get(
        "TARGET_IPV4",
        "",
    )

    ipv6 = os.environ.get(
        "TARGET_IPV6",
        "",
    )

    ipv6_profile = (
        os.environ.get(
            "IPV6_PROFILE",
            "0",
        )
        == "1"
    )

    try:
        tcp4 = load_ports(
            "TCP_OPEN"
        )

        udp4 = load_ports(
            "UDP_OPEN"
        )

        if ipv6_profile:
            tcp6 = load_ports(
                "V6_TCP_OPEN"
            )

            udp6 = load_ports(
                "V6_UDP_OPEN"
            )
        else:
            tcp6 = []
            udp6 = []

    except ValueError as exc:
        print(
            "[services] invalid configuration: %s"
            % exc,
            file=sys.stderr,
            flush=True,
        )

        return 1

    print(
        "[services] target: %s"
        % target_name,
        flush=True,
    )

    print(
        "[services] IPv4: %s"
        % ipv4,
        flush=True,
    )

    if ipv6_profile:
        print(
            "[services] IPv6: %s"
            % ipv6,
            flush=True,
        )

    print(
        "[services] IPv4 TCP OPEN sockets: %d"
        % len(tcp4),
        flush=True,
    )

    print(
        "[services] IPv4 UDP OPEN sockets: %d"
        % len(udp4),
        flush=True,
    )

    print(
        "[services] IPv6 TCP OPEN sockets: %d"
        % len(tcp6),
        flush=True,
    )

    print(
        "[services] IPv6 UDP OPEN sockets: %d"
        % len(udp6),
        flush=True,
    )

    try:
        register_family(
            socket.AF_INET,
            "IPv4",
            tcp4,
            udp4,
        )

        if ipv6_profile:
            register_family(
                socket.AF_INET6,
                "IPv6",
                tcp6,
                udp6,
            )

    except OSError as exc:
        print(
            "[services] startup failed: %s"
            % exc,
            file=sys.stderr,
            flush=True,
        )

        close_all()
        return 1

    print(
        "[services] ready",
        flush=True,
    )

    try:
        while running:
            try:
                events = selector.select(
                    timeout=0.5
                )
            except InterruptedError:
                continue

            for key, _mask in events:
                sock = key.fileobj

                (
                    family_name,
                    proto,
                    port,
                ) = key.data

                if proto == "tcp":
                    handle_tcp(sock)
                else:
                    handle_udp(
                        sock,
                        family_name,
                        port,
                    )

    finally:
        close_all()

    print(
        "[services] stopped",
        flush=True,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
