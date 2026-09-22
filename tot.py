#!/usr/bin/env python3

from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent


ROOT = Path.cwd()
LAB = ROOT / "lab"

NET_A_V4 = "172.28.0.0/24"
NET_A_V6 = "fd42:28::/64"

NET_B_V4 = "172.29.0.0/24"
NET_B_V6 = "fd42:29::/64"

FIRST_TARGET = 10
LAST_TARGET = 29

STATES = ("O", "C", "D", "R")


# ============================================================================
# Model
# ============================================================================

@dataclass
class Target:
    number: int
    name: str
    start: int
    end: int
    tcp: dict[int, str]
    udp: dict[int, str]
    rate_limit: str = "none"
    rate_ports: str = ""
    rate: str = "5/second"
    burst: int = 5

    @property
    def network(self) -> str:
        return "net-a" if self.number < 20 else "net-b"

    @property
    def ipv4(self) -> str:
        if self.number < 20:
            return f"172.28.0.{self.number}"

        return f"172.29.0.{self.number}"

    @property
    def ipv6(self) -> str:
        if self.number == 10:
            return "fd42:28::10"

        if self.number == 20:
            return "fd42:29::20"

        return ""

    @property
    def has_ipv6_profile(self) -> bool:
        return self.number in (10, 20)


def new_map(start: int, end: int, default: str = "C") -> dict[int, str]:
    return {
        port: default
        for port in range(start, end + 1)
    }


def set_range(
    states: dict[int, str],
    start: int,
    end: int,
    state: str,
) -> None:
    if state not in STATES:
        raise ValueError(f"invalid state: {state}")

    for port in range(start, end + 1):
        if port not in states:
            raise ValueError(
                f"port {port} outside controlled range"
            )

        states[port] = state


def set_ports(
    states: dict[int, str],
    ports,
    state: str,
) -> None:
    if state not in STATES:
        raise ValueError(f"invalid state: {state}")

    for port in ports:
        if port not in states:
            raise ValueError(
                f"port {port} outside controlled range"
            )

        states[port] = state


def set_pattern(
    states: dict[int, str],
    start: int,
    pattern: str,
) -> None:
    for offset, state in enumerate(pattern):
        if state not in STATES:
            raise ValueError(
                f"invalid state in pattern: {state}"
            )

        states[start + offset] = state


# ============================================================================
# Common IPv4 baseline: ports 30-39
# ============================================================================

BASELINE_TCP = {
    30: "O",
    31: "C",
    32: "D",
    33: "C",
    34: "O",
    35: "C",
    36: "R",
    37: "C",
    38: "O",
    39: "D",
}

BASELINE_UDP = {
    30: "C",
    31: "O",
    32: "C",
    33: "D",
    34: "O",
    35: "C",
    36: "C",
    37: "R",
    38: "D",
    39: "O",
}


def apply_baseline(
    tcp: dict[int, str],
    udp: dict[int, str],
) -> None:
    for port, state in BASELINE_TCP.items():
        tcp[port] = state

    for port, state in BASELINE_UDP.items():
        udp[port] = state


# ============================================================================
# IPv6 profile
#
# Only target-10 and target-20 officially expose this profile.
#
# 1-1024 is deterministic.
# Everything not explicitly changed remains CLOSED.
# ============================================================================

def build_ipv6_profile():
    tcp = new_map(1, 1024)
    udp = new_map(1, 1024)

    apply_baseline(tcp, udp)

    # Extra TCP coverage.
    set_ports(tcp, [80, 443], "O")
    set_ports(tcp, [81, 444], "D")
    set_ports(tcp, [82, 445], "R")

    # Extra UDP coverage.
    set_ports(udp, [53, 123], "O")
    set_ports(udp, [54, 124], "D")
    set_ports(udp, [55, 125], "R")

    return tcp, udp


IPV6_TCP, IPV6_UDP = build_ipv6_profile()


# ============================================================================
# 172.28.0.10 - full/default IPv4 target
# ============================================================================

def build_full_target() -> Target:
    tcp = new_map(1, 1024)
    udp = new_map(1, 1024)

    # TCP ------------------------------------------------------------

    set_range(tcp, 1, 25, "O")
    set_range(tcp, 26, 29, "C")

    set_range(tcp, 40, 49, "O")
    set_range(tcp, 50, 52, "C")
    set_ports(tcp, [53], "O")
    set_range(tcp, 54, 59, "C")

    set_range(tcp, 60, 69, "D")
    set_range(tcp, 70, 79, "R")

    set_range(tcp, 80, 99, "O")
    set_range(tcp, 100, 109, "D")
    set_ports(tcp, [110], "O")
    set_range(tcp, 111, 142, "D")
    set_ports(tcp, [143], "O")
    set_range(tcp, 144, 299, "D")

    set_range(tcp, 300, 399, "R")
    set_range(tcp, 400, 442, "C")
    set_range(tcp, 443, 445, "O")
    set_range(tcp, 446, 499, "C")

    set_range(tcp, 500, 649, "D")
    set_range(tcp, 650, 749, "R")
    set_range(tcp, 750, 799, "C")
    set_range(tcp, 800, 839, "O")
    set_range(tcp, 840, 899, "C")

    set_range(tcp, 900, 949, "D")
    set_range(tcp, 950, 989, "R")
    set_range(tcp, 990, 999, "O")
    set_range(tcp, 1000, 1024, "R")

    # UDP ------------------------------------------------------------

    set_range(udp, 1, 20, "O")
    set_range(udp, 21, 29, "C")

    set_range(udp, 40, 49, "C")
    set_range(udp, 50, 59, "O")
    set_range(udp, 60, 69, "D")
    set_range(udp, 70, 79, "R")

    set_range(udp, 80, 122, "D")
    set_ports(udp, [123], "O")
    set_range(udp, 124, 160, "D")
    set_ports(udp, [161], "O")
    set_range(udp, 162, 199, "D")

    set_range(udp, 200, 299, "R")
    set_range(udp, 300, 399, "C")
    set_range(udp, 400, 419, "O")
    set_range(udp, 420, 499, "D")

    set_ports(udp, [500], "O")
    set_range(udp, 501, 513, "D")
    set_ports(udp, [514], "O")
    set_range(udp, 515, 549, "D")

    set_range(udp, 550, 649, "R")
    set_range(udp, 650, 749, "C")
    set_range(udp, 750, 769, "O")
    set_range(udp, 770, 849, "C")
    set_range(udp, 850, 949, "D")
    set_range(udp, 950, 1024, "R")

    apply_baseline(tcp, udp)

    return Target(
        number=10,
        name="full-default",
        start=1,
        end=1024,
        tcp=tcp,
        udp=udp,
    )


# ============================================================================
# Fleet
# ============================================================================

def new_fleet_target(
    number: int,
    name: str,
) -> Target:
    tcp = new_map(30, 79)
    udp = new_map(30, 79)

    apply_baseline(tcp, udp)

    return Target(
        number=number,
        name=name,
        start=30,
        end=79,
        tcp=tcp,
        udp=udp,
    )


def build_fleet_targets() -> list[Target]:
    targets = []

    # .11 balanced ---------------------------------------------------

    t = new_fleet_target(11, "balanced")

    set_pattern(t.tcp, 40, "OOOCCCDDRR")
    set_range(t.tcp, 50, 59, "C")
    set_range(t.tcp, 60, 69, "D")
    set_range(t.tcp, 70, 79, "R")

    set_pattern(t.udp, 40, "CCCOOORRDD")
    set_range(t.udp, 50, 59, "O")
    set_range(t.udp, 60, 69, "R")
    set_range(t.udp, 70, 79, "D")

    targets.append(t)

    # .12 TCP open-heavy ---------------------------------------------

    t = new_fleet_target(12, "tcp-open-heavy")

    set_pattern(t.tcp, 40, "OOOOOOOOOC")
    set_range(t.tcp, 50, 69, "O")
    set_range(t.tcp, 70, 79, "C")

    set_pattern(t.udp, 40, "CCCOOODDRR")
    set_range(t.udp, 50, 59, "O")
    set_range(t.udp, 60, 69, "D")
    set_range(t.udp, 70, 79, "R")

    targets.append(t)

    # .13 TCP closed-heavy -------------------------------------------

    t = new_fleet_target(13, "tcp-closed-heavy")

    set_pattern(t.tcp, 40, "CCCCCCCCCO")
    set_range(t.tcp, 50, 69, "C")
    set_range(t.tcp, 70, 79, "O")

    set_pattern(t.udp, 40, "OOOCCCDDRR")
    set_range(t.udp, 50, 59, "C")
    set_range(t.udp, 60, 69, "D")
    set_range(t.udp, 70, 79, "R")

    targets.append(t)

    # .14 TCP filtered-heavy -----------------------------------------

    t = new_fleet_target(14, "tcp-filtered-heavy")

    set_pattern(t.tcp, 40, "DDDDDRRRRR")
    set_range(t.tcp, 50, 69, "D")
    set_range(t.tcp, 70, 79, "R")

    set_pattern(t.udp, 40, "CCCOOODDRR")
    set_range(t.udp, 50, 59, "O")
    set_range(t.udp, 60, 69, "D")
    set_range(t.udp, 70, 79, "R")

    targets.append(t)

    # .15 UDP open-heavy ---------------------------------------------

    t = new_fleet_target(15, "udp-open-heavy")

    set_pattern(t.tcp, 40, "OOOCCCDDRR")
    set_range(t.tcp, 50, 59, "C")
    set_range(t.tcp, 60, 69, "D")
    set_range(t.tcp, 70, 79, "R")

    set_pattern(t.udp, 40, "OOOOOOOOOC")
    set_range(t.udp, 50, 69, "O")
    set_range(t.udp, 70, 79, "C")

    targets.append(t)

    # .16 UDP closed-heavy -------------------------------------------

    t = new_fleet_target(16, "udp-closed-heavy")

    set_pattern(t.tcp, 40, "OOOCCCDDRR")
    set_range(t.tcp, 50, 59, "C")
    set_range(t.tcp, 60, 69, "D")
    set_range(t.tcp, 70, 79, "R")

    set_pattern(t.udp, 40, "CCCCCCCCCO")
    set_range(t.udp, 50, 69, "C")
    set_range(t.udp, 70, 79, "O")

    targets.append(t)

    # .17 UDP filtered-heavy -----------------------------------------

    t = new_fleet_target(17, "udp-filtered-heavy")

    set_pattern(t.tcp, 40, "OOOCCCDDRR")
    set_range(t.tcp, 50, 59, "C")
    set_range(t.tcp, 60, 69, "D")
    set_range(t.tcp, 70, 79, "R")

    set_pattern(t.udp, 40, "DDDDDRRRRR")
    set_range(t.udp, 50, 69, "D")
    set_range(t.udp, 70, 79, "R")

    targets.append(t)

    # .18 open-heavy -------------------------------------------------

    t = new_fleet_target(18, "open-heavy")

    for states in (t.tcp, t.udp):
        set_pattern(states, 40, "OOOOOOOOOC")
        set_range(states, 50, 69, "O")
        set_range(states, 70, 79, "C")

    targets.append(t)

    # .19 closed-heavy -----------------------------------------------

    t = new_fleet_target(19, "closed-heavy")

    for states in (t.tcp, t.udp):
        set_pattern(states, 40, "CCCCCCCCCO")
        set_range(states, 50, 69, "C")
        set_range(states, 70, 79, "O")

    targets.append(t)

    # .20 filtered-heavy ---------------------------------------------

    t = new_fleet_target(20, "filtered-heavy")

    for states in (t.tcp, t.udp):
        set_pattern(states, 40, "DDDDDRRRRR")
        set_range(states, 50, 69, "D")
        set_range(states, 70, 79, "R")

    targets.append(t)

    # .21 TCP open / UDP closed -------------------------------------

    t = new_fleet_target(21, "tcp-open-udp-closed")

    set_pattern(t.tcp, 40, "OOOOOOOOOC")
    set_range(t.tcp, 50, 69, "O")
    set_range(t.tcp, 70, 79, "C")

    set_pattern(t.udp, 40, "CCCCCCCCCO")
    set_range(t.udp, 50, 69, "C")
    set_range(t.udp, 70, 79, "O")

    targets.append(t)

    # .22 TCP closed / UDP open -------------------------------------

    t = new_fleet_target(22, "tcp-closed-udp-open")

    set_pattern(t.tcp, 40, "CCCCCCCCCO")
    set_range(t.tcp, 50, 69, "C")
    set_range(t.tcp, 70, 79, "O")

    set_pattern(t.udp, 40, "OOOOOOOOOC")
    set_range(t.udp, 50, 69, "O")
    set_range(t.udp, 70, 79, "C")

    targets.append(t)

    # .23 TCP open / UDP filtered -----------------------------------

    t = new_fleet_target(23, "tcp-open-udp-filtered")

    set_pattern(t.tcp, 40, "OOOOOOOOOC")
    set_range(t.tcp, 50, 69, "O")
    set_range(t.tcp, 70, 79, "C")

    set_pattern(t.udp, 40, "DDDDDRRRRR")
    set_range(t.udp, 50, 69, "D")
    set_range(t.udp, 70, 79, "R")

    targets.append(t)

    # .24 TCP filtered / UDP open -----------------------------------

    t = new_fleet_target(24, "tcp-filtered-udp-open")

    set_pattern(t.tcp, 40, "DDDDDRRRRR")
    set_range(t.tcp, 50, 69, "D")
    set_range(t.tcp, 70, 79, "R")

    set_pattern(t.udp, 40, "OOOOOOOOOC")
    set_range(t.udp, 50, 69, "O")
    set_range(t.udp, 70, 79, "C")

    targets.append(t)

    # .25 alternating ------------------------------------------------

    t = new_fleet_target(25, "alternating")

    tcp_cycle = ("O", "C", "D", "R")
    udp_cycle = ("C", "D", "R", "O")

    for port in range(40, 80):
        t.tcp[port] = tcp_cycle[(port - 40) % 4]
        t.udp[port] = udp_cycle[(port - 40) % 4]

    targets.append(t)

    # .26 reject-heavy -----------------------------------------------

    t = new_fleet_target(26, "reject-heavy")

    for states in (t.tcp, t.udp):
        set_pattern(states, 40, "RRRRRRRRRC")
        set_range(states, 50, 69, "R")
        set_range(states, 70, 79, "C")

    targets.append(t)

    # .27 mixed ------------------------------------------------------

    t = new_fleet_target(27, "mixed")

    set_pattern(t.tcp, 40, "OCDRODCCOR")
    set_range(t.tcp, 50, 54, "O")
    set_range(t.tcp, 55, 59, "D")
    set_range(t.tcp, 60, 64, "C")
    set_range(t.tcp, 65, 69, "R")
    set_range(t.tcp, 70, 74, "O")
    set_range(t.tcp, 75, 79, "C")

    set_pattern(t.udp, 40, "RDOCCDOROC")
    set_range(t.udp, 50, 54, "R")
    set_range(t.udp, 55, 59, "O")
    set_range(t.udp, 60, 64, "D")
    set_range(t.udp, 65, 69, "C")
    set_range(t.udp, 70, 74, "O")
    set_range(t.udp, 75, 79, "R")

    targets.append(t)

    # .28 controlled UDP/ICMP rate-limit ----------------------------

    t = new_fleet_target(28, "icmp-rate-limit")

    set_range(t.tcp, 40, 79, "C")
    set_range(t.udp, 40, 79, "C")

    t.rate_limit = "udp-icmp"
    t.rate_ports = "40-79"

    targets.append(t)

    # .29 controlled TCP RST rate-limit ------------------------------

    t = new_fleet_target(29, "rst-rate-limit")

    set_range(t.tcp, 40, 79, "C")
    set_range(t.udp, 40, 79, "C")

    t.rate_limit = "tcp-rst"
    t.rate_ports = "40-79"

    targets.append(t)

    return targets


# ============================================================================
# Validation
# ============================================================================

def validate_state_map(
    name: str,
    states: dict[int, str],
    start: int,
    end: int,
) -> None:
    expected = set(range(start, end + 1))

    if set(states) != expected:
        raise ValueError(
            f"{name}: incomplete range {start}-{end}"
        )

    for port, state in states.items():
        if state not in STATES:
            raise ValueError(
                f"{name}: invalid state {state} on port {port}"
            )


def validate_targets(
    targets: list[Target],
) -> None:
    numbers = [
        target.number
        for target in targets
    ]

    expected_numbers = list(
        range(FIRST_TARGET, LAST_TARGET + 1)
    )

    if numbers != expected_numbers:
        raise ValueError(
            f"expected {expected_numbers}, got {numbers}"
        )

    for target in targets:
        validate_state_map(
            f"{target.ipv4} TCP",
            target.tcp,
            target.start,
            target.end,
        )

        validate_state_map(
            f"{target.ipv4} UDP",
            target.udp,
            target.start,
            target.end,
        )

        for port in range(30, 40):
            if target.tcp[port] != BASELINE_TCP[port]:
                raise ValueError(
                    f"{target.ipv4}: TCP baseline differs "
                    f"on port {port}"
                )

            if target.udp[port] != BASELINE_UDP[port]:
                raise ValueError(
                    f"{target.ipv4}: UDP baseline differs "
                    f"on port {port}"
                )

    validate_state_map(
        "IPv6 TCP",
        IPV6_TCP,
        1,
        1024,
    )

    validate_state_map(
        "IPv6 UDP",
        IPV6_UDP,
        1,
        1024,
    )

    for port in range(30, 40):
        if IPV6_TCP[port] != BASELINE_TCP[port]:
            raise ValueError(
                f"IPv6 TCP baseline differs on {port}"
            )

        if IPV6_UDP[port] != BASELINE_UDP[port]:
            raise ValueError(
                f"IPv6 UDP baseline differs on {port}"
            )


# ============================================================================
# Port formatting
# ============================================================================

def compress_ports(ports) -> str:
    ports = sorted(set(ports))

    if not ports:
        return ""

    result = []

    start = ports[0]
    previous = ports[0]

    for port in ports[1:]:
        if port == previous + 1:
            previous = port
            continue

        if start == previous:
            result.append(str(start))
        else:
            result.append(f"{start}-{previous}")

        start = port
        previous = port

    if start == previous:
        result.append(str(start))
    else:
        result.append(f"{start}-{previous}")

    return ",".join(result)


def state_spec(
    states: dict[int, str],
    state: str,
) -> str:
    return compress_ports(
        port
        for port, current in states.items()
        if current == state
    )


def complete_state_spec(
    target: Target,
    states: dict[int, str],
    state: str,
) -> str:
    ports = [
        port
        for port, current in states.items()
        if current == state
    ]

    if state == "C":
        ports.extend(
            range(1, target.start)
        )

        ports.extend(
            range(target.end + 1, 65536)
        )

    return compress_ports(ports)


def full_ipv6_state_spec(
    states: dict[int, str],
    state: str,
) -> str:
    ports = [
        port
        for port, current in states.items()
        if current == state
    ]

    if state == "C":
        ports.extend(
            range(1025, 65536)
        )

    return compress_ports(ports)


# ============================================================================
# Environment files
# ============================================================================

def render_config(
    target: Target,
) -> str:
    if target.has_ipv6_profile:
        ipv6_enabled = "1"
        ipv6_address = target.ipv6

        v6_tcp_open = full_ipv6_state_spec(
            IPV6_TCP,
            "O",
        )

        v6_tcp_closed = full_ipv6_state_spec(
            IPV6_TCP,
            "C",
        )

        v6_tcp_drop = full_ipv6_state_spec(
            IPV6_TCP,
            "D",
        )

        v6_tcp_reject = full_ipv6_state_spec(
            IPV6_TCP,
            "R",
        )

        v6_udp_open = full_ipv6_state_spec(
            IPV6_UDP,
            "O",
        )

        v6_udp_closed = full_ipv6_state_spec(
            IPV6_UDP,
            "C",
        )

        v6_udp_drop = full_ipv6_state_spec(
            IPV6_UDP,
            "D",
        )

        v6_udp_reject = full_ipv6_state_spec(
            IPV6_UDP,
            "R",
        )
    else:
        ipv6_enabled = "0"
        ipv6_address = ""

        v6_tcp_open = ""
        v6_tcp_closed = ""
        v6_tcp_drop = ""
        v6_tcp_reject = ""

        v6_udp_open = ""
        v6_udp_closed = ""
        v6_udp_drop = ""
        v6_udp_reject = ""

    return dedent(
        f"""\
        # Generated by build_lab.py

        TARGET_NAME={target.name}
        TARGET_IPV4={target.ipv4}
        TARGET_IPV6={ipv6_address}

        TCP_OPEN={complete_state_spec(target, target.tcp, "O")}
        TCP_CLOSED={complete_state_spec(target, target.tcp, "C")}
        TCP_DROP={complete_state_spec(target, target.tcp, "D")}
        TCP_REJECT={complete_state_spec(target, target.tcp, "R")}

        UDP_OPEN={complete_state_spec(target, target.udp, "O")}
        UDP_CLOSED={complete_state_spec(target, target.udp, "C")}
        UDP_DROP={complete_state_spec(target, target.udp, "D")}
        UDP_REJECT={complete_state_spec(target, target.udp, "R")}

        IPV6_PROFILE={ipv6_enabled}

        V6_TCP_OPEN={v6_tcp_open}
        V6_TCP_CLOSED={v6_tcp_closed}
        V6_TCP_DROP={v6_tcp_drop}
        V6_TCP_REJECT={v6_tcp_reject}

        V6_UDP_OPEN={v6_udp_open}
        V6_UDP_CLOSED={v6_udp_closed}
        V6_UDP_DROP={v6_udp_drop}
        V6_UDP_REJECT={v6_udp_reject}

        RATE_LIMIT={target.rate_limit}
        RATE_LIMIT_PORTS={target.rate_ports}
        RATE_LIMIT_RATE={target.rate}
        RATE_LIMIT_BURST={target.burst}
        """
    )


# ============================================================================
# service_lab.py
# ============================================================================

SERVICE_LAB = r'''#!/usr/bin/env python3

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
'''


# ============================================================================
# entrypoint.sh
# ============================================================================

ENTRYPOINT = r'''#!/bin/sh
set -eu


apply_spec()
{
    tool="$1"
    proto="$2"
    spec="$3"
    action="$4"
    reject_type="${5:-}"

    [ -n "$spec" ] || return 0

    old_ifs="$IFS"
    IFS=","
    set -- $spec
    IFS="$old_ifs"

    for item do
        item=$(
            printf '%s' "$item" |
            tr -d '[:space:]'
        )

        [ -n "$item" ] || continue

        case "$item" in
            *-*)
                start=${item%-*}
                end=${item#*-}
                dport="${start}:${end}"
                ;;
            *)
                dport="$item"
                ;;
        esac

        case "$action" in
            ACCEPT)
                "$tool" \
                    -A INPUT \
                    -p "$proto" \
                    --dport "$dport" \
                    -j ACCEPT
                ;;

            DROP)
                "$tool" \
                    -A INPUT \
                    -p "$proto" \
                    --dport "$dport" \
                    -j DROP
                ;;

            REJECT)
                "$tool" \
                    -A INPUT \
                    -p "$proto" \
                    --dport "$dport" \
                    -j REJECT \
                    --reject-with "$reject_type"
                ;;

            *)
                echo \
                    "unknown firewall action: $action" \
                    >&2

                exit 1
                ;;
        esac
    done
}


# ============================================================================
# Reset
# ============================================================================

iptables -F INPUT
iptables -P INPUT ACCEPT

ip6tables -F INPUT
ip6tables -P INPUT ACCEPT


# ============================================================================
# IPv4
#
# CLOSED needs no firewall rule.
# No listener + ACCEPT => kernel-native closed response.
# ============================================================================

apply_spec \
    iptables \
    tcp \
    "${TCP_OPEN:-}" \
    ACCEPT

apply_spec \
    iptables \
    udp \
    "${UDP_OPEN:-}" \
    ACCEPT

apply_spec \
    iptables \
    tcp \
    "${TCP_DROP:-}" \
    DROP

apply_spec \
    iptables \
    udp \
    "${UDP_DROP:-}" \
    DROP

apply_spec \
    iptables \
    tcp \
    "${TCP_REJECT:-}" \
    REJECT \
    icmp-host-prohibited

apply_spec \
    iptables \
    udp \
    "${UDP_REJECT:-}" \
    REJECT \
    icmp-host-prohibited


# ============================================================================
# IPv6
#
# Only target-10 and target-20 have an official IPv6 profile.
# CLOSED again means no listener + no filtering rule.
# ============================================================================

if [ "${IPV6_PROFILE:-0}" = "1" ]; then
    apply_spec \
        ip6tables \
        tcp \
        "${V6_TCP_OPEN:-}" \
        ACCEPT

    apply_spec \
        ip6tables \
        udp \
        "${V6_UDP_OPEN:-}" \
        ACCEPT

    apply_spec \
        ip6tables \
        tcp \
        "${V6_TCP_DROP:-}" \
        DROP

    apply_spec \
        ip6tables \
        udp \
        "${V6_UDP_DROP:-}" \
        DROP

    apply_spec \
        ip6tables \
        tcp \
        "${V6_TCP_REJECT:-}" \
        REJECT \
        icmp6-adm-prohibited

    apply_spec \
        ip6tables \
        udp \
        "${V6_UDP_REJECT:-}" \
        REJECT \
        icmp6-adm-prohibited
fi


# ============================================================================
# Special deterministic IPv4 rate limits
# ============================================================================

case "${RATE_LIMIT:-none}" in
    none)
        ;;

    udp-icmp)
        ports="${RATE_LIMIT_PORTS:-40-79}"

        start=${ports%-*}
        end=${ports#*-}

        iptables \
            -A INPUT \
            -p udp \
            --dport "${start}:${end}" \
            -m limit \
            --limit "${RATE_LIMIT_RATE:-5/second}" \
            --limit-burst "${RATE_LIMIT_BURST:-5}" \
            -j ACCEPT

        iptables \
            -A INPUT \
            -p udp \
            --dport "${start}:${end}" \
            -j DROP
        ;;

    tcp-rst)
        ports="${RATE_LIMIT_PORTS:-40-79}"

        start=${ports%-*}
        end=${ports#*-}

        iptables \
            -A INPUT \
            -p tcp \
            --syn \
            --dport "${start}:${end}" \
            -m limit \
            --limit "${RATE_LIMIT_RATE:-5/second}" \
            --limit-burst "${RATE_LIMIT_BURST:-5}" \
            -j ACCEPT

        iptables \
            -A INPUT \
            -p tcp \
            --syn \
            --dport "${start}:${end}" \
            -j DROP
        ;;

    *)
        echo \
            "unknown RATE_LIMIT=${RATE_LIMIT}" \
            >&2

        exit 1
        ;;
esac


echo "[target] name:       ${TARGET_NAME:-unknown}"
echo "[target] IPv4:       ${TARGET_IPV4:-unknown}"

if [ "${IPV6_PROFILE:-0}" = "1" ]; then
    echo "[target] IPv6:       ${TARGET_IPV6:-unknown}"
    echo "[target] IPv6 mode:  enabled"
else
    echo "[target] IPv6 mode:  not part of test profile"
fi

echo "[target] rate-limit: ${RATE_LIMIT:-none}"

exec python3 /service_lab.py
'''


# ============================================================================
# Dockerfile
# ============================================================================

DOCKERFILE = r'''FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iptables \
      iproute2 \
      procps \
      python3 \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY service_lab.py /service_lab.py

RUN chmod +x \
      /entrypoint.sh \
      /service_lab.py

ENTRYPOINT ["/entrypoint.sh"]
'''


# ============================================================================
# Docker Compose
# ============================================================================

def render_compose(
    targets: list[Target],
) -> str:
    lines = [
        "name: ft-nmap-lab",
        "",
        "x-target-common: &target-common",
        "  image: ft-nmap-lab-target:local",
        "  build:",
        "    context: ./target",
        "  cap_add:",
        "    - NET_ADMIN",
        "    - NET_RAW",
        "  restart: \"no\"",
        "",
        "services:",
    ]

    for target in targets:
        profiles = []

        if target.number == 10:
            profiles.append("full")

        profiles.append("fleet")

        if target.has_ipv6_profile:
            profiles.append("ipv6")

        lines.extend(
            [
                f"  target-{target.number}:",
                "    <<: *target-common",
                (
                    "    container_name: "
                    f"ft_nmap_target_{target.number}"
                ),
                "    env_file:",
                (
                    "      - "
                    f"./configs/target-{target.number}.env"
                ),
                "    profiles:",
            ]
        )

        for profile in profiles:
            lines.append(
                f'      - "{profile}"'
            )

        lines.extend(
            [
                "    networks:",
                f"      {target.network}:",
                f"        ipv4_address: {target.ipv4}",
            ]
        )

        if target.has_ipv6_profile:
            lines.append(
                f"        ipv6_address: {target.ipv6}"
            )

        lines.append("")

    lines.extend(
        [
            "networks:",
            "  net-a:",
            "    driver: bridge",
            "    enable_ipv6: true",
            "    ipam:",
            "      config:",
            f"        - subnet: {NET_A_V4}",
            f"        - subnet: {NET_A_V6}",
            "",
            "  net-b:",
            "    driver: bridge",
            "    enable_ipv6: true",
            "    ipam:",
            "      config:",
            f"        - subnet: {NET_B_V4}",
            f"        - subnet: {NET_B_V6}",
            "",
        ]
    )

    return "\n".join(lines)


# ============================================================================
# Makefile
# ============================================================================

MAKEFILE = r'''.DEFAULT_GOAL := help

SUDO    ?= sudo
COMPOSE ?= docker compose


help:
	@printf '%s\n' 'ft_nmap network lab'
	@printf '%s\n' ''
	@printf '%s\n' '  make up      start all 20 IPv4 targets'
	@printf '%s\n' '  make full    start target-10 only'
	@printf '%s\n' '  make ipv6    start target-10 and target-20'
	@printf '%s\n' '  make down    stop the lab'
	@printf '%s\n' '  make re      rebuild and restart everything'
	@printf '%s\n' '  make clean   remove containers/networks/volumes'
	@printf '%s\n' '  make ps      show containers'
	@printf '%s\n' '  make logs    follow logs'


up:
	$(SUDO) $(COMPOSE) \
		--profile full \
		--profile fleet \
		up -d --build --force-recreate


full: down
	$(SUDO) $(COMPOSE) \
		--profile full \
		up -d --build --force-recreate


ipv6: down
	$(SUDO) $(COMPOSE) \
		--profile ipv6 \
		up -d --build --force-recreate


down:
	$(SUDO) $(COMPOSE) \
		--profile full \
		--profile fleet \
		--profile ipv6 \
		down


re: down
	$(MAKE) up


clean:
	$(SUDO) $(COMPOSE) \
		--profile full \
		--profile fleet \
		--profile ipv6 \
		down -v --remove-orphans


ps:
	$(SUDO) $(COMPOSE) \
		--profile full \
		--profile fleet \
		--profile ipv6 \
		ps


logs:
	$(SUDO) $(COMPOSE) \
		--profile full \
		--profile fleet \
		--profile ipv6 \
		logs -f


.PHONY: \
	help \
	up \
	full \
	ipv6 \
	down \
	re \
	clean \
	ps \
	logs
'''


# ============================================================================
# README
# ============================================================================

def markdown_state_row(
    proto: str,
    states: dict[int, str],
) -> str:
    return (
        f"| {proto} "
        f"| `{state_spec(states, 'O') or '-'}` "
        f"| `{state_spec(states, 'C') or '-'}` "
        f"| `{state_spec(states, 'D') or '-'}` "
        f"| `{state_spec(states, 'R') or '-'}` |"
    )


def render_readme(
    targets: list[Target],
) -> str:
    lines = [
        "# ft_nmap deterministic network lab",
        "",
        "## Networks",
        "",
        "### Network A",
        "",
        f"- IPv4: `{NET_A_V4}`",
        f"- IPv6: `{NET_A_V6}`",
        "- IPv4 targets: `.10` through `.19`",
        "- official IPv6 target: `fd42:28::10`",
        "",
        "### Network B",
        "",
        f"- IPv4: `{NET_B_V4}`",
        f"- IPv6: `{NET_B_V6}`",
        "- IPv4 targets: `.20` through `.29`",
        "- official IPv6 target: `fd42:29::20`",
        "",
        "Only `::10` and `::20` belong to the supported IPv6",
        "test contract.",
        "",
        "## States",
        "",
        "- `O`: OPEN, real listener",
        "- `C`: CLOSED, kernel-native closed response",
        "- `D`: DROP, silent firewall drop",
        "- `R`: REJECT, explicit firewall rejection",
        "",
        "## Common baseline 30-39",
        "",
        "| Port | TCP | UDP |",
        "|---:|:---:|:---:|",
    ]

    for port in range(30, 40):
        lines.append(
            f"| {port} "
            f"| {BASELINE_TCP[port]} "
            f"| {BASELINE_UDP[port]} |"
        )

    lines.extend(
        [
            "",
            "This baseline is identical on all IPv4 targets and",
            "on both official IPv6 targets.",
            "",
            "## IPv4 target addresses",
            "",
        ]
    )

    for target in targets:
        lines.append(
            f"- target-{target.number}: "
            f"`{target.ipv4}` — {target.name}"
        )

    lines.extend(
        [
            "",
            "## Exact IPv4 matrices",
            "",
        ]
    )

    for target in targets:
        lines.extend(
            [
                f"### {target.ipv4} — {target.name}",
                "",
                "| Proto | OPEN | CLOSED | DROP | REJECT |",
                "|---|---|---|---|---|",
                markdown_state_row(
                    "TCP",
                    target.tcp,
                ),
                markdown_state_row(
                    "UDP",
                    target.udp,
                ),
                "",
            ]
        )

        if target.number == 10:
            lines.append(
                "Ports `1025-65535` are CLOSED."
            )
        else:
            lines.append(
                "Ports `1-29` and `80-65535` are CLOSED."
            )

        lines.append("")

    lines.extend(
        [
            "## IPv6 targets",
            "",
            "The two official IPv6 targets use exactly the same",
            "1-1024 matrix.",
            "",
            "- `fd42:28::10` on network A",
            "- `fd42:29::20` on network B",
            "",
            "| Proto | OPEN | CLOSED | DROP | REJECT |",
            "|---|---|---|---|---|",
            markdown_state_row(
                "TCP",
                IPV6_TCP,
            ),
            markdown_state_row(
                "UDP",
                IPV6_UDP,
            ),
            "",
            "Ports `1025-65535` are CLOSED.",
            "",
            "Important representative IPv6 ports:",
            "",
            "```text",
            "TCP",
            "30 OPEN",
            "31 CLOSED",
            "32 DROP",
            "36 REJECT",
            "80 OPEN",
            "81 DROP",
            "82 REJECT",
            "443 OPEN",
            "444 DROP",
            "445 REJECT",
            "",
            "UDP",
            "31 OPEN",
            "30 CLOSED",
            "33 DROP",
            "37 REJECT",
            "53 OPEN",
            "54 DROP",
            "55 REJECT",
            "123 OPEN",
            "124 DROP",
            "125 REJECT",
            "```",
            "",
            "## Generated target lists",
            "",
            "`targets.txt` and `targets-v4.txt`:",
            "",
            "all 20 IPv4 targets.",
            "",
            "`targets-v6.txt`:",
            "",
            "```text",
            "fd42:28::10",
            "fd42:29::20",
            "```",
            "",
            "`targets-mixed.txt`:",
            "",
            "```text",
            "172.28.0.10",
            "fd42:28::10",
            "172.29.0.20",
            "fd42:29::20",
            "```",
            "",
            "The mixed list deliberately combines:",
            "",
            "- IPv4",
            "- IPv6",
            "- network A",
            "- network B",
            "",
            "## Commands",
            "",
            "```sh",
            "make full",
            "make ipv6",
            "make up",
            "make down",
            "make re",
            "make ps",
            "make logs",
            "```",
            "",
        ]
    )

    return "\n".join(lines)


# ============================================================================
# Generation
# ============================================================================

def write_file(
    path: Path,
    content: str,
    executable: bool = False,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        content.rstrip() + "\n",
        encoding="utf-8",
    )

    if executable:
        path.chmod(
            path.stat().st_mode | 0o111
        )


def cleanup_generated_configs():
    directory = LAB / "configs"

    if not directory.exists():
        return

    for path in directory.glob(
        "target-*.env"
    ):
        path.unlink()


def generate_target_lists(
    targets: list[Target],
) -> None:
    ipv4 = "\n".join(
        target.ipv4
        for target in targets
    )

    write_file(
        LAB / "targets.txt",
        ipv4,
    )

    write_file(
        LAB / "targets-v4.txt",
        ipv4,
    )

    write_file(
        LAB / "targets-v6.txt",
        "\n".join(
            [
                "fd42:28::10",
                "fd42:29::20",
            ]
        ),
    )

    write_file(
        LAB / "targets-mixed.txt",
        "\n".join(
            [
                "172.28.0.10",
                "fd42:28::10",
                "172.29.0.20",
                "fd42:29::20",
            ]
        ),
    )


def generate(
    targets: list[Target],
) -> None:
    LAB.mkdir(
        parents=True,
        exist_ok=True,
    )

    cleanup_generated_configs()

    write_file(
        LAB / "README.md",
        render_readme(targets),
    )

    write_file(
        LAB / "Makefile",
        MAKEFILE,
    )

    write_file(
        LAB / "docker-compose.yml",
        render_compose(targets),
    )

    generate_target_lists(
        targets,
    )

    for target in targets:
        write_file(
            (
                LAB
                / "configs"
                / f"target-{target.number}.env"
            ),
            render_config(target),
        )

    write_file(
        LAB / "target" / "Dockerfile",
        DOCKERFILE,
    )

    write_file(
        LAB / "target" / "entrypoint.sh",
        ENTRYPOINT,
        executable=True,
    )

    write_file(
        LAB / "target" / "service_lab.py",
        SERVICE_LAB,
        executable=True,
    )


def print_summary(
    targets: list[Target],
) -> None:
    print()
    print("Generated ./lab")
    print()
    print("IPv4:")
    print("  network A: 172.28.0.10-19")
    print("  network B: 172.29.0.20-29")
    print()
    print("IPv6:")
    print("  fd42:28::10")
    print("  fd42:29::20")
    print()
    print("Target lists:")
    print("  lab/targets.txt")
    print("  lab/targets-v4.txt")
    print("  lab/targets-v6.txt")
    print("  lab/targets-mixed.txt")
    print()
    print("Targets:", len(targets))
    print()
    print("Next:")
    print("  cd lab")
    print("  make ipv6")
    print()


def main() -> int:
    targets = [
        build_full_target(),
        *build_fleet_targets(),
    ]

    validate_targets(targets)
    generate(targets)
    print_summary(targets)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())