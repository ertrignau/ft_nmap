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
