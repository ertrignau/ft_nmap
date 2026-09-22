#!/bin/sh
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
