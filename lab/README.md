# ft_nmap deterministic network lab

## Networks

### Network A

- IPv4: `172.28.0.0/24`
- IPv6: `fd42:28::/64`
- IPv4 targets: `.10` through `.19`
- official IPv6 target: `fd42:28::10`

### Network B

- IPv4: `172.29.0.0/24`
- IPv6: `fd42:29::/64`
- IPv4 targets: `.20` through `.29`
- official IPv6 target: `fd42:29::20`

Only `::10` and `::20` belong to the supported IPv6
test contract.

## States

- `O`: OPEN, real listener
- `C`: CLOSED, kernel-native closed response
- `D`: DROP, silent firewall drop
- `R`: REJECT, explicit firewall rejection

## Common baseline 30-39

| Port | TCP | UDP |
|---:|:---:|:---:|
| 30 | O | C |
| 31 | C | O |
| 32 | D | C |
| 33 | C | D |
| 34 | O | O |
| 35 | C | C |
| 36 | R | C |
| 37 | C | R |
| 38 | O | D |
| 39 | D | O |

This baseline is identical on all IPv4 targets and
on both official IPv6 targets.

## IPv4 target addresses

- target-10: `172.28.0.10` — full-default
- target-11: `172.28.0.11` — balanced
- target-12: `172.28.0.12` — tcp-open-heavy
- target-13: `172.28.0.13` — tcp-closed-heavy
- target-14: `172.28.0.14` — tcp-filtered-heavy
- target-15: `172.28.0.15` — udp-open-heavy
- target-16: `172.28.0.16` — udp-closed-heavy
- target-17: `172.28.0.17` — udp-filtered-heavy
- target-18: `172.28.0.18` — open-heavy
- target-19: `172.28.0.19` — closed-heavy
- target-20: `172.29.0.20` — filtered-heavy
- target-21: `172.29.0.21` — tcp-open-udp-closed
- target-22: `172.29.0.22` — tcp-closed-udp-open
- target-23: `172.29.0.23` — tcp-open-udp-filtered
- target-24: `172.29.0.24` — tcp-filtered-udp-open
- target-25: `172.29.0.25` — alternating
- target-26: `172.29.0.26` — reject-heavy
- target-27: `172.29.0.27` — mixed
- target-28: `172.29.0.28` — icmp-rate-limit
- target-29: `172.29.0.29` — rst-rate-limit

## Exact IPv4 matrices

### 172.28.0.10 — full-default

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `1-25,30,34,38,40-49,53,80-99,110,143,443-445,800-839,990-999` | `26-29,31,33,35,37,50-52,54-59,400-442,446-499,750-799,840-899` | `32,39,60-69,100-109,111-142,144-299,500-649,900-949` | `36,70-79,300-399,650-749,950-989,1000-1024` |
| UDP | `1-20,31,34,39,50-59,123,161,400-419,500,514,750-769` | `21-30,32,35-36,40-49,300-399,650-749,770-849` | `33,38,60-69,80-122,124-160,162-199,420-499,501-513,515-549,850-949` | `37,70-79,200-299,550-649,950-1024` |

Ports `1025-65535` are CLOSED.

### 172.28.0.11 — balanced

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38,40-42` | `31,33,35,37,43-45,50-59` | `32,39,46-47,60-69` | `36,48-49,70-79` |
| UDP | `31,34,39,43-45,50-59` | `30,32,35-36,40-42` | `33,38,48-49,70-79` | `37,46-47,60-69` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.28.0.12 — tcp-open-heavy

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38,40-48,50-69` | `31,33,35,37,49,70-79` | `32,39` | `36` |
| UDP | `31,34,39,43-45,50-59` | `30,32,35-36,40-42` | `33,38,46-47,60-69` | `37,48-49,70-79` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.28.0.13 — tcp-closed-heavy

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38,49,70-79` | `31,33,35,37,40-48,50-69` | `32,39` | `36` |
| UDP | `31,34,39-42` | `30,32,35-36,43-45,50-59` | `33,38,46-47,60-69` | `37,48-49,70-79` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.28.0.14 — tcp-filtered-heavy

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38` | `31,33,35,37` | `32,39-44,50-69` | `36,45-49,70-79` |
| UDP | `31,34,39,43-45,50-59` | `30,32,35-36,40-42` | `33,38,46-47,60-69` | `37,48-49,70-79` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.28.0.15 — udp-open-heavy

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38,40-42` | `31,33,35,37,43-45,50-59` | `32,39,46-47,60-69` | `36,48-49,70-79` |
| UDP | `31,34,39-48,50-69` | `30,32,35-36,49,70-79` | `33,38` | `37` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.28.0.16 — udp-closed-heavy

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38,40-42` | `31,33,35,37,43-45,50-59` | `32,39,46-47,60-69` | `36,48-49,70-79` |
| UDP | `31,34,39,49,70-79` | `30,32,35-36,40-48,50-69` | `33,38` | `37` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.28.0.17 — udp-filtered-heavy

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38,40-42` | `31,33,35,37,43-45,50-59` | `32,39,46-47,60-69` | `36,48-49,70-79` |
| UDP | `31,34,39` | `30,32,35-36` | `33,38,40-44,50-69` | `37,45-49,70-79` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.28.0.18 — open-heavy

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38,40-48,50-69` | `31,33,35,37,49,70-79` | `32,39` | `36` |
| UDP | `31,34,39-48,50-69` | `30,32,35-36,49,70-79` | `33,38` | `37` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.28.0.19 — closed-heavy

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38,49,70-79` | `31,33,35,37,40-48,50-69` | `32,39` | `36` |
| UDP | `31,34,39,49,70-79` | `30,32,35-36,40-48,50-69` | `33,38` | `37` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.29.0.20 — filtered-heavy

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38` | `31,33,35,37` | `32,39-44,50-69` | `36,45-49,70-79` |
| UDP | `31,34,39` | `30,32,35-36` | `33,38,40-44,50-69` | `37,45-49,70-79` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.29.0.21 — tcp-open-udp-closed

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38,40-48,50-69` | `31,33,35,37,49,70-79` | `32,39` | `36` |
| UDP | `31,34,39,49,70-79` | `30,32,35-36,40-48,50-69` | `33,38` | `37` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.29.0.22 — tcp-closed-udp-open

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38,49,70-79` | `31,33,35,37,40-48,50-69` | `32,39` | `36` |
| UDP | `31,34,39-48,50-69` | `30,32,35-36,49,70-79` | `33,38` | `37` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.29.0.23 — tcp-open-udp-filtered

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38,40-48,50-69` | `31,33,35,37,49,70-79` | `32,39` | `36` |
| UDP | `31,34,39` | `30,32,35-36` | `33,38,40-44,50-69` | `37,45-49,70-79` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.29.0.24 — tcp-filtered-udp-open

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38` | `31,33,35,37` | `32,39-44,50-69` | `36,45-49,70-79` |
| UDP | `31,34,39-48,50-69` | `30,32,35-36,49,70-79` | `33,38` | `37` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.29.0.25 — alternating

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38,40,44,48,52,56,60,64,68,72,76` | `31,33,35,37,41,45,49,53,57,61,65,69,73,77` | `32,39,42,46,50,54,58,62,66,70,74,78` | `36,43,47,51,55,59,63,67,71,75,79` |
| UDP | `31,34,39,43,47,51,55,59,63,67,71,75,79` | `30,32,35-36,40,44,48,52,56,60,64,68,72,76` | `33,38,41,45,49,53,57,61,65,69,73,77` | `37,42,46,50,54,58,62,66,70,74,78` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.29.0.26 — reject-heavy

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38` | `31,33,35,37,49,70-79` | `32,39` | `36,40-48,50-69` |
| UDP | `31,34,39` | `30,32,35-36,49,70-79` | `33,38` | `37,40-48,50-69` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.29.0.27 — mixed

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38,40,44,48,50-54,70-74` | `31,33,35,37,41,46-47,60-64,75-79` | `32,39,42,45,55-59` | `36,43,49,65-69` |
| UDP | `31,34,39,42,46,48,55-59,70-74` | `30,32,35-36,43-44,49,65-69` | `33,38,41,45,60-64` | `37,40,47,50-54,75-79` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.29.0.28 — icmp-rate-limit

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38` | `31,33,35,37,40-79` | `32,39` | `36` |
| UDP | `31,34,39` | `30,32,35-36,40-79` | `33,38` | `37` |

Ports `1-29` and `80-65535` are CLOSED.

### 172.29.0.29 — rst-rate-limit

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38` | `31,33,35,37,40-79` | `32,39` | `36` |
| UDP | `31,34,39` | `30,32,35-36,40-79` | `33,38` | `37` |

Ports `1-29` and `80-65535` are CLOSED.

## IPv6 targets

The two official IPv6 targets use exactly the same
1-1024 matrix.

- `fd42:28::10` on network A
- `fd42:29::20` on network B

| Proto | OPEN | CLOSED | DROP | REJECT |
|---|---|---|---|---|
| TCP | `30,34,38,80,443` | `1-29,31,33,35,37,40-79,83-442,446-1024` | `32,39,81,444` | `36,82,445` |
| UDP | `31,34,39,53,123` | `1-30,32,35-36,40-52,56-122,126-1024` | `33,38,54,124` | `37,55,125` |

Ports `1025-65535` are CLOSED.

Important representative IPv6 ports:

```text
TCP
30 OPEN
31 CLOSED
32 DROP
36 REJECT
80 OPEN
81 DROP
82 REJECT
443 OPEN
444 DROP
445 REJECT

UDP
31 OPEN
30 CLOSED
33 DROP
37 REJECT
53 OPEN
54 DROP
55 REJECT
123 OPEN
124 DROP
125 REJECT
```

## Generated target lists

`targets.txt` and `targets-v4.txt`:

all 20 IPv4 targets.

`targets-v6.txt`:

```text
fd42:28::10
fd42:29::20
```

`targets-mixed.txt`:

```text
172.28.0.10
fd42:28::10
172.29.0.20
fd42:29::20
```

The mixed list deliberately combines:

- IPv4
- IPv6
- network A
- network B

## Commands

```sh
make full
make ipv6
make up
make down
make re
make ps
make logs
```
