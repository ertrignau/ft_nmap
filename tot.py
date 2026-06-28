python3 - <<'PY'
from pathlib import Path

p = Path("srcs/packet/parse.c")
s = p.read_text()

old = "if (!get_ip_offset(config->capture.datalink, &ip_offset))"
new = "if (!nmap_get_ipv4_offset(config->capture.datalink, packet, len, &ip_offset))"

if old not in s:
    raise SystemExit("pattern not found")

s = s.replace(old, new, 1)
p.write_text(s)
PY