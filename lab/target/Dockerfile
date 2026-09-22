FROM debian:bookworm-slim

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
