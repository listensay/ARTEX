FROM metacubex/mihomo:v1.19.33@sha256:9211361a3ed85305383288d38c05e85862d6d5a590c10007c37fc059cca82e9c AS mihomo
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates iptables iproute2 && rm -rf /var/lib/apt/lists/*
COPY --from=mihomo /mihomo /usr/local/bin/mihomo
COPY configure.py runtime.py control.py firewall.sh entrypoint.sh /opt/vpn/
RUN chmod 755 /opt/vpn/*.sh
ENTRYPOINT ["/opt/vpn/entrypoint.sh"]
