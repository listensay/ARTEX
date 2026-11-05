#!/bin/sh
set -eu
umask 077
/opt/vpn/firewall.sh
python3 /opt/vpn/runtime.py prepare
export SSL_CERT_FILE=/run/vpn/ca-bundle.pem
broker=0
if [ "${VPN_AGENT_CONTROL:-0}" = "1" ]; then
    python3 /opt/vpn/control.py &
    broker=$!
fi
# Core errors can include a subscription URL. Keep them in gateway-private tmpfs.
mihomo -d /var/lib/mihomo -f /run/vpn/config.json > /run/vpn/core.log 2>&1 &
core=$!
stop() {
    kill -TERM "$core" 2>/dev/null || true
    [ "$broker" -eq 0 ] || kill -TERM "$broker" 2>/dev/null || true
    wait "$core" 2>/dev/null || true
    exit 0
}
trap stop INT TERM
code=0
wait "$core" || code=$?
[ "$broker" -eq 0 ] || kill -TERM "$broker" 2>/dev/null || true
exit "$code"
