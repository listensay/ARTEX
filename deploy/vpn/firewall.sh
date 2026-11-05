#!/bin/sh
set -eu

# Set policies BEFORE touching rules: restarts never open a direct-dial window.
iptables -w -P OUTPUT DROP
iptables -w -P INPUT DROP
iptables -w -P FORWARD DROP
ip6tables -w -P OUTPUT DROP
ip6tables -w -P INPUT DROP
ip6tables -w -P FORWARD DROP
iptables -w -F OUTPUT
iptables -w -F INPUT
ip6tables -w -F OUTPUT
ip6tables -w -F INPUT

iptables -w -t mangle -N ARTEX_VPN_REPLY 2>/dev/null || true
iptables -w -t mangle -F ARTEX_VPN_REPLY
iptables -w -t mangle -C OUTPUT -j ARTEX_VPN_REPLY 2>/dev/null || \
    iptables -w -t mangle -A OUTPUT -j ARTEX_VPN_REPLY
# Management responses keep their inbound route, not the VPN default route.
iptables -w -t mangle -A ARTEX_VPN_REPLY -m conntrack \
    --ctstate ESTABLISHED,RELATED --ctdir REPLY -j MARK --set-mark 1979

iptables -w -A INPUT -i lo -j ACCEPT
iptables -w -A INPUT -i artex-tun -j ACCEPT
iptables -w -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for port in ${VPN_LISTEN_PORTS:-}; do
    case "$port" in *[!0-9]*|"") exit 1 ;; esac
    iptables -w -A INPUT -p tcp --dport "$port" -j ACCEPT
done

# Only the isolated gateway has CAP_NET_ADMIN and can set Mihomo's socket mark.
iptables -w -A OUTPUT -m mark --mark 1979 -j ACCEPT
# Docker's embedded DNS can forward outside this namespace; clients cannot use it.
iptables -w -A OUTPUT -d 127.0.0.11 -j REJECT
iptables -w -A OUTPUT -o lo -j ACCEPT
iptables -w -A OUTPUT -o artex-tun -j ACCEPT
iptables -w -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j ACCEPT

# Mihomo's auto-route preserves connected LAN routes. Override that for workloads
# too: only exact internal-service exclusions may use the main routing table.
ip -4 rule del priority 7999 2>/dev/null || true
ip -4 rule del priority 8000 2>/dev/null || true
ip -4 rule add priority 7999 fwmark 1979 lookup main
ip -4 rule add priority 8000 not fwmark 1979 lookup 2022
