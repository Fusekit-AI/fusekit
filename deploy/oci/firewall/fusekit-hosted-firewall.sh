#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

if [[ "$(id -u)" != "0" ]]; then
  echo "run as root on the FuseKit OCI hosted launcher" >&2
  exit 77
fi

for command in iptables; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "missing required command: ${command}" >&2
    exit 69
  fi
done

if ! iptables -C INPUT \
  -p tcp \
  -m multiport --dports 80,443 \
  -m state --state NEW \
  -j ACCEPT 2>/dev/null; then
  iptables -I INPUT 5 \
    -p tcp \
    -m multiport --dports 80,443 \
    -m state --state NEW \
    -j ACCEPT
fi

if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save
elif command -v iptables-save >/dev/null 2>&1; then
  install -d -o root -g root -m 0755 /etc/iptables
  iptables-save > /etc/iptables/rules.v4
fi
