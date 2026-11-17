#!/usr/bin/env bash
# NetGuard Linux agent installer
#   sudo ./install.sh --server https://netguard.example.com:8787 --token <join_token> [--command-key <key>] [--insecure] [--trusted 10.0.0.5,10.0.0.0/24]
#   (--command-key: contents of command-signing.pub from the dashboard data folder; pins the dashboard that may send commands)
#   sudo ./install.sh --uninstall
set -euo pipefail

SERVER=""; TOKEN=""; INSECURE=0; TRUSTED=""; UNINSTALL=0; CMDKEY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER="$2"; shift ;;
    --token) TOKEN="$2"; shift ;;
    --insecure) INSECURE=1 ;;
    --trusted) TRUSTED="$2"; shift ;;
    --command-key) CMDKEY="$2"; shift ;;
    --uninstall) UNINSTALL=1 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

if [[ $UNINSTALL -eq 1 ]]; then
  systemctl disable --now netguard-agent 2>/dev/null || true
  rm -f /etc/systemd/system/netguard-agent.service
  systemctl daemon-reload
  rm -rf /opt/netguard
  echo "Removed agent. Config (/etc/netguard) and state (/var/lib/netguard) kept; delete manually if wanted."
  exit 0
fi

[[ -n "$SERVER" && -n "$TOKEN" ]] || { echo "usage: $0 --server URL --token TOKEN" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v ss >/dev/null || { echo "ss (iproute2) is required" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
HARDEN="$HERE/../../hardening/linux/harden.sh"
install -d -m 755 /opt/netguard
install -d -m 700 /etc/netguard /var/lib/netguard
install -m 755 "$HERE/netguard_agent.py" /opt/netguard/netguard_agent.py
install -m 755 "$HERE/netguard_backup.py" /opt/netguard/netguard_backup.py
command -v openssl >/dev/null || echo "note: install the openssl package for encrypted backups"
[[ -f "$HARDEN" ]] && install -m 755 "$HARDEN" /opt/netguard/harden.sh

trusted_json="[]"
if [[ -n "$TRUSTED" ]]; then
  trusted_json="[$(echo "$TRUSTED" | sed 's/[^,][^,]*/"&"/g')]"
fi
if [[ ! -f /etc/netguard/agent.json ]]; then
  cat > /etc/netguard/agent.json <<EOF
{
  "server_url": "$SERVER",
  "agent_token": "$TOKEN",
  "verify_tls": $([[ $INSECURE -eq 1 ]] && echo false || echo true),
  "ca_file": "",
  "interval_seconds": 60,
  "harden_script": "/opt/netguard/harden.sh",
  "hardening_interval_minutes": 360,
  "blocklist_file": "/etc/netguard/blocklist.txt",
  "trusted_ips": $trusted_json,
  "command_public_key": "$CMDKEY",
  "thresholds": {
    "auth_failures": 10, "auth_window_seconds": 600, "port_scan_ports": 15,
    "conn_per_ip": 200, "rx_mbps": 500, "tx_mbps": 500,
    "cpu_pct": 90, "cpu_cycles": 5, "mem_pct": 90, "disk_pct": 90
  }
}
EOF
  chmod 600 /etc/netguard/agent.json
else
  echo "/etc/netguard/agent.json exists - left unchanged"
fi
[[ -f /etc/netguard/blocklist.txt ]] || printf '# One IP or CIDR per line. Connections to/from these raise critical alerts.\n' > /etc/netguard/blocklist.txt

cat > /etc/systemd/system/netguard-agent.service <<'EOF'
[Unit]
Description=NetGuard monitoring agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/env python3 /opt/netguard/netguard_agent.py --config /etc/netguard/agent.json --daemon
Restart=always
RestartSec=10
Nice=10

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now netguard-agent
sleep 2
systemctl --no-pager status netguard-agent | head -5
echo
echo "Installed. Logs: journalctl -u netguard-agent -f"
echo "First cycle records the current listening ports as the baseline."
