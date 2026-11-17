#!/usr/bin/env bash
# Runs the NetGuard Linux agent inside WSL against the lab dashboard on the Windows host.
# Started by Start-Lab.ps1:  run-linux-agent.sh <port> <agent_token> [interval]
set -e
PORT="$1"; TOKEN="$2"; INTERVAL="${3:-30}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
LAB=/var/lib/netguard-lab
mkdir -p "$LAB/state"

# Find the Windows host: localhost works with WSL "mirrored" networking, otherwise use the NAT gateway.
probe() { python3 -c "import urllib.request,sys; urllib.request.urlopen('http://$1:$PORT/healthz', timeout=2)" 2>/dev/null; }
HOSTIP=""
for cand in 127.0.0.1 "$(ip route show default | awk '{print $3; exit}')"; do
  if [ -n "$cand" ] && probe "$cand"; then HOSTIP="$cand"; break; fi
done
if [ -z "$HOSTIP" ]; then
  echo "Cannot reach the dashboard on the Windows host (port $PORT)."
  echo "Windows Firewall is probably blocking python.exe from WSL. Allow it once from an elevated PowerShell:"
  echo "  New-NetFirewallRule -DisplayName 'NetGuard lab dashboard' -Direction Inbound -Protocol TCP -LocalPort $PORT -RemoteAddress 172.16.0.0/12,192.168.0.0/16 -Action Allow"
  sleep 600; exit 1
fi

cat > "$LAB/agent.json" <<EOF
{
  "server_url": "http://$HOSTIP:$PORT",
  "agent_token": "$TOKEN",
  "host_name": "wsl-$(hostname)",
  "state_dir": "$LAB/state",
  "interval_seconds": $INTERVAL,
  "harden_script": "$HERE/hardening/linux/harden.sh",
  "hardening_interval_minutes": 60
}
EOF
chmod 600 "$LAB/agent.json"
echo "NetGuard Linux agent (lab) -> http://$HOSTIP:$PORT  every ${INTERVAL}s. Close this window or run Stop-Lab.ps1 to stop."
exec python3 "$HERE/agents/linux/netguard_agent.py" --config "$LAB/agent.json" --daemon
