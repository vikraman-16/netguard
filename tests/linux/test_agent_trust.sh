#!/usr/bin/env bash
# Linux agent detection test (run in WSL or on a Linux box, as a normal user):
#   bash tests/linux/test_agent_trust.sh
# Starts harmless decoys (copies of sleep/python, loopback listeners), runs the agent with --dry-run, checks the report.
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
D="$(mktemp -d)"; T="$(mktemp -d /tmp/ngdecoy.XXXX)"
cleanup() { kill "${PIDS[@]}" 2>/dev/null; wait 2>/dev/null; rm -rf "$D" "$T"; }
trap cleanup EXIT
cp /usr/bin/sleep "$T/sshd"; cp /usr/bin/sleep "$D/sshdd"; cp "$(readlink -f /usr/bin/python3)" "$D/mysrv"
PIDS=()
"$T/sshd" 120 & PIDS+=($!)
"$D/sshdd" 120 & PIDS+=($!)
bash -c 'exec -a "[kworker/0:2]" sleep 120' & PIDS+=($!)
python3 -c 'import os; fd=os.memfd_create("payload"); os.write(fd, open("/usr/bin/sleep","rb").read()); os.execv("/proc/self/fd/%d" % fd, ["sleep","120"])' & PIDS+=($!)
python3 -m http.server 18556 --bind 127.0.0.1 >/dev/null 2>&1 & PIDS+=($!)
PYTHONHOME=/usr "$D/mysrv" -m http.server 18558 --bind 127.0.0.1 >/dev/null 2>&1 & PIDS+=($!)
sleep 2
mkdir -p "$D/state"
printf '{"server_url":"http://127.0.0.1:9","agent_token":"x","host_name":"t","state_dir":"%s/state","harden_script":""}' "$D" > "$D/agent.json"
echo '{"listen_baseline": []}' > "$D/state/agent-state.json"
python3 "$REPO/agents/linux/netguard_agent.py" --config "$D/agent.json" --once --dry-run 2>"$D/err" >"$D/report.json"
python3 - "$D/report.json" "$T" "$D" <<'EOF'
import json, sys
r = json.load(open(sys.argv[1])); tdir, ddir = sys.argv[2], sys.argv[3]
a = r["alerts"]; fails = 0
def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name); fails += 0 if cond else 1
check("fake sshd from /tmp is critical masquerade", any(x["rule"] == "process_masquerade" and x["severity"] == "critical" and x["evidence"].get("exe") == tdir + "/sshd" for x in a))
check("sshdd flagged as look-alike", any("imitates 'sshd'" in x["title"] for x in a))
check("fake [kworker] detected", any("[kworker/0:2]" in x["title"] for x in a))
check("fileless memfd process detected", any(x["title"].startswith("Fileless process") for x in a))
check("unpackaged listener alert offers Trust + Quarantine", any("18558" in x["title"] and {"allow_process", "quarantine_file"} <= {s["action"] for s in x["suggested"]} for x in a))
check("packaged python3 listener auto-trusted (no alert)", not any("18556" in x["title"] for x in a))
check("capabilities reported", len(r["capabilities"]["supported"]) >= 10)
sys.exit(1 if fails else 0)
EOF
