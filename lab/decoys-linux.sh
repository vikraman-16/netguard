#!/usr/bin/env bash
# Harmless fake threats for the NetGuard lab (run as your normal WSL user).
# Every decoy is a copy of sleep/python or a loopback-only listener and exits after $1 seconds.
SECS="${1:-600}"
D="$HOME/.netguard-decoys"; T=/tmp/netguard-decoys
rm -rf "$D" "$T"; mkdir -p "$D" "$T"
cp /usr/bin/sleep "$T/sshd"                         # fake sshd running from /tmp       -> critical
cp /usr/bin/sleep "$D/sshdd"                        # look-alike name                   -> high
cp "$(readlink -f /usr/bin/python3)" "$D/mysrv"     # unpackaged program serving a port -> medium + "Trust process"

"$T/sshd" "$SECS" &
"$D/sshdd" "$SECS" &
bash -c "exec -a '[kworker/0:2]' sleep $SECS" &     # disguised as a kernel thread      -> critical
python3 -c "import os; fd=os.memfd_create('payload'); os.write(fd, open('/usr/bin/sleep','rb').read()); os.execv('/proc/self/fd/%d' % fd, ['sleep','$SECS'])" &   # fileless -> critical
PYTHONHOME=/usr timeout "$SECS" "$D/mysrv" -m http.server 18558 --bind 127.0.0.1 >/dev/null 2>&1 &
command -v nc >/dev/null && timeout "$SECS" nc -lk 127.0.0.1 18557 >/dev/null 2>&1 &   # netcat holding a port -> high
wait
rm -rf "$D" "$T"
