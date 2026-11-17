#!/usr/bin/env bash
# =============================================================================
# NetGuard - Linux server hardening (Debian/Ubuntu, RHEL/Rocky/Alma/Fedora, SUSE)
#
#   sudo ./harden.sh                      # audit only (default, changes nothing)
#   sudo ./harden.sh --apply              # fix failing checks, asks per check
#   sudo ./harden.sh --apply --yes        # fix everything without prompting
#   sudo ./harden.sh --apply --only ssh_x11_forwarding,sysctl.net.ipv4.tcp_syncookies
#   sudo ./harden.sh --skip ssh_password_auth,firewall_active
#   sudo ./harden.sh --json /tmp/report.json   (or --json - for stdout)
#   sudo ./harden.sh --list
#   sudo ./harden.sh --restore /var/backups/netguard-hardening/20261117-104700
#
# Every changed file is copied to /var/backups/netguard-hardening/<timestamp>/
# before modification. Risky changes (SSH password auth, root login, firewall)
# have lock-out guards and refuse to apply when they could cut off access.
# =============================================================================
set -uo pipefail

VERSION="1.0.0"
MODE="audit"
ASSUME_YES=0
ONLY=""
SKIP=""
JSON_OUT=""
RESTORE_DIR=""
LIST_ONLY=0
BACKUP_ROOT="/var/backups/netguard-hardening"
BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/var/log/netguard-hardening.log"
BACKUP_MADE=0

if [[ -t 1 ]]; then
  C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_BLU=$'\e[34m'; C_DIM=$'\e[2m'; C_RST=$'\e[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_DIM=""; C_RST=""
fi

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) MODE="apply" ;;
    --audit) MODE="audit" ;;
    --yes|-y) ASSUME_YES=1 ;;
    --only) ONLY="${2:-}"; shift ;;
    --skip) SKIP="${2:-}"; shift ;;
    --json) JSON_OUT="${2:-}"; shift ;;
    --restore) RESTORE_DIR="${2:-}"; shift ;;
    --list) LIST_ONLY=1 ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

log() { [[ -w "$(dirname "$LOG_FILE")" ]] && echo "$(date -Is) [$MODE] $*" >> "$LOG_FILE"; }
info() { [[ "$JSON_OUT" == "-" ]] && echo "$*" >&2 || echo "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

if [[ $EUID -ne 0 && $LIST_ONLY -eq 0 ]]; then
  echo "${C_YEL}Warning:${C_RST} not running as root; many checks will be inaccurate and --apply will fail." >&2
fi

# ---------------------------------------------------------------------------
# Platform helpers
# ---------------------------------------------------------------------------
PKG=""
if have apt-get; then PKG="apt"; elif have dnf; then PKG="dnf"; elif have yum; then PKG="yum"; elif have zypper; then PKG="zypper"; fi

pkg_install() {
  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" ;;
    dnf) dnf install -y -q "$@" ;;
    yum) yum install -y -q "$@" ;;
    zypper) zypper -n -q install "$@" ;;
    *) echo "no supported package manager" >&2; return 1 ;;
  esac
}
pkg_installed() {
  case "$PKG" in
    apt) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed" ;;
    *) rpm -q "$1" >/dev/null 2>&1 ;;
  esac
}
svc_active() { systemctl is-active --quiet "$1" 2>/dev/null; }
svc_enabled() { systemctl is-enabled --quiet "$1" 2>/dev/null; }

backup_file() {
  local f="$1"
  mkdir -p "$BACKUP_DIR"
  BACKUP_MADE=1
  if [[ -e "$f" ]]; then
    mkdir -p "$BACKUP_DIR$(dirname "$f")"
    cp -a "$f" "$BACKUP_DIR$f"
  else
    echo "$f" >> "$BACKUP_DIR/created-files.txt"
  fi
}

ssh_port() {
  local p
  p=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}')
  echo "${p:-22}"
}

# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------
if [[ -n "$RESTORE_DIR" ]]; then
  [[ -d "$RESTORE_DIR" ]] || { echo "No such backup: $RESTORE_DIR" >&2; exit 1; }
  echo "Restoring files from $RESTORE_DIR ..."
  (cd "$RESTORE_DIR" && find . -type f ! -name created-files.txt -print) | while read -r rel; do
    dest="${rel#.}"
    cp -a "$RESTORE_DIR$dest" "$dest" && echo "  restored $dest"
  done
  if [[ -f "$RESTORE_DIR/created-files.txt" ]]; then
    while read -r f; do [[ -n "$f" && -e "$f" ]] && rm -f "$f" && echo "  removed  $f"; done < "$RESTORE_DIR/created-files.txt"
  fi
  sysctl --system >/dev/null 2>&1 || true
  if have sshd && sshd -t; then systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true; fi
  echo "Done. Note: installed packages and enabled services were not reverted."
  log "restore from $RESTORE_DIR"
  exit 0
fi

# ---------------------------------------------------------------------------
# Check registry
#   Each check: check_<fn> sets DETAIL, returns 0=pass 1=fail 2=n/a
#               fix_<fn>   returns 0 on success (optional -> manual)
# ---------------------------------------------------------------------------
declare -a CHECKS=()
declare -A TITLE=() SEV=() FN=() ARG=()
DETAIL=""

reg() { # id severity function title [arg]
  CHECKS+=("$1"); SEV[$1]="$2"; FN[$1]="$3"; TITLE[$1]="$4"; ARG[$1]="${5:-}"
}

# ---------------- SSH ----------------
sshd_val() { sshd -T 2>/dev/null | awk -v k="$1" '$1==k{ $1=""; sub(/^ /,""); print; exit}'; }

set_sshd_option() { # key value
  local key="$1" val="$2" target
  if [[ -d /etc/ssh/sshd_config.d ]] && grep -Eqi '^\s*Include\s+/etc/ssh/sshd_config.d/\*\.conf' /etc/ssh/sshd_config; then
    # sshd uses the FIRST value it sees; 00- sorts before cloud-init's 50-*.conf
    target=/etc/ssh/sshd_config.d/00-netguard-hardening.conf
    backup_file "$target"
    touch "$target"; chmod 600 "$target"
    sed -i "/^\s*${key}\s/Id" "$target"
    echo "$key $val" >> "$target"
  else
    target=/etc/ssh/sshd_config
    backup_file "$target"
    sed -i "s/^\s*\(${key}\s.*\)$/# netguard: \1/I" "$target"
    sed -i "1i ${key} ${val}" "$target"
  fi
  if ! sshd -t 2>/tmp/netguard-sshd.err; then
    echo "sshd config test failed, reverting: $(cat /tmp/netguard-sshd.err)" >&2
    if [[ -e "$BACKUP_DIR$target" ]]; then cp -a "$BACKUP_DIR$target" "$target"; else rm -f "$target"; fi
    return 1
  fi
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
}

ssh_present() { have sshd && [[ -f /etc/ssh/sshd_config ]]; }

check_ssh_opt() { # arg = key|expected|op   op: eq / le
  ssh_present || { DETAIL="OpenSSH server not installed"; return 2; }
  local key exp op cur
  IFS='|' read -r key exp op <<< "$1"
  cur=$(sshd_val "${key,,}")
  DETAIL="$key is '${cur:-unset}' (want ${op/le/<=} $exp)"
  if [[ "$op" == "le" ]]; then [[ "${cur:-999}" =~ ^[0-9]+$ ]] && (( cur <= exp )) && return 0
  elif [[ "$op" == "nzle" ]]; then [[ "${cur:-0}" =~ ^[0-9]+$ ]] && (( cur > 0 && cur <= exp )) && return 0
  else [[ "${cur,,}" == "${exp,,}" ]] && return 0; fi
  return 1
}
fix_ssh_opt() {
  local key exp op
  IFS='|' read -r key exp op <<< "$1"
  set_sshd_option "$key" "$exp"
}

# lock-out guards
other_admin_exists() {
  local u grp
  for grp in sudo wheel admin; do
    getent group "$grp" >/dev/null || continue
    for u in $(getent group "$grp" | cut -d: -f4 | tr ',' ' '); do
      [[ "$u" != "root" ]] && id "$u" >/dev/null 2>&1 && return 0
    done
  done
  return 1
}
someone_has_keys() {
  local home
  while IFS=: read -r user _ uid _ _ home _; do
    [[ "$uid" -ge 1000 || "$user" == "root" ]] || continue
    [[ -s "$home/.ssh/authorized_keys" ]] && return 0
  done < /etc/passwd
  return 1
}
fix_ssh_root_login() {
  if ! other_admin_exists; then
    echo "REFUSED: no non-root user in sudo/wheel/admin group. Create one first or you'd lose admin SSH access." >&2
    return 1
  fi
  set_sshd_option PermitRootLogin no
}
fix_ssh_client_alive() { set_sshd_option ClientAliveInterval 300 && set_sshd_option ClientAliveCountMax 3; }
fix_ssh_password_auth() {
  if ! someone_has_keys; then
    echo "REFUSED: no user has ~/.ssh/authorized_keys. Set up key login first or you'd be locked out." >&2
    return 1
  fi
  set_sshd_option PasswordAuthentication no && set_sshd_option KbdInteractiveAuthentication no
}

# ---------------- firewall ----------------
listening_tcp_ports() {
  ss -Htlnp 2>/dev/null | awk '{print $4}' | grep -Ev '^(127\.|\[::1\]|::1)' | sed -E 's/.*:([0-9]+)$/\1/' | sort -un
}
check_firewall() {
  if have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then DETAIL="ufw active"; return 0; fi
  if svc_active firewalld; then DETAIL="firewalld active"; return 0; fi
  if have nft && nft list ruleset 2>/dev/null | grep -Eq 'hook input .*policy drop'; then DETAIL="nftables input policy drop"; return 0; fi
  if have iptables && iptables -S INPUT 2>/dev/null | grep -q -- '-P INPUT DROP'; then DETAIL="iptables INPUT policy DROP"; return 0; fi
  DETAIL="no active host firewall (ufw/firewalld/nftables/iptables default-deny)"
  return 1
}
fix_firewall() {
  local sp ports p
  sp=$(ssh_port)
  ports=$(listening_tcp_ports)
  if [[ "$PKG" == "apt" ]] || have ufw; then
    have ufw || pkg_install ufw || return 1
    ufw default deny incoming; ufw default allow outgoing
    ufw allow "$sp"/tcp comment 'ssh (netguard)'
    for p in $ports; do ufw allow "$p"/tcp comment 'was listening when firewall enabled (netguard)'; done
    ufw --force enable
  else
    have firewall-cmd || pkg_install firewalld || return 1
    systemctl enable --now firewalld || return 1
    firewall-cmd --permanent --add-port="$sp"/tcp
    for p in $ports; do firewall-cmd --permanent --add-port="$p"/tcp; done
    firewall-cmd --reload
  fi
  echo "Firewall enabled. Allowed SSH ($sp) and currently-listening TCP ports: $(echo $ports | tr '\n' ' ')"
  echo "Review and remove ports that should not be public."
}

# ---------------- fail2ban ----------------
check_fail2ban() {
  ssh_present || { DETAIL="no sshd, fail2ban not required"; return 2; }
  if svc_active fail2ban; then DETAIL="fail2ban running"; return 0; fi
  DETAIL="fail2ban not running"; return 1
}
fix_fail2ban() {
  if ! have fail2ban-client; then
    if [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then pkg_install epel-release >/dev/null 2>&1 || true; fi
    pkg_install fail2ban || return 1
  fi
  local f=/etc/fail2ban/jail.d/netguard.local backend="auto"
  [[ -d /run/systemd/system ]] && backend="systemd"
  backup_file "$f"
  cat > "$f" <<EOF
# managed by NetGuard harden.sh
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
banaction = $(have ufw && echo ufw || (svc_active firewalld && echo firewallcmd-rich-rules) || echo iptables-multiport)

[sshd]
enabled = true
port    = $(ssh_port)
backend = $backend
EOF
  systemctl enable --now fail2ban && systemctl restart fail2ban
}

# ---------------- updates ----------------
check_auto_updates() {
  case "$PKG" in
    apt)
      pkg_installed unattended-upgrades && grep -Rqs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/ \
        && { DETAIL="unattended-upgrades enabled"; return 0; }
      DETAIL="unattended-upgrades not installed/enabled"; return 1 ;;
    dnf|yum)
      svc_enabled dnf-automatic-install.timer || svc_enabled dnf-automatic.timer || svc_enabled yum-cron \
        && { DETAIL="automatic updates timer enabled"; return 0; }
      DETAIL="dnf-automatic not enabled"; return 1 ;;
    *) DETAIL="unsupported package manager"; return 2 ;;
  esac
}
fix_auto_updates() {
  case "$PKG" in
    apt)
      pkg_install unattended-upgrades || return 1
      backup_file /etc/apt/apt.conf.d/20auto-upgrades
      printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades ;;
    dnf|yum)
      pkg_install dnf-automatic || return 1
      backup_file /etc/dnf/automatic.conf
      sed -i 's/^upgrade_type.*/upgrade_type = security/; s/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
      systemctl enable --now dnf-automatic.timer ;;
  esac
}

# ---------------- auditd ----------------
check_auditd() { svc_active auditd && { DETAIL="auditd running"; return 0; }; DETAIL="auditd not running"; return 1; }
fix_auditd() {
  if ! have auditctl; then
    if [[ "$PKG" == "apt" ]]; then pkg_install auditd audispd-plugins || pkg_install auditd || return 1; else pkg_install audit || return 1; fi
  fi
  local f=/etc/audit/rules.d/50-netguard.rules
  backup_file "$f"
  cat > "$f" <<'EOF'
## NetGuard: watch identity, auth and privilege configuration
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
EOF
  systemctl enable --now auditd 2>/dev/null || service auditd start
  have augenrules && augenrules --load >/dev/null 2>&1 || true
}

# ---------------- sysctl ----------------
SYSCTL_FILE=/etc/sysctl.d/99-netguard-hardening.conf
check_sysctl() {
  local key="${1%%=*}" want="${1#*=}" cur
  cur=$(sysctl -n "$key" 2>/dev/null) || { DETAIL="$key not present on this kernel"; return 2; }
  DETAIL="$key = $cur (want $want)"
  [[ "$cur" == "$want" ]]
}
fix_sysctl() {
  local key="${1%%=*}" want="${1#*=}"
  backup_file "$SYSCTL_FILE"
  touch "$SYSCTL_FILE"
  sed -i "/^${key//./\\.}\s*=/d" "$SYSCTL_FILE"
  echo "$key = $want" >> "$SYSCTL_FILE"
  sysctl -q -w "$key=$want"
}

# ---------------- file permissions ----------------
check_perm() { # arg path|maxmode|owner
  local path max owner mode cur_owner
  IFS='|' read -r path max owner <<< "$1"
  [[ -e "$path" ]] || { DETAIL="$path not present"; return 2; }
  mode=$(stat -c %a "$path"); cur_owner=$(stat -c %U "$path")
  DETAIL="$path mode $mode owner $cur_owner (want <= $max, owner $owner)"
  (( (8#$mode & ~8#$max) == 0 )) && [[ "$cur_owner" == "$owner" ]]
}
fix_perm() {
  local path max owner mode
  IFS='|' read -r path max owner <<< "$1"
  mode=$(stat -c %a "$path")
  backup_file "$path"
  chown "$owner" "$path" && chmod "$(printf '%o' $(( 8#$mode & 8#$max )))" "$path"
}

# ---------------- accounts ----------------
check_uid0() {
  local extra
  extra=$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd | tr '\n' ' ')
  DETAIL="${extra:+extra UID 0 accounts: $extra}"; DETAIL="${DETAIL:-only root has UID 0}"
  [[ -z "$extra" ]]
}
check_empty_pw() {
  local users
  [[ -r /etc/shadow ]] || { DETAIL="cannot read /etc/shadow (run as root)"; return 2; }
  users=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
  DETAIL="${users:+accounts with EMPTY password: $users}"; DETAIL="${DETAIL:-no empty passwords}"
  [[ -z "$users" ]]
}
fix_empty_pw() {
  local u
  backup_file /etc/shadow
  for u in $(awk -F: '($2==""){print $1}' /etc/shadow); do passwd -l "$u"; done
}
check_login_defs() {
  local max min
  max=$(awk '$1=="PASS_MAX_DAYS"{print $2}' /etc/login.defs 2>/dev/null)
  min=$(awk '$1=="PASS_MIN_DAYS"{print $2}' /etc/login.defs 2>/dev/null)
  DETAIL="PASS_MAX_DAYS=${max:-unset} PASS_MIN_DAYS=${min:-unset} (want <=365 and >=1)"
  [[ "${max:-99999}" -le 365 && "${min:-0}" -ge 1 ]]
}
fix_login_defs() {
  backup_file /etc/login.defs
  sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/; s/^PASS_WARN_AGE.*/PASS_WARN_AGE\t14/' /etc/login.defs
  grep -q '^PASS_MAX_DAYS' /etc/login.defs || echo -e "PASS_MAX_DAYS\t365" >> /etc/login.defs
  grep -q '^PASS_MIN_DAYS' /etc/login.defs || echo -e "PASS_MIN_DAYS\t1" >> /etc/login.defs
  echo "Applies to new passwords; existing users: chage --maxdays 365 <user>"
}

# ---------------- sudo ----------------
SUDO_FILE=/etc/sudoers.d/90-netguard
check_sudo() {
  have sudo || { DETAIL="sudo not installed"; return 2; }
  [[ -r /etc/sudoers ]] || { DETAIL="cannot read /etc/sudoers (run as root)"; return 2; }
  local d; d=$(cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null)
  if grep -q 'use_pty' <<< "$d" && grep -q 'logfile' <<< "$d"; then DETAIL="sudo use_pty + logfile set"; return 0; fi
  DETAIL="sudo missing 'Defaults use_pty' and/or 'Defaults logfile'"; return 1
}
fix_sudo() {
  backup_file "$SUDO_FILE"
  printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\n' > "$SUDO_FILE.tmp"
  if visudo -cf "$SUDO_FILE.tmp" >/dev/null; then mv "$SUDO_FILE.tmp" "$SUDO_FILE"; chmod 440 "$SUDO_FILE"
  else rm -f "$SUDO_FILE.tmp"; echo "visudo validation failed" >&2; return 1; fi
}

# ---------------- misc ----------------
check_core_dumps() {
  grep -Rqs -E '^\s*\*\s+hard\s+core\s+0' /etc/security/limits.conf /etc/security/limits.d/ \
    && { DETAIL="core dumps restricted"; return 0; }
  DETAIL="no '* hard core 0' limit"; return 1
}
fix_core_dumps() {
  local f=/etc/security/limits.d/90-netguard.conf
  backup_file "$f"; echo '* hard core 0' > "$f"
}
LEGACY_SVCS="telnet.socket telnetd rsh.socket rlogin.socket rexec.socket tftp.socket tftpd-hpa xinetd vsftpd"
check_legacy_svcs() {
  local s bad=""
  for s in $LEGACY_SVCS; do svc_enabled "$s" && bad+="$s "; done
  DETAIL="${bad:+insecure services enabled: $bad}"; DETAIL="${DETAIL:-no telnet/rsh/tftp/ftp services enabled}"
  [[ -z "$bad" ]]
}
fix_legacy_svcs() { local s; for s in $LEGACY_SVCS; do svc_enabled "$s" && systemctl disable --now "$s"; done; return 0; }
OPTIONAL_SVCS="avahi-daemon cups cups-browsed rpcbind"
check_optional_svcs() {
  local s bad=""
  for s in $OPTIONAL_SVCS; do svc_enabled "$s" && bad+="$s "; done
  DETAIL="${bad:+usually unneeded on servers: $bad(keep rpcbind if you use NFS)}"; DETAIL="${DETAIL:-none enabled}"
  [[ -z "$bad" ]]
}
fix_optional_svcs() { local s; for s in $OPTIONAL_SVCS; do svc_enabled "$s" && systemctl disable --now "$s" "$s.socket" 2>/dev/null; done; return 0; }
check_time_sync() {
  have timedatectl || { DETAIL="timedatectl unavailable"; return 2; }
  [[ "$(timedatectl show -p NTP --value 2>/dev/null)" == "yes" ]] && { DETAIL="NTP sync enabled"; return 0; }
  DETAIL="NTP time sync disabled (log timestamps unreliable)"; return 1
}
fix_time_sync() { timedatectl set-ntp true; }
check_world_writable() {
  local files
  files=$(timeout 60 find / -xdev -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -20 | tr '\n' ' ')
  DETAIL="${files:+world-writable files: $files}"; DETAIL="${DETAIL:-none found}"
  [[ -z "$files" ]]
}

# ---------------------------------------------------------------------------
# Register checks
# ---------------------------------------------------------------------------
reg ssh_root_login        high   ssh_opt  "SSH: disable root login"               "PermitRootLogin|no|eq"
reg ssh_password_auth     high   ssh_opt  "SSH: key-only authentication"          "PasswordAuthentication|no|eq"
reg ssh_empty_passwords   critical ssh_opt "SSH: forbid empty passwords"          "PermitEmptyPasswords|no|eq"
reg ssh_max_auth_tries    medium ssh_opt  "SSH: MaxAuthTries <= 4"                "MaxAuthTries|4|le"
reg ssh_x11_forwarding    low    ssh_opt  "SSH: disable X11 forwarding"           "X11Forwarding|no|eq"
reg ssh_login_grace       low    ssh_opt  "SSH: LoginGraceTime <= 60s"            "LoginGraceTime|60|le"
reg ssh_client_alive      low    ssh_opt  "SSH: idle session timeout (300s)"      "ClientAliveInterval|300|nzle"
reg firewall_active       critical firewall "Host firewall enabled (default deny inbound)"
reg fail2ban_active       high   fail2ban "fail2ban protecting SSH"
reg auto_updates          high   auto_updates "Automatic security updates"
reg auditd_active         medium auditd   "auditd running with NetGuard rules"
for kv in \
  "net.ipv4.tcp_syncookies=1" "net.ipv4.conf.all.accept_redirects=0" "net.ipv4.conf.default.accept_redirects=0" \
  "net.ipv4.conf.all.secure_redirects=0" "net.ipv4.conf.all.send_redirects=0" "net.ipv4.conf.default.send_redirects=0" \
  "net.ipv4.conf.all.accept_source_route=0" "net.ipv4.conf.default.accept_source_route=0" \
  "net.ipv4.conf.all.rp_filter=1" "net.ipv4.conf.default.rp_filter=1" "net.ipv4.icmp_echo_ignore_broadcasts=1" \
  "net.ipv4.icmp_ignore_bogus_error_responses=1" "net.ipv4.conf.all.log_martians=1" \
  "net.ipv6.conf.all.accept_redirects=0" "net.ipv6.conf.default.accept_redirects=0" "net.ipv6.conf.all.accept_source_route=0" \
  "kernel.randomize_va_space=2" "kernel.kptr_restrict=2" "kernel.dmesg_restrict=1" "kernel.yama.ptrace_scope=1" \
  "fs.suid_dumpable=0" "fs.protected_hardlinks=1" "fs.protected_symlinks=1"; do
  reg "sysctl.${kv%%=*}" medium sysctl "Kernel: ${kv}" "$kv"
done
reg perm_shadow           high   perm "/etc/shadow permissions"   "/etc/shadow|640|root"
reg perm_gshadow          high   perm "/etc/gshadow permissions"  "/etc/gshadow|640|root"
reg perm_passwd           medium perm "/etc/passwd permissions"   "/etc/passwd|644|root"
reg perm_group            medium perm "/etc/group permissions"    "/etc/group|644|root"
reg perm_sshd_config      medium perm "sshd_config permissions"   "/etc/ssh/sshd_config|600|root"
reg perm_crontab          medium perm "/etc/crontab permissions"  "/etc/crontab|600|root"
reg uid0_only_root        critical uid0 "Only root has UID 0"
reg empty_passwords       critical empty_pw "No accounts with empty passwords"
reg login_defs_aging      low    login_defs "Password aging policy"
reg sudo_logging          medium sudo "sudo uses pty and logs to file"
reg core_dumps            low    core_dumps "Core dumps disabled"
reg legacy_services       high   legacy_svcs "Insecure legacy services disabled"
reg optional_services     low    optional_svcs "Unneeded desktop/network services disabled"
reg time_sync             medium time_sync "Time synchronisation enabled"
reg world_writable_files  medium world_writable "No world-writable files"

# ---------------------------------------------------------------------------
# What each fix changes / what it can break (shown in the dashboard before applying)
# ---------------------------------------------------------------------------
fix_info() { # id fn arg -> sets FI_CHANGE FI_RISK FI_REBOOT
  local id="$1" fn="$2" arg="$3" key val path max owner
  FI_REBOOT=false; FI_RISK="Low."
  case "$fn" in
    ssh_opt)
      IFS='|' read -r key val _ <<< "$arg"
      FI_CHANGE="Set '$key $val' in an sshd drop-in (validated with sshd -t, reverted if invalid), then reload sshd. Existing sessions stay connected."
      case "$id" in
        ssh_root_login) FI_RISK="You can no longer SSH in as root; use your sudo user. Refused automatically if no other sudo user exists." ;;
        ssh_password_auth) FI_RISK="Password logins over SSH stop working; only SSH keys work. Refused automatically if nobody has authorized_keys." ;;
        ssh_max_auth_tries) FI_RISK="Clients offering many keys may need -o IdentitiesOnly=yes." ;;
        ssh_x11_forwarding) FI_RISK="Remote GUI apps over ssh -X stop working." ;;
        ssh_client_alive) FI_RISK="Idle SSH sessions are disconnected after ~15 minutes."
                          FI_CHANGE="Set ClientAliveInterval 300 and ClientAliveCountMax 3 in an sshd drop-in, then reload sshd." ;;
        *) FI_RISK="None for normal use." ;;
      esac ;;
    sysctl) FI_CHANGE="Set ${arg} in /etc/sysctl.d/99-netguard-hardening.conf and apply it immediately."
            case "$arg" in
              *ip_forward*|*rp_filter*) FI_RISK="Can break routing on hosts acting as routers, VPN gateways or with asymmetric routes." ;;
              *ptrace_scope*) FI_RISK="Debuggers (gdb, strace) can only attach to their own child processes without sudo." ;;
              *dmesg_restrict*|*kptr_restrict*) FI_RISK="Non-root users can no longer read the kernel log / kernel addresses." ;;
              *) FI_RISK="None for normal servers." ;;
            esac ;;
    perm) IFS='|' read -r path max owner <<< "$arg"
          FI_CHANGE="chown $owner and remove permissions beyond $max on $path."; FI_RISK="None for normal use." ;;
    firewall) FI_CHANGE="Install/enable ufw (or firewalld): deny inbound by default, allow SSH and every TCP port currently listening."
              FI_RISK="Ports that were not listening at that moment become unreachable from outside until you allow them." ;;
    fail2ban) FI_CHANGE="Install fail2ban and enable an sshd jail (5 failures in 10 min = 1 h ban)."
              FI_RISK="You can ban yourself for an hour after 5 bad SSH logins; add your IP to ignoreip if needed." ;;
    auto_updates) FI_CHANGE="Install and enable unattended-upgrades (Debian/Ubuntu) or dnf-automatic security updates."
                  FI_RISK="Security updates install automatically; services restart when their packages update." ;;
    auditd) FI_CHANGE="Install auditd and add watch rules for identity files, sudoers, sshd config, cron, systemd units and kernel modules."
            FI_RISK="Small disk/CPU overhead for audit logging." ;;
    empty_pw) FI_CHANGE="Lock (passwd -l) every account that has an empty password."; FI_RISK="Those accounts can no longer log in until given a password." ;;
    login_defs) FI_CHANGE="Set PASS_MAX_DAYS 365, PASS_MIN_DAYS 1, PASS_WARN_AGE 14 in /etc/login.defs."; FI_RISK="Applies to newly set passwords only." ;;
    sudo) FI_CHANGE="Add 'Defaults use_pty' and 'Defaults logfile=/var/log/sudo.log' (validated with visudo)."; FI_RISK="None for normal use." ;;
    core_dumps) FI_CHANGE="Add '* hard core 0' to /etc/security/limits.d."; FI_RISK="Crashing programs no longer leave core dumps for debugging." ;;
    legacy_svcs) FI_CHANGE="Stop and disable telnet, rsh, rlogin, rexec, tftp, xinetd and vsftpd."; FI_RISK="Anything still using those protocols stops working." ;;
    optional_svcs) FI_CHANGE="Stop and disable avahi-daemon, cups and rpcbind."; FI_RISK="Printing and .local discovery stop; NFS needs rpcbind - skip this if you use NFS." ;;
    time_sync) FI_CHANGE="Enable NTP time synchronisation (timedatectl set-ntp true)."; FI_RISK="None." ;;
    *) FI_CHANGE=""; FI_RISK="" ;;
  esac
}

if [[ $LIST_ONLY -eq 1 ]]; then
  for id in "${CHECKS[@]}"; do printf "%-45s %-9s %s\n" "$id" "${SEV[$id]}" "${TITLE[$id]}"; done
  exit 0
fi

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
in_list() { [[ ",$2," == *",$1,"* ]]; }
json_esc() { local s="$1"; s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\t'/ }; s=${s//$'\r'/}; printf '%s' "$s"; }
confirm() {
  [[ $ASSUME_YES -eq 1 ]] && return 0
  [[ -r /dev/tty ]] || return 1
  local a; read -r -p "    Apply fix? [y/N] " a < /dev/tty; [[ "$a" =~ ^[Yy] ]]
}

declare -a JSON_ROWS=()
PASS=0; FAIL=0; FIXED=0; NA=0; ERR=0
info "${C_BLU}NetGuard hardening v$VERSION${C_RST} - mode: $MODE - host: $(hostname)"
log "run started only=$ONLY skip=$SKIP"

for id in "${CHECKS[@]}"; do
  [[ -n "$ONLY" ]] && ! in_list "$id" "$ONLY" && continue
  [[ -n "$SKIP" ]] && in_list "$id" "$SKIP" && continue
  fn="${FN[$id]}"; arg="${ARG[$id]}"
  DETAIL=""
  "check_$fn" "$arg"; rc=$?
  status="pass"; fixable=0
  declare -F "fix_$id" >/dev/null && fixfn="fix_$id" || fixfn="fix_$fn"
  declare -F "$fixfn" >/dev/null && fixable=1

  if [[ $rc -eq 2 ]]; then
    status="n/a"; ((NA++))
    info "  ${C_DIM}[ n/a ] $id - $DETAIL${C_RST}"
  elif [[ $rc -eq 0 ]]; then
    ((PASS++))
    info "  ${C_GRN}[ ok  ]${C_RST} $id ${C_DIM}- $DETAIL${C_RST}"
  else
    status="fail"
    info "  ${C_RED}[FAIL ]${C_RST} $id (${SEV[$id]}) - $DETAIL"
    if [[ "$MODE" == "apply" ]]; then
      if [[ $fixable -eq 0 ]]; then
        info "    ${C_YEL}manual fix required${C_RST}"
      elif confirm; then
        out=$("$fixfn" "$arg" 2>&1); frc=$?
        [[ -n "$out" ]] && info "$(sed 's/^/    | /' <<< "$out")"
        DETAIL=""; "check_$fn" "$arg"; rc=$?
        if [[ $frc -eq 0 && $rc -eq 0 ]]; then status="fixed"; ((FIXED++)); info "    ${C_GRN}fixed${C_RST} - $DETAIL"; log "fixed $id"
        else status="error"; ((ERR++)); DETAIL="fix failed: ${out:-$DETAIL}"; info "    ${C_RED}fix failed${C_RST}"; log "fix failed $id: $out"; fi
      fi
    fi
    [[ "$status" == "fail" ]] && ((FAIL++))
  fi
  fix_info "$id" "$fn" "$arg"
  JSON_ROWS+=("{\"id\":\"$(json_esc "$id")\",\"title\":\"$(json_esc "${TITLE[$id]}")\",\"severity\":\"${SEV[$id]}\",\"status\":\"$status\",\"fixable\":$([[ $fixable -eq 1 ]] && echo true || echo false),\"detail\":\"$(json_esc "$DETAIL")\",\"change\":\"$(json_esc "$FI_CHANGE")\",\"risk\":\"$(json_esc "$FI_RISK")\",\"reboot\":$FI_REBOOT}")
done

info ""
info "Summary: ${C_GRN}$PASS passed${C_RST}, ${C_RED}$FAIL failing${C_RST}, $FIXED fixed, $ERR errors, $NA n/a"
[[ $BACKUP_MADE -eq 1 ]] && info "Backups: $BACKUP_DIR  (undo: $0 --restore $BACKUP_DIR)"
[[ "$MODE" == "audit" && $FAIL -gt 0 ]] && info "Run with --apply to fix (you'll be asked per check)."

if [[ -n "$JSON_OUT" ]]; then
  json="{\"tool\":\"netguard-harden\",\"version\":\"$VERSION\",\"os\":\"linux\",\"host\":\"$(hostname)\",\"timestamp\":$(date +%s),\"mode\":\"$MODE\",\"backup_dir\":\"$([[ $BACKUP_MADE -eq 1 ]] && json_esc "$BACKUP_DIR")\",\"results\":[$(IFS=,; echo "${JSON_ROWS[*]}")]}"
  if [[ "$JSON_OUT" == "-" ]]; then echo "$json"; else echo "$json" > "$JSON_OUT"; fi
fi
log "run finished pass=$PASS fail=$FAIL fixed=$FIXED err=$ERR"
[[ $FAIL -eq 0 && $ERR -eq 0 ]]
