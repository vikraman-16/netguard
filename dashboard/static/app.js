/* NetGuard dashboard front-end. No dependencies. */
"use strict";

// ---------------------------------------------------------------------------
// Playbooks: what each alert means and how to decide what to do.
// ---------------------------------------------------------------------------
const PLAYBOOK = {
  new_listener: {
    what: "A process started listening on a port that wasn't in this host's baseline. Verified binaries are accepted automatically: on Windows, core processes at their expected path with a valid Microsoft signature, plus trusted publishers; on Linux, files owned by a package whose checksum matches the package database. Allowlisted binaries are accepted on both. So whatever reaches you here was NOT verified as trusted.",
    check: [
      "Look at <i>trust</i> in the evidence. Serious: masquerade, bad signature, modified (Linux binary fails its package checksum), fileless (runs from memory). Worth a look: unsigned / unpackaged / deleted.",
      "Is the process name/path expected (a deploy, new service, package update)?",
      "Is it bound to 0.0.0.0 / :: (reachable from the network) or only 127.0.0.1?",
      "Unknown binaries in /tmp, /dev/shm, %TEMP%, AppData or ProgramData are a strong compromise signal. Check the SHA256 on VirusTotal.",
    ],
    options: "Legit software → <b>Trust process</b> (pins its publisher, or its hash if unsigned, so a swapped binary alerts again). Legit port but don't vouch for the binary → <b>Accept this port only</b>. Unknown → <b>Block inbound port</b>. Malicious → <b>Kill process</b>, then investigate.",
  },
  untrusted_listener: {
    what: "A port that is in the baseline is served by a binary that can't be verified: unsigned or badly signed (Windows), not from any package / failing its package checksum / deleted from disk (Linux), or a commonly-abused tool (powershell, rundll32, bash, nc, socat…).",
    check: [
      "Unsigned (Windows) or unpackaged (Linux: /opt apps, Go binaries, nvm node) is common for self-installed software — check the path and hash.", "<i>deleted</i> on Linux usually means a package upgrade replaced the file: restart the service and it clears.",
      "'bad signature' means the file was modified after signing, or its certificate is untrusted/revoked: treat as suspicious.",
      "A LOLBin (powershell, rundll32, mshta…) holding a listening port is a classic backdoor pattern.",
    ],
    options: "You know it → <b>Trust process</b> (unsigned files get pinned to their SHA256). Not sure → look up the SHA256 on VirusTotal first. Malicious → <b>Kill process</b> and <b>Block inbound port</b>.",
  },
  process_masquerade: {
    what: "A process pretends to be a system process. Windows: a core name (svchost, lsass…) from the wrong folder, without a valid Microsoft signature, or with the wrong parent. Linux: a core daemon (sshd, systemd, cron…) from the wrong path or failing its package checksum, a userland process disguised as a kernel thread ([kworker/0:1]), a fileless (memfd) process, or something running from /tmp or /dev/shm. Both: one-letter look-alike names (scvhost, sshdd…).",
    check: [
      "Genuine svchost/lsass/services only run from C:\\Windows\\System32 and are Microsoft-signed; genuine sshd is /usr/sbin/sshd from the openssh-server package; real kernel threads have no executable.",
      "Look up the SHA256 on VirusTotal.",
      "Check what started it (parent) and its command line.",
    ],
    options: "Almost always malicious → <b>Kill process</b> (NetGuard refuses to kill the genuine binary), block any remote IPs it talks to, then investigate how it got there (Windows: scheduled tasks, services, Run keys; Linux: cron, systemd units, ~/.bashrc, authorized_keys, ld.so.preload). The genuine system process can't be allowlisted or killed.",
  },
  suspicious_port: {
    what: "A connection uses a port commonly associated with reverse shells, IRC botnets or C2 (e.g. 4444, 6667, 1337, 31337).",
    check: [
      "Which process owns the connection? Is it a shell (bash, sh, powershell, cmd, nc)?",
      "Is the remote IP yours (VPN, another server) or an unknown internet host?",
    ],
    options: "Legit app on an odd port → <b>Suppress on this host</b>. Otherwise <b>Kill process</b> and <b>Block IP</b>, then review how it got there.",
  },
  blocklisted_ip: {
    what: "The host is talking to an IP on your blocklist (threat feed / known-bad list).",
    check: ["Which process? Outbound connections from servers to bad IPs often mean malware or a compromised dependency."],
    options: "<b>Block IP</b> immediately, <b>Kill process</b> if unknown. Consider isolating the host.",
  },
  auth_bruteforce: {
    what: "Many failed logins (SSH / RDP / Windows logon) from one source in a short window.",
    check: [
      "Is the source internal (a misconfigured script/service account) or internet?",
      "Which usernames are targeted? root/administrator/admin = generic scanning; real usernames = targeted.",
      "Was there a successful login from the same IP? (see 'login after brute force' alerts)",
    ],
    options: "Internet source → <b>Block IP</b>. Internal → fix the client, then resolve. Recurring → apply hardening (fail2ban, key-only SSH, NLA, account lockout).",
  },
  login_after_bruteforce: {
    what: "A login SUCCEEDED from an IP that was just brute-forcing. Treat as possible account compromise.",
    check: [
      "Confirm with the account owner whether this was them.",
      "Review what the session did: shell history, new users, cron jobs/scheduled tasks, new listeners.",
    ],
    options: "Not legit → <b>Block IP</b>, disable/reset the account, kill its sessions, and investigate. Legit → resolve with a note.",
  },
  port_scan: {
    what: "One remote IP is touching many different local ports, typical of a port scan.",
    check: ["Internet-wide scanners are constant background noise; internal scanners usually aren't."],
    options: "Internet source → <b>Block IP</b> or simply resolve (firewall already drops closed ports). Internal source → find out who's scanning.",
  },
  connection_flood: {
    what: "A single remote IP holds an unusually large number of connections.",
    check: ["Load balancer / proxy / monitoring IPs legitimately do this — suppress those.", "Otherwise could be a DoS, scraper or abuse."],
    options: "Known infrastructure → <b>Suppress on this host</b>. Abuse → <b>Block IP</b>.",
  },
  bandwidth_spike: {
    what: "Network throughput exceeded the configured threshold.",
    check: ["Backups, updates and deploys cause spikes. Sustained outbound traffic at odd hours can mean data exfiltration."],
    options: "Explained → resolve. Unexplained outbound → check top talkers (ss -tnp / Get-NetTCPConnection) and block if needed.",
  },
  resource_pressure: {
    what: "CPU, memory or disk usage is above threshold.",
    check: ["Unexpected sustained 100% CPU is a classic crypto-miner symptom.", "Full disks break logging and services."],
    options: "Fix capacity or the runaway process, then resolve. If a process is unknown, <b>Kill process</b>.",
  },
  hardening_drift: {
    what: "A security hardening check is failing on this host (a setting was never applied or was reverted).",
    check: ["Read the check detail. Some fixes (SSH password auth, legacy TLS, SMB signing) can lock out users or old clients."],
    options: "Safe for this host → <b>Apply hardening fix</b> (backup is taken first). Intentional exception → <b>Suppress on this host</b> with a reason.",
  },
  firewall_disabled: {
    what: "The host firewall is off or has no active profile.",
    check: ["Was it disabled during troubleshooting and never re-enabled?"],
    options: "<b>Apply hardening fix</b> to re-enable it (SSH/RDP are allowed before enabling).",
  },
  defender_disabled: {
    what: "Microsoft Defender real-time protection is off, or signatures are stale.",
    check: ["A 3rd-party AV can legitimately disable Defender. Malware also disables it."],
    options: "No other AV → <b>Apply hardening fix</b>. Other AV present → suppress on this host.",
  },
  agent_offline: {
    what: "The monitoring agent hasn't reported within the configured interval.",
    check: ["Is the host up (ping/console)?", "Is the agent's cron job / scheduled task still present and running?", "Did someone stop it? Attackers often kill monitoring."],
    options: "Restart the agent; this alert auto-resolves when it checks in again.",
  },
};

// ---------------------------------------------------------------------------
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtTime = (t) => (t ? new Date(t * 1000).toLocaleString() : "–");
function ago(t) {
  if (!t) return "–";
  const s = Math.max(0, Date.now() / 1000 - t);
  if (s < 60) return Math.floor(s) + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}

async function api(path, body) {
  const opt = body === undefined ? {} : {
    method: "POST", body: JSON.stringify(body),
    headers: { "Content-Type": "application/json", "X-NetGuard": "1" },
  };
  // location.origin never contains user:pass@, which fetch() refuses
  const r = await fetch(location.origin + path, opt);
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) { location.replace("/login"); throw new Error("Signed out"); }
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function toast(msg, err) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (err ? " err" : "");
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.hidden = true), 3500);
}

const state = { tab: "alerts", alerts: [], selected: new Set(), openAlert: null, hosts: [], me: null, people: null };

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------
$$(".tabs button").forEach((b) => b.addEventListener("click", () => {
  state.tab = b.dataset.tab;
  $$(".tabs button").forEach((x) => x.classList.toggle("active", x === b));
  $$(".panel").forEach((p) => (p.hidden = p.id !== "tab-" + state.tab));
  refresh();
}));

$$(".tile[data-filter]").forEach((t) => t.addEventListener("click", () => {
  $("#f-severity").value = t.dataset.filter;
  $("#f-status").value = "active";
  $('.tabs button[data-tab="alerts"]').click();
}));

["#f-status", "#f-severity", "#f-host"].forEach((s) => $(s).addEventListener("change", loadAlerts));
let qTimer;
$("#f-q").addEventListener("input", () => { clearTimeout(qTimer); qTimer = setTimeout(loadAlerts, 250); });

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
async function loadSummary() {
  const s = await api("/api/summary");
  const sev = s.by_severity;
  $("#t-critical").textContent = sev.critical;
  $("#t-high").textContent = sev.high;
  $("#t-medium").textContent = sev.medium;
  $("#t-low").textContent = sev.low + sev.info;
  $("#t-hosts").textContent = `${s.hosts_online}/${s.hosts_total}`;
  const urgent = sev.critical + sev.high;
  $("#badge-alerts").textContent = urgent || "";
  $("#badge-cmds").textContent = s.pending_commands || "";
  document.title = urgent ? `(${urgent}) NetGuard` : "NetGuard";
  // sparkline
  const v = s.timeline_24h, max = Math.max(1, ...v), w = 240 / v.length;
  $("#spark").innerHTML = v.map((n, i) => {
    const h = Math.max(n ? 3 : 1, (n / max) * 38);
    return `<rect x="${i * w + 1}" y="${40 - h}" width="${w - 2}" height="${h}" rx="1.5" fill="${n ? "var(--accent)" : "var(--border)"}"><title>${n} alert(s), ${23 - i}h ago</title></rect>`;
  }).join("");
  $("#updated").textContent = "updated " + new Date().toLocaleTimeString();
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------
async function loadAlerts() {
  const p = new URLSearchParams({
    status: $("#f-status").value, severity: $("#f-severity").value,
    host: $("#f-host").value, q: $("#f-q").value,
  });
  state.alerts = await api("/api/alerts?" + p);
  const tb = $("#alerts-table tbody");
  tb.innerHTML = state.alerts.map((a) => `
    <tr class="clickable" data-id="${a.id}">
      <td class="cb"><input type="checkbox" data-cb="${a.id}" ${state.selected.has(a.id) ? "checked" : ""} aria-label="Select"></td>
      <td><span class="sev ${esc(a.severity)}">${esc(a.severity)}</span></td>
      <td><div class="alert-title">${esc(a.title)}</div><div class="alert-sub">${esc(a.rule)} · ${esc(shortDetails(a))}</div></td>
      <td>${esc(a.host)}</td>
      <td><span class="status ${esc(a.status)}">${esc(a.status)}</span></td>
      <td class="num">${a.count}×</td>
      <td title="${esc(fmtTime(a.last_seen))}">${ago(a.last_seen)}</td>
    </tr>`).join("");
  $("#alerts-empty").hidden = state.alerts.length > 0;
  updateBulk();
}

function shortDetails(a) {
  const e = a.evidence || {};
  const bits = [e.remote_ip, e.process, e.port && `port ${e.port}`, e.check_id,
    e.trust && !["system", "trusted_signer", "allowlisted"].includes(e.trust) && e.trust.replace(/_/g, " ")].filter(Boolean);
  return bits.length ? bits.join(" · ") : (a.details || "").slice(0, 90);
}

$("#alerts-table tbody").addEventListener("click", (ev) => {
  const cb = ev.target.closest("[data-cb]");
  if (cb) {
    const id = +cb.dataset.cb;
    cb.checked ? state.selected.add(id) : state.selected.delete(id);
    updateBulk();
    return;
  }
  const tr = ev.target.closest("tr[data-id]");
  if (tr) openAlert(+tr.dataset.id);
});
$("#cb-all").addEventListener("change", (e) => {
  state.alerts.forEach((a) => (e.target.checked ? state.selected.add(a.id) : state.selected.delete(a.id)));
  loadAlerts();
});
function updateBulk() {
  $("#bulk").hidden = state.selected.size === 0 || !canAct();
  $("#bulk-n").textContent = `${state.selected.size} selected`;
}
$$("[data-bulk]").forEach((b) => b.addEventListener("click", async () => {
  const status = b.dataset.bulk;
  const res = await confirmBox(`${status === "resolved" ? "Resolve" : "Acknowledge"} ${state.selected.size} alert(s)?`, "");
  if (!res) return;
  try {
    await api("/api/alerts/bulk", { ids: [...state.selected], status, note: res.note });
    state.selected.clear();
    toast("Updated");
    refresh();
  } catch (e) { toast(e.message, true); }
}));

// ---------------------------------------------------------------------------
// Alert drawer
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Actions: what each one does, in plain words (shown before you click)
// ---------------------------------------------------------------------------
const ACTION_INFO = {
  harden_fix: { group: "fix", tone: "primary",
    effect: (a) => `${(a.evidence || {}).fix_changes || "Applies the recommended setting."} A backup is taken first, and you can undo it from "Actions taken" below.` },
  run_hardening_audit: { group: "fix", tone: "",
    effect: () => "Re-checks this host's settings now instead of waiting for the next scheduled audit." },
  quarantine_file: { group: "contain", tone: "danger",
    effect: (a, s) => `Stops every process running ${s.params.path} and moves the file into NetGuard's quarantine folder so it can't run again. You can restore it later.` },
  kill_process: { group: "contain", tone: "danger",
    effect: (a, s) => `Ends ${s.params.name} (pid ${s.params.pid}) right now. If a service or scheduled task starts it again it will come back; use Quarantine for that.` },
  block_ip: { group: "contain", tone: "danger",
    effect: (a, s) => s.params.hours
      ? `The firewall on ${a.host} drops all traffic to and from ${s.params.ip} for ${s.params.hours} hours, then removes the block automatically.`
      : `The firewall on ${a.host} drops all traffic to and from ${s.params.ip} until you undo it.` },
  block_port: { group: "contain", tone: "danger",
    effect: (a, s) => `Other machines can no longer connect to ${String(s.params.protocol).toUpperCase()} port ${s.params.port} on ${a.host}. Programs on the host itself keep working.` },
  allow_process: { group: "accept", tone: "",
    effect: (a, s) => `Marks ${s.params.path} as trusted on ${a.host}, pinned to its current publisher (or exact file hash if unsigned). If the file is ever swapped, it alerts again.` },
  accept_listener: { group: "accept", tone: "",
    effect: (a, s) => `Treats ${String(s.params.protocol).toUpperCase()} port ${s.params.port} as normal for ${a.host}. The program behind it is still verified every minute.` },
};
const GROUPS = [["fix", "Fix the cause"], ["contain", "Contain the threat"], ["accept", "It's legitimate"]];
// Alerts that describe something still true on the host: resolving alone doesn't make them go away
const CONDITION_RULES = new Set(["hardening_drift", "untrusted_listener", "firewall_disabled", "defender_disabled",
  "new_listener", "process_masquerade", "resource_pressure", "bandwidth_spike"]);
const ACTION_NAMES = {
  harden_fix: "Applied hardening fix", harden_restore: "Undid hardening fix", quarantine_file: "Quarantined file",
  restore_quarantine: "Restored file from quarantine", kill_process: "Killed process", block_ip: "Blocked IP",
  unblock_ip: "Unblocked IP", block_port: "Blocked port", unblock_port: "Unblocked port", allow_process: "Trusted program",
  accept_listener: "Accepted port", run_hardening_audit: "Ran hardening audit",
};

function expandSuggestions(a) {
  const out = [];
  for (const s of a.suggested || []) {
    if (s.action === "block_ip") {
      out.push({ ...s, params: { ...s.params, hours: 24 }, label: `Block ${s.params.ip} for 24 hours` });
      out.push({ ...s, label: `Block ${s.params.ip} permanently` });
    } else out.push(s);
  }
  const ip = (a.evidence || {}).remote_ip;
  if (ip && !out.some((s) => s.action === "block_ip")) {
    out.push({ action: "block_ip", params: { ip, hours: 24 }, label: `Block ${ip} for 24 hours` });
    out.push({ action: "block_ip", params: { ip }, label: `Block ${ip} permanently` });
  }
  return out;
}

function actionBlocked(a, action) {
  const caps = a.capabilities || {};
  if (caps.supported && caps.supported.length && !caps.supported.includes(action))
    return "The agent on this host is an older version without this action. Re-run setup to update it.";
  if (Array.isArray(caps.allowed_actions) && !caps.allowed_actions.includes(action))
    return `Turned off on ${a.host} (safe mode). Re-run setup and choose full control to allow it.`;
  return "";
}

function describeParams(c) {
  let p = c.params;
  try { p = typeof p === "string" ? JSON.parse(p) : p; } catch (e) { return String(c.params); }
  return Object.entries(p || {}).map(([k, v]) => `${k}=${v}`).join(" ");
}

async function openAlert(id) {
  const keepScroll = state.openAlert === id && !$("#drawer").hidden ? $("#drawer").scrollTop : null;
  state.openAlert = id;
  const a = await api("/api/alerts/" + id);
  const g = PLAYBOOK[a.rule] || { what: a.details, check: [], options: "" };
  const ev = a.evidence || {};
  const hidden = new Set(["fix_changes", "fix_risk", "fix_reboot"]);
  const evOrder = ["trust", "trust_reason", "signer", "signature", "exe", "sha256", "current"];
  const evEntries = Object.entries(ev).filter(([k]) => !hidden.has(k)).sort(([x], [y]) => {
    const ix = evOrder.indexOf(x), iy = evOrder.indexOf(y);
    return (ix < 0 ? 99 : ix) - (iy < 0 ? 99 : iy);
  });
  const evRows = evEntries.map(([k, v]) => {
    let cell;
    if (k === "trust") cell = `<span class="trust ${esc(v)}">${esc(String(v).replace(/_/g, " "))}</span>`;
    else if (k === "sha256" && /^[A-Fa-f0-9]{64}$/.test(v))
      cell = `<span class="mono">${esc(v)}</span> <a href="https://www.virustotal.com/gui/file/${esc(v)}" target="_blank" rel="noopener noreferrer">VirusTotal ↗</a>`;
    else if (typeof v === "object") cell = `<pre class="mono">${esc(JSON.stringify(v, null, 2))}</pre>`;
    else cell = `<span class="mono">${esc(v)}</span>`;
    return `<tr><td>${esc(k.replace(/_/g, " "))}</td><td>${cell}</td></tr>`;
  }).join("");
  const active = a.status === "open" || a.status === "acknowledged";
  const isCondition = CONDITION_RULES.has(a.rule);

  // options grouped by intent
  const opts = expandSuggestions(a).filter((s) => ACTION_INFO[s.action]);
  state.drawerOpts = opts;
  const groupHtml = GROUPS.map(([gid, gtitle]) => {
    const items = opts.map((s, i) => ({ s, i })).filter(({ s }) => ACTION_INFO[s.action].group === gid);
    let extra = "";
    if (gid === "accept" && isCondition)
      extra += `<div class="opt"><button class="btn" data-accept-risk="1">Accept the risk</button>
        <div class="opt-text">You decided this is OK for ${esc(a.host)} (for example a home PC that hosts no services). It stops alerting for this host; a reason is required and kept in the audit log. You can undo it under Suppressions.</div></div>`;
    if (!items.length && !extra) return "";
    return `<div class="opt-group"><div class="opt-title">${gtitle}</div>
      ${items.map(({ s, i }) => {
        const info = ACTION_INFO[s.action];
        const why = actionBlocked(a, s.action);
        return `<div class="opt ${why ? "blocked" : ""}">
          <button class="btn ${why ? "" : info.tone}" data-opt="${i}" ${why ? "disabled" : ""}>${esc(s.label)}</button>
          <div class="opt-text">${esc(info.effect(a, s))}${why ? `<div class="opt-why">${esc(why)}</div>` : ""}</div></div>`;
      }).join("")}${extra}</div>`;
  }).join("");

  const fixBox = ev.fix_changes ? `
    <div class="fixbox">
      <div><b>If you apply the fix:</b> ${esc(ev.fix_changes)}</div>
      ${ev.fix_risk ? `<div><b>Could affect:</b> ${esc(ev.fix_risk)}</div>` : ""}
      ${ev.fix_reboot ? `<div><b>Reboot needed:</b> ${esc(ev.fix_reboot)}</div>` : ""}
    </div>` : "";

  $("#drawer-body").innerHTML = `
    <div class="meta"><span class="sev ${esc(a.severity)}">${esc(a.severity)}</span>
      <span class="status ${esc(a.status)}">${esc(a.status)}</span>
      <span>${esc(a.host)}</span><span>· ${esc(a.rule)}</span></div>
    <h2>${esc(a.title)}</h2>
    <div class="meta">First seen ${esc(fmtTime(a.first_seen))} · last ${ago(a.last_seen)} · ${a.count} occurrence(s)</div>
    ${a.details ? `<p>${esc(a.details)}</p>` : ""}

    <h3>What this means / how to decide</h3>
    <div class="guide">
      <p>${esc(g.what)}</p>
      ${g.check.length ? `<b>Check:</b><ul>${g.check.map((c) => `<li>${c}</li>`).join("")}</ul>` : ""}
    </div>
    ${fixBox}

    <h3>Evidence</h3>
    <div class="evidence">${evRows ? `<table>${evRows}</table>` : '<span class="muted">none</span>'}</div>

    ${active && !canAct() ? `<div class="readonly-note">You have read-only access (${esc(state.me ? state.me.role : "viewer")}). Ask an admin or owner to act on this alert.</div>` : ""}
    ${active && canAct() ? `<h3>What do you want to do?</h3>${groupHtml}
      <div class="opt-group"><div class="opt-title">Not a real problem</div>
        <div class="opt"><button class="btn" data-sup="1">False positive…</button>
          <div class="opt-text">NetGuard got this wrong. Hide it on this host or everywhere, for a while or forever.</div></div>
      </div>` : ""}

    <div class="track" ${canAct() ? "" : "hidden"}>
      ${a.status === "open" ? '<button class="btn small" data-st="acknowledged">I\'m looking into it</button>' : ""}
      ${active ? `<button class="btn small" data-st="resolved">Mark resolved</button>` : '<button class="btn small" data-st="open">Reopen</button>'}
      ${active && isCondition ? '<span class="muted small">This alert describes something that is still true. Resolving only hides it until the next check, so fix or accept it instead.</span>' : ""}
    </div>
    ${a.note ? `<p class="muted small">Note: ${esc(a.note)}</p>` : ""}

    ${a.commands.length ? `<h3>Actions taken</h3>
      <ul class="timeline">${a.commands.map((c) => `<li>
        <span class="status ${esc(c.status)}">${esc(c.status)}</span>
        <b>${esc(ACTION_NAMES[c.action] || c.action)}</b> <span class="mono muted">${esc(describeParams(c))}</span>
        <span class="muted">by ${esc(c.created_by)} ${ago(c.created_at)}</span>
        ${c.status === "pending" ? `<button class="btn small ghost" data-cancel="${c.id}">Cancel</button>` : ""}
        ${c.status === "done" && c.undo ? `<button class="btn small" data-undo="${c.id}" title="${esc(c.undo.label)}">↶ ${esc(c.undo.label)}</button>` : ""}
        ${c.output ? `<details><summary class="muted small">Output</summary><pre class="mono evidence">${esc(c.output)}</pre></details>` : ""}
      </li>`).join("")}</ul>` : ""}

    <h3>History</h3>
    <ul class="timeline">${a.history.map((h) => `<li><span class="muted">${esc(fmtTime(h.ts))}</span> · <b>${esc(h.user)}</b> ${esc(h.action)} <span class="muted">${esc(h.detail)}</span></li>`).join("") || '<li class="muted">No actions yet.</li>'}</ul>

    ${a.related.length ? `<h3>Earlier occurrences on ${esc(a.host)}</h3>
      <ul class="timeline">${a.related.map((r) => `<li><a href="#" data-open="${r.id}">#${r.id}</a> ${esc(r.title)} · <span class="status ${esc(r.status)}">${esc(r.status)}</span> · ${ago(r.last_seen)}</li>`).join("")}</ul>` : ""}
  `;

  const body = $("#drawer-body");
  $$("[data-st]", body).forEach((b) => b.addEventListener("click", () => setStatus(a, b.dataset.st)));
  $$("[data-opt]", body).forEach((b) => b.addEventListener("click", () => queueAction(a, state.drawerOpts[+b.dataset.opt])));
  $$("[data-sup]", body).forEach((b) => b.addEventListener("click", () => suppress(a)));
  $$("[data-accept-risk]", body).forEach((b) => b.addEventListener("click", () => acceptRisk(a)));
  $$("[data-undo]", body).forEach((b) => b.addEventListener("click", () => undoCommand(+b.dataset.undo, b.title, a.id)));
  $$("[data-cancel]", body).forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/commands/${b.dataset.cancel}/cancel`, {}); openAlert(a.id);
  }));
  $$("[data-open]", body).forEach((l) => l.addEventListener("click", (e) => { e.preventDefault(); openAlert(+l.dataset.open); }));

  $("#drawer").hidden = false;
  $("#scrim").hidden = false;
  if (keepScroll != null) $("#drawer").scrollTop = keepScroll;
}

function closeDrawer() {
  state.openAlert = null;
  $("#drawer").hidden = true;
  $("#scrim").hidden = true;
}
$("#drawer-close").addEventListener("click", closeDrawer);
$("#scrim").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("#confirm").open) closeDrawer(); });

async function setStatus(a, status) {
  const label = { acknowledged: "Mark as being looked into", resolved: "Mark resolved", open: "Reopen" }[status];
  const res = await confirmBox(`${label}: alert #${a.id}?`,
    status === "resolved" && CONDITION_RULES.has(a.rule)
      ? "This alert describes something that is still true on the host. Resolving only hides it, and it comes back at the next check. To make it go away for good, fix it or accept the risk."
      : status === "resolved" ? "Records that you've dealt with it." : "");
  if (!res) return;
  try {
    await api(`/api/alerts/${a.id}/status`, { status, note: res.note });
    toast("Updated");
    refresh(); openAlert(a.id);
  } catch (e) { toast(e.message, true); }
}

async function queueAction(a, s) {
  const info = ACTION_INFO[s.action];
  const risk = s.action === "harden_fix" && (a.evidence || {}).fix_risk ? ` Could affect: ${(a.evidence || {}).fix_risk}` : "";
  const res = await confirmBox(`${s.label}?`, `${info ? info.effect(a, s) : ""}${risk} Runs on ${a.host} within about a minute.`, "", info && info.tone === "danger");
  if (!res) return;
  try {
    await api(`/api/alerts/${a.id}/action`, { action: s.action, params: s.params, note: res.note });
    toast("Sent. The result appears under \"Actions taken\" within about a minute.");
    refresh(); openAlert(a.id);
  } catch (e) { toast(e.message, true); }
}

async function acceptRisk(a) {
  const res = await confirmBox(`Accept the risk on ${a.host}?`,
    "This alert stops appearing for this host. Write down why. It's saved in the audit log, and you can remove it later under Suppressions.");
  if (!res) return;
  if (!res.note.trim()) { toast("Please give a reason for accepting the risk.", true); return; }
  try {
    await api(`/api/alerts/${a.id}/action`, { action: "suppress", scope: "fingerprint_host", days: null, note: "risk accepted: " + res.note });
    toast("Risk accepted");
    refresh(); openAlert(a.id);
  } catch (e) { toast(e.message, true); }
}

async function undoCommand(cid, label, alertId) {
  const res = await confirmBox(`${label}?`, "Reverses the earlier action on the host within about a minute. The alert is reopened so you can decide again.");
  if (!res) return;
  try {
    await api(`/api/commands/${cid}/undo`, { note: res.note });
    toast("Undo sent");
    refresh(); if (alertId) openAlert(alertId);
  } catch (e) { toast(e.message, true); }
}

async function suppress(a) {
  const extra = `
    <label class="note">Hide
      <select id="sup-scope">
        <option value="fingerprint_host">This exact alert on ${esc(a.host)}</option>
        <option value="rule_host">All "${esc(a.rule)}" alerts on ${esc(a.host)}</option>
        ${isOwner() ? `<option value="fingerprint_all">This exact alert on every host</option>
        <option value="rule_all">All "${esc(a.rule)}" alerts everywhere</option>` : ""}
      </select></label>
    <label class="note">For
      <select id="sup-days"><option value="1">1 day</option><option value="7">7 days</option><option value="30" selected>30 days</option><option value="">Forever</option></select></label>`;
  const res = await confirmBox("Mark as false positive", "Matching alerts are dropped when they arrive. Say why, so you remember later.", extra);
  if (!res) return;
  try {
    await api(`/api/alerts/${a.id}/action`, { action: "suppress", scope: res.scope, days: res.days || null, note: "false positive: " + res.note });
    toast("Hidden");
    refresh(); openAlert(a.id);
  } catch (e) { toast(e.message, true); }
}

function confirmBox(title, text, extraHtml = "", danger = false) {
  const d = $("#confirm");
  $("#confirm-title").textContent = title;
  $("#confirm-text").textContent = text;
  $("#confirm-extra").innerHTML = extraHtml;
  $("#confirm-note").value = "";
  $("#confirm-ok").className = "btn " + (danger ? "danger" : "primary");
  d.showModal();
  return new Promise((resolve) => {
    d.addEventListener("close", function h() {
      d.removeEventListener("close", h);
      if (d.returnValue !== "ok") return resolve(null);
      resolve({
        note: $("#confirm-note").value,
        scope: $("#sup-scope")?.value, days: $("#sup-days")?.value,
      });
    });
  });
}

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------
function bar(pct) {
  if (pct == null) return "";
  const cls = pct >= 90 ? "bad" : pct >= 75 ? "warn" : "";
  return `<div class="bar"><i class="${cls}" style="width:${Math.min(100, pct)}%"></i></div>`;
}
async function loadHosts() {
  state.hosts = await api("/api/hosts");
  // host filter dropdown
  const sel = $("#f-host"), cur = sel.value;
  sel.innerHTML = '<option value="">All hosts</option>' + state.hosts.map((h) => `<option ${h.name === cur ? "selected" : ""}>${esc(h.name)}</option>`).join("");
  if (state.tab !== "hosts") return;
  $("#host-grid").innerHTML = state.hosts.map((h) => {
    const m = h.metrics || {}, hd = h.hardening || {};
    const oa = h.open_alerts || {};
    const alertsTxt = ["critical", "high", "medium", "low"].filter((s) => oa[s]).map((s) => `<span class="sev ${s}">${oa[s]} ${s}</span>`).join(" ") || '<span class="muted">none</span>';
    return `<div class="host">
      <h4><span class="dot ${h.online ? "on" : ""}"></span>${esc(h.name)}</h4>
      <div class="muted small">${esc(h.os)} · ${esc(h.ip)} · agent ${esc(h.agent_version)} · ${h.online ? "online" : "OFFLINE"} (${ago(h.last_seen)})</div>
      <dl class="kv">
        <dt>Open alerts</dt><dd>${alertsTxt}</dd>
        <dt>CPU</dt><dd>${m.cpu_pct ?? "–"}% ${bar(m.cpu_pct)}</dd>
        <dt>Memory</dt><dd>${m.mem_pct ?? "–"}% ${bar(m.mem_pct)}</dd>
        <dt>Disk (max)</dt><dd>${m.disk_pct ?? "–"}% ${bar(m.disk_pct)}</dd>
        <dt>Network</dt><dd>↓ ${m.rx_mbps ?? "–"} / ↑ ${m.tx_mbps ?? "–"} Mbps</dd>
        <dt>Connections</dt><dd>${m.established ?? "–"} established · ${m.listening ?? "–"} listening</dd>
        <dt>Hardening</dt><dd>${hd.total ? `${hd.passed}/${hd.total} checks pass ${bar(Math.round(100 * hd.passed / hd.total))}<span class="muted small">audited ${ago(hd.ts)}</span>` : '<span class="muted">not audited yet</span>'}</dd>
      </dl>
      <div class="acts">
        <button class="btn small" data-hfilter="${esc(h.name)}">View alerts</button>
        ${canAct() ? `<button class="btn small" data-haudit="${esc(h.name)}">Run hardening audit</button>
        <button class="btn small" data-hblock="${esc(h.name)}">Block an IP…</button>` : ""}
      </div>
    </div>`;
  }).join("") || '<div class="empty">No hosts have checked in yet. Install an agent (see README).</div>';

  $$("[data-hfilter]").forEach((b) => b.addEventListener("click", () => {
    $("#f-host").value = b.dataset.hfilter; $('.tabs button[data-tab="alerts"]').click();
  }));
  $$("[data-haudit]").forEach((b) => b.addEventListener("click", () => hostAction(b.dataset.haudit, "run_hardening_audit", {}, "Run hardening audit")));
  $$("[data-hblock]").forEach((b) => b.addEventListener("click", async () => {
    const res = await confirmBox(`Block an IP on ${b.dataset.hblock}`, "Adds an inbound+outbound firewall block on the host.",
      '<label class="note">IP or CIDR<input id="hb-ip" class="field" placeholder="203.0.113.7"></label>', true);
    if (!res) return;
    hostAction(b.dataset.hblock, "block_ip", { ip: $("#hb-ip").value.trim() }, null, res.note);
  }));
}
async function hostAction(host, action, params, confirmTitle, note) {
  if (confirmTitle && !(await confirmBox(confirmTitle + ` on ${host}?`, "Runs at the agent's next check-in."))) return;
  try {
    await api(`/api/hosts/${encodeURIComponent(host)}/action`, { action, params, note });
    toast("Queued");
    refresh();
  } catch (e) { toast(e.message, true); }
}

// ---------------------------------------------------------------------------
// Commands / suppressions / audit
// ---------------------------------------------------------------------------
async function loadCommands() {
  const rows = await api("/api/commands");
  $("#cmd-table tbody").innerHTML = rows.map((c) => `<tr>
    <td>${c.id}</td><td>${esc(c.host)}</td><td><b>${esc(ACTION_NAMES[c.action] || c.action)}</b>${c.alert_id ? ` <a href="#" data-open="${c.alert_id}">#${c.alert_id}</a>` : ""}</td>
    <td class="mono">${esc(c.params)}</td><td><span class="status ${esc(c.status)}">${esc(c.status)}</span></td>
    <td>${esc(c.created_by)}</td><td title="${esc(fmtTime(c.created_at))}">${ago(c.created_at)}</td>
    <td class="out mono">${esc(c.output)}</td>
    <td>${c.status === "pending" ? `<button class="btn small" data-cancel="${c.id}">Cancel</button>` : ""}${c.status === "done" && c.undo ? `<button class="btn small" data-undo="${c.id}" title="${esc(c.undo.label)}">↶ Undo</button>` : ""}</td></tr>`).join("")
    || '<tr><td colspan="9" class="empty">No remediation actions yet.</td></tr>';
  $$("#cmd-table [data-undo]").forEach((b) => b.addEventListener("click", () => undoCommand(+b.dataset.undo, b.title, null).then(loadCommands)));
  $$("#cmd-table [data-cancel]").forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/commands/${b.dataset.cancel}/cancel`, {}); toast("Cancelled"); loadCommands();
  }));
  $$("#cmd-table [data-open]").forEach((l) => l.addEventListener("click", (e) => { e.preventDefault(); openAlert(+l.dataset.open); }));
}
async function loadSuppressions() {
  const rows = await api("/api/suppressions");
  $("#sup-table tbody").innerHTML = rows.map((s) => `<tr>
    <td>${s.id}</td><td>${esc(s.rule)}</td><td>${esc(s.host || "all hosts")}</td><td class="mono">${esc(s.fingerprint || "(whole rule)")}</td>
    <td>${esc(s.reason)}</td><td>${esc(s.created_by)}</td><td>${s.expires_at ? esc(fmtTime(s.expires_at)) : "never"}</td>
    <td><button class="btn small" data-del="${s.id}">Delete</button></td></tr>`).join("")
    || '<tr><td colspan="8" class="empty">No suppressions.</td></tr>';
  $$("#sup-table [data-del]").forEach((b) => b.addEventListener("click", async () => {
    if (!(await confirmBox("Delete suppression?", "Matching alerts will be raised again."))) return;
    await api(`/api/suppressions/${b.dataset.del}/delete`, {}); toast("Deleted"); loadSuppressions();
  }));
}
async function loadAudit() {
  const rows = await api("/api/audit");
  $("#audit-table tbody").innerHTML = rows.map((r) => `<tr>
    <td>${esc(fmtTime(r.ts))}</td><td>${esc(r.user)}</td><td>${esc(r.host || "")}</td>
    <td>${r.alert_id ? `<a href="#" data-open="${r.alert_id}">#${r.alert_id}</a>` : ""}</td>
    <td>${esc(r.action)}</td><td class="out">${esc(r.detail)}</td></tr>`).join("");
  $$("#audit-table [data-open]").forEach((l) => l.addEventListener("click", (e) => { e.preventDefault(); openAlert(+l.dataset.open); }));
}

// ---------------------------------------------------------------------------
// Signed-in user, user menu, people management
// ---------------------------------------------------------------------------
const ROLE_HELP = {
  owner: "Everything, including inviting and removing people",
  admin: "View and act on alerts (fix, quarantine, block, undo, hide)",
  viewer: "Read-only: can look at alerts and servers, can't change anything",
};
function canAct() { return state.me && (state.me.role === "admin" || state.me.role === "owner"); }
function isOwner() { return state.me && state.me.role === "owner"; }
function deviceName(ua) {
  ua = ua || "";
  const os = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "Unknown";
  const br = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "browser";
  return `${br} on ${os}`;
}
function serversText(h) { return h === "*" ? "All servers" : (h && h.length ? h.join(", ") : "None yet"); }

async function loadMe() {
  state.me = await api("/api/me");
  $("#me-name").textContent = state.me.display_name || state.me.username;
  $("#me-role").textContent = state.me.role;
  $("#me-role").className = "role " + state.me.role;
  $("#me-who").innerHTML = `<b>${esc(state.me.username)}</b><br><span class="muted">${esc(ROLE_HELP[state.me.role])}</span><br><span class="muted">${esc(serversText(state.me.hosts))}</span>`;
  $("#tab-btn-people").hidden = !isOwner();
  document.body.classList.toggle("readonly", !canAct());
}

$("#usermenu-btn").addEventListener("click", (e) => { e.stopPropagation(); $("#usermenu-list").hidden = !$("#usermenu-list").hidden; });
document.addEventListener("click", () => ($("#usermenu-list").hidden = true));
$$("[data-menu]").forEach((b) => b.addEventListener("click", async () => {
  $("#usermenu-list").hidden = true;
  const m = b.dataset.menu;
  if (m === "logout") {
    await api("/api/auth/logout", {}).catch(() => {});
    location.replace("/login");
  } else if (m === "password") {
    const res = await confirmBox("Change your password", "At least 12 characters.",
      `<label class="note">Current password<input id="cp-cur" type="password" class="field" autocomplete="current-password"></label>
       <label class="note">New password<input id="cp-new" type="password" class="field" autocomplete="new-password"></label>
       <label class="note">Repeat new password<input id="cp-new2" type="password" class="field" autocomplete="new-password"></label>`);
    if (!res) return;
    if ($("#cp-new").value !== $("#cp-new2").value) return toast("The new passwords don't match.", true);
    try { await api("/api/me/password", { current: $("#cp-cur").value, new: $("#cp-new").value }); toast("Password changed"); }
    catch (e) { toast(e.message, true); }
    finally { ["#cp-cur", "#cp-new", "#cp-new2"].forEach((s) => ($(s).value = "")); }
  } else if (m === "devices") {
    const rows = await api("/api/sessions");
    const mine = rows.filter((r) => r.user_id === state.me.id);
    await confirmBox("Your signed-in devices", "Sign out any device you don't recognise. You stay signed in on this one.",
      `<ul class="timeline">${mine.map((r) => `<li>${esc(deviceName(r.user_agent))} · ${esc(r.ip)} · active ${ago(r.last_seen)}
        <button type="button" class="btn small" data-revoke="${r.id}">Sign out</button></li>`).join("")}</ul>`);
  }
}));
document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-revoke]");
  if (!b) return;
  e.preventDefault();
  try { await api(`/api/sessions/${b.dataset.revoke}/revoke`, {}); b.closest("li, tr").remove(); toast("Signed out that device"); }
  catch (err) { toast(err.message, true); }
});

function hostPicker(selected, allHosts) {
  const all = selected === "*";
  return `<label class="note"><span><input type="radio" name="hp-mode" value="all" ${all ? "checked" : ""}> All servers (including ones added later)</span></label>
    <label class="note"><span><input type="radio" name="hp-mode" value="some" ${all ? "" : "checked"}> Only these servers:</span></label>
    <div class="hostpick">${allHosts.map((h) => `<label><input type="checkbox" class="hp-host" value="${esc(h)}" ${!all && selected.includes(h) ? "checked" : ""}> ${esc(h)}</label>`).join("") || '<span class="muted small">No servers have reported yet.</span>'}</div>`;
}
function readHostPicker() {
  const mode = document.querySelector('input[name="hp-mode"]:checked');
  if (!mode || mode.value === "all") return "*";
  return $$(".hp-host").filter((c) => c.checked).map((c) => c.value);
}
function roleSelect(cur) {
  return `<label class="note">Role<select id="pp-role">${["viewer", "admin", "owner"].map((r) =>
    `<option value="${r}" ${r === cur ? "selected" : ""}>${r} — ${ROLE_HELP[r]}</option>`).join("")}</select></label>`;
}

async function showLink(title, path, hours, who) {
  const url = location.origin + path;
  await confirmBox(title, `Send this link to ${who} privately (not in a public channel). It works once and expires in ${hours} hours. They'll choose a password and set up 2-factor.`,
    `<div class="linkbox"><input id="lk" class="field" readonly value="${esc(url)}"><button type="button" class="btn" id="lk-copy">Copy</button></div>
     ${/^http:\/\/(127\.0\.0\.1|localhost)/.test(url) ? '<p class="small" style="color:var(--medium)">This link uses the local address, so it only works on this PC. For other people, open the dashboard through its Tailscale address first, then create the link.</p>' : ""}`);
}
document.addEventListener("click", async (e) => {
  if (e.target.id !== "lk-copy") return;
  e.preventDefault();
  try { await navigator.clipboard.writeText($("#lk").value); toast("Link copied"); } catch (err) { $("#lk").select(); }
});

$("#invite-btn").addEventListener("click", async () => {
  const data = await api("/api/users");
  const res = await confirmBox("Invite someone", "Choose what they can do and which servers they can see.",
    roleSelect("admin") + hostPicker("*", data.hosts));
  if (!res) return;
  try {
    const r = await api("/api/users/invite", { role: $("#pp-role").value, hosts: readHostPicker(), note: res.note });
    await showLink("Invite link ready", r.link_path, r.expires_hours, "the person you're inviting");
    loadPeople();
  } catch (err) { toast(err.message, true); }
});

async function loadPeople() {
  if (!isOwner()) return;
  const data = await api("/api/users");
  state.people = data;
  $("#people-table tbody").innerHTML = data.users.map((u) => `<tr>
    <td><b>${esc(u.display_name || u.username)}</b><div class="muted small">${esc(u.username)}${u.id === state.me.id ? " (you)" : ""}</div></td>
    <td><span class="role ${esc(u.role)}">${esc(u.role)}</span></td>
    <td>${esc(serversText(u.hosts))}</td>
    <td>${u.totp_enabled ? '<span class="status resolved">on</span>' : '<span class="status open">not set up</span>'}</td>
    <td>${u.last_login ? ago(u.last_login) : '<span class="muted">never</span>'}</td>
    <td>${u.disabled ? '<span class="status failed">disabled</span>' : u.locked ? '<span class="status open">locked 15 min</span>' : '<span class="status resolved">active</span>'}</td>
    <td style="white-space:nowrap">
      <button class="btn small" data-pedit="${u.id}">Edit</button>
      <button class="btn small" data-preset="${u.id}" title="New password + 2-factor (lost phone, forgot password)">Reset sign-in</button>
      ${u.id === state.me.id ? "" : `<button class="btn small" data-pdisable="${u.id}">${u.disabled ? "Enable" : "Disable"}</button>
      <button class="btn small" data-pdelete="${u.id}">Remove</button>`}
    </td></tr>`).join("");
  const sessions = await api("/api/sessions");
  $("#sessions-table tbody").innerHTML = sessions.map((s) => `<tr>
    <td>${esc(s.username)}</td><td>${esc(deviceName(s.user_agent))}</td><td class="mono">${esc(s.ip)}</td>
    <td>${ago(s.created_at)}</td><td>${ago(s.last_seen)}</td>
    <td><button class="btn small" data-revoke="${s.id}">Sign out</button></td></tr>`).join("")
    || '<tr><td colspan="6" class="empty">Nobody is signed in.</td></tr>';
}

$("#people-table").addEventListener("click", async (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  const id = +(b.dataset.pedit || b.dataset.preset || b.dataset.pdisable || b.dataset.pdelete);
  const u = state.people.users.find((x) => x.id === id);
  try {
    if (b.dataset.pedit) {
      const res = await confirmBox(`Edit ${u.username}`, "Changes apply immediately.", roleSelect(u.role) + hostPicker(u.hosts, state.people.hosts));
      if (!res) return;
      await api(`/api/users/${id}/update`, { role: $("#pp-role").value, hosts: readHostPicker(), disabled: u.disabled });
      toast("Saved");
    } else if (b.dataset.preset) {
      if (!(await confirmBox(`Reset sign-in for ${u.username}?`, "Creates a one-time link. When they open it they choose a new password and set up 2-factor again. All their devices are signed out when they use it."))) return;
      const r = await api(`/api/users/${id}/reset`, {});
      await showLink("Reset link ready", r.link_path, r.expires_hours, u.username);
    } else if (b.dataset.pdisable) {
      const dis = !u.disabled;
      if (!(await confirmBox(`${dis ? "Disable" : "Enable"} ${u.username}?`, dis ? "They are signed out everywhere and can't sign in until enabled again." : "They can sign in again."))) return;
      await api(`/api/users/${id}/update`, { role: u.role, hosts: u.hosts, disabled: dis });
      toast(dis ? "Disabled" : "Enabled");
    } else if (b.dataset.pdelete) {
      if (!(await confirmBox(`Remove ${u.username}?`, "Deletes the account and signs them out everywhere. Their past actions stay in the audit log.", "", true))) return;
      await api(`/api/users/${id}/delete`, {});
      toast("Removed");
    }
    loadPeople();
  } catch (err) { toast(err.message, true); }
});

// ---------------------------------------------------------------------------
async function refresh() {
  try {
    await loadSummary();
    await loadHosts();
    if (state.tab === "alerts") await loadAlerts();
    if (state.tab === "commands") await loadCommands();
    if (state.tab === "suppressions") await loadSuppressions();
    if (state.tab === "audit") await loadAudit();
    if (state.tab === "people") await loadPeople();
  } catch (e) { toast("Refresh failed: " + e.message, true); }
}
setInterval(() => {
  if ($("#autorefresh").checked && !$("#confirm").open) {
    refresh();
    if (state.openAlert) openAlert(state.openAlert).catch(() => {});
  }
}, 10000);
loadMe().then(refresh).catch((e) => toast(e.message, true));
