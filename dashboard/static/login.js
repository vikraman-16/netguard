/* NetGuard sign-in: password -> (new password) -> (2-factor setup) -> 6-digit code -> dashboard */
"use strict";
const $ = (s) => document.querySelector(s);
let ticket = null;

async function post(path, body) {
  const r = await fetch(location.origin + path, {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-NetGuard": "1" },
    body: JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || "Something went wrong (" + r.status + ")");
  return data;
}

function show(id) {
  document.querySelectorAll(".step").forEach((f) => (f.hidden = f.id !== id));
  msg("");
  const first = $("#" + id + " input:not([type=hidden])");
  if (first) setTimeout(() => first.focus(), 30);
}
function msg(text, ok) {
  const m = $("#msg");
  m.textContent = text;
  m.hidden = !text;
  m.className = "login-msg" + (ok ? " ok" : "");
}
function busy(form, on) { form.querySelectorAll("button, input").forEach((e) => (e.disabled = on)); }

async function next(res) {
  ticket = res.ticket;
  if (res.step === "password") return show("step-password");
  if (res.step === "totp") { $("#t-user").textContent = res.username; return show("step-totp"); }
  if (res.step === "enroll") {
    const e = await post("/api/auth/enroll/start", { ticket });
    $("#e-secret").textContent = e.secret;
    $("#e-uri").href = e.uri;
    return show("step-enroll");
  }
}

function handle(formId, fn) {
  const f = $(formId);
  f.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    busy(f, true);
    try { await fn(); } catch (e) { msg(e.message); } finally { busy(f, false); }
  });
}

handle("#step-login", async () => {
  await next(await post("/api/auth/login", { username: $("#l-user").value, password: $("#l-pass").value }));
  $("#l-pass").value = "";
});
handle("#step-password", async () => {
  if ($("#p-new").value !== $("#p-new2").value) throw new Error("The two passwords don't match.");
  await next(await post("/api/auth/password", { ticket, new_password: $("#p-new").value }));
});
handle("#step-enroll", async () => {
  await post("/api/auth/enroll/finish", { ticket, code: $("#e-code").value });
  location.replace("/");
});
handle("#step-totp", async () => {
  await post("/api/auth/totp", { ticket, code: $("#t-code").value });
  location.replace("/");
});

// invite / reset links: /login#invite=TOKEN or /login#reset=TOKEN (the token never reaches server logs)
let linkToken = null;
handle("#step-invite", async () => {
  if ($("#i-pass").value !== $("#i-pass2").value) throw new Error("The two passwords don't match.");
  const res = await post("/api/invite/accept", {
    token: linkToken, username: $("#i-user").value, display_name: $("#i-name").value, password: $("#i-pass").value,
  });
  history.replaceState(null, "", "/login");
  await next(res);
});

(async function init() {
  const m = location.hash.match(/^#(invite|reset)=([A-Za-z0-9_\-]+)$/);
  if (!m) return show("step-login");
  linkToken = m[2];
  try {
    const info = await post("/api/invite/info", { token: linkToken });
    const scope = info.hosts === "*" ? "all servers" : (info.hosts.length ? info.hosts.join(", ") : "no servers yet");
    if (info.kind === "reset") {
      $("#i-title").textContent = "Reset your sign-in";
      $("#i-info").textContent = `Set a new password for ${info.username}. You'll set up 2-factor again on the next step.`;
      $("#i-user-wrap").hidden = true; $("#i-user").required = false;
      $("#i-name-wrap").hidden = true;
    } else {
      $("#i-info").textContent = `${info.invited_by} invited you to NetGuard as ${info.role} for ${scope}.`;
    }
    show("step-invite");
  } catch (e) {
    show("step-login");
    msg(e.message);
  }
})();
