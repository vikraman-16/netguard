"""
NetGuard accounts: users, roles, per-server access, sessions, TOTP 2-factor, invites and lockouts.
Standard library only.

Roles
  owner  - everything, including managing people and global suppressions
  admin  - view + act (resolve, remediate, undo, suppress) on the servers they are given
  viewer - read-only on the servers they are given
Every account must enrol a TOTP authenticator (Google/Microsoft Authenticator, 1Password, Bitwarden...).
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import threading
import time
from urllib.parse import quote

ROLES = ("owner", "admin", "viewer")
ROLE_RANK = {"viewer": 1, "admin": 2, "owner": 3}
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
PBKDF2_ITER = 600000
SESSION_IDLE = 8 * 3600          # sign out after 8 h without activity
SESSION_MAX = 7 * 24 * 3600      # and at most after 7 days
TICKET_TTL = 600                 # half-finished sign-ins expire after 10 minutes
INVITE_TTL = 48 * 3600
LOCK_AFTER = 5                   # failed attempts ...
LOCK_FOR = 15 * 60               # ... lock the account / source IP for 15 minutes
MIN_PASSWORD = 12

AUTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT DEFAULT '',
    password_hash TEXT DEFAULT '',
    role TEXT NOT NULL DEFAULT 'viewer',
    hosts TEXT NOT NULL DEFAULT '"*"',
    totp_secret TEXT DEFAULT '',
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_last_step INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    locked_until REAL NOT NULL DEFAULT 0,
    created_at REAL, created_by TEXT DEFAULT '', last_login REAL
);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    created_at REAL, last_seen REAL, expires_at REAL,
    ip TEXT DEFAULT '', user_agent TEXT DEFAULT '',
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,
    kind TEXT NOT NULL DEFAULT 'invite',      -- invite | reset
    user_id INTEGER,                          -- for reset links
    role TEXT, hosts TEXT, note TEXT DEFAULT '',
    created_by TEXT, created_at REAL, expires_at REAL, used_at REAL
);
"""


class AuthError(Exception):
    """Shown to the user as-is (no internals)."""


def _sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
def hash_password(pw):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF2_ITER)
    return "pbkdf2_sha256$%d$%s$%s" % (PBKDF2_ITER, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(pw, stored):
    try:
        algo, it, salt, dk = stored.split("$")
        assert algo == "pbkdf2_sha256"
        got = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), base64.b64decode(salt), int(it))
        return hmac.compare_digest(got, base64.b64decode(dk))
    except Exception:
        return False


_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))   # equalises timing for unknown users


def check_password_policy(pw, username=""):
    if len(pw) < MIN_PASSWORD:
        raise AuthError("Password must be at least %d characters." % MIN_PASSWORD)
    if username and username.lower() in pw.lower():
        raise AuthError("Password must not contain the username.")
    if len(set(pw)) < 6:
        raise AuthError("Password is too repetitive.")


# ---------------------------------------------------------------------------
# TOTP (RFC 6238, SHA1, 6 digits, 30 s)
# ---------------------------------------------------------------------------
def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_at(secret, step):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000
    return "%06d" % code


def totp_match(secret, code, last_step):
    """Returns the matched time step (>last_step, so codes can't be replayed) or None."""
    code = re.sub(r"\s", "", str(code or ""))
    if not re.match(r"^\d{6}$", code):
        return None
    now = int(time.time() // 30)
    for step in (now - 1, now, now + 1):
        if step > last_step and hmac.compare_digest(totp_at(secret, step), code):
            return step
    return None


# ---------------------------------------------------------------------------
class AuthManager:
    def __init__(self, db, cfg, config_path=None):
        self.db = db
        self.cfg = cfg
        self.config_path = config_path
        with db.lock:
            db.conn.executescript(AUTH_SCHEMA)
            db.conn.commit()
        self.tickets = {}           # in-progress sign-ins: token -> {user_id, stage, expires}
        self.ip_fail = {}           # ip -> [timestamps]
        self.lock = threading.Lock()
        self._bootstrap()

    # ---- bootstrap: turn the old single shared password into the first owner account ----
    def _bootstrap(self):
        if self.db.one("SELECT id FROM users LIMIT 1"):
            return
        pw = self.cfg.get("admin_password") or ""
        name = (self.cfg.get("admin_user") or "admin").lower()
        now = time.time()
        self.db.x("""INSERT INTO users(username,display_name,password_hash,role,hosts,must_change_password,created_at,created_by)
                     VALUES(?,?,?,?,?,1,?,'setup')""",
                  (name, "Owner", hash_password(pw) if pw else "", "owner", json.dumps("*"), now))
        self.db.audit("system", "user_created", "owner '%s' created from the initial setup password" % name)

    def clear_bootstrap_password(self):
        """After the owner has chosen a real password, remove the plaintext one from config.json."""
        if not self.config_path or not self.cfg.get("admin_password"):
            return
        try:
            with open(self.config_path, encoding="utf-8") as f:
                data = json.load(f)
            data["admin_password"] = ""
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            self.cfg["admin_password"] = ""
        except OSError:
            pass

    # ---- helpers ----------------------------------------------------------
    @staticmethod
    def public(u):
        if not u:
            return None
        return {"id": u["id"], "username": u["username"], "display_name": u["display_name"], "role": u["role"],
                "hosts": json.loads(u["hosts"] or '"*"'), "totp_enabled": bool(u["totp_enabled"]),
                "disabled": bool(u["disabled"]), "last_login": u["last_login"], "created_at": u["created_at"],
                "created_by": u["created_by"], "locked": u["locked_until"] > time.time()}

    def user(self, uid):
        return self.db.one("SELECT * FROM users WHERE id=?", (uid,))

    @staticmethod
    def scope(u):
        """None = all hosts, else list of host names the user may see."""
        if u["role"] == "owner":
            return None
        h = json.loads(u["hosts"] or '"*"')
        return None if h == "*" else list(h)

    @staticmethod
    def can(u, need):
        return ROLE_RANK.get(u["role"], 0) >= ROLE_RANK[need]

    def _ip_locked(self, ip):
        now = time.time()
        with self.lock:
            hits = [t for t in self.ip_fail.get(ip, []) if now - t < LOCK_FOR]
            self.ip_fail[ip] = hits
            return len(hits) >= LOCK_AFTER * 4      # per-IP limit across usernames

    def _fail(self, ip, u=None):
        with self.lock:
            self.ip_fail.setdefault(ip, []).append(time.time())
        if u:
            failed = u["failed"] + 1
            locked = time.time() + LOCK_FOR if failed >= LOCK_AFTER else 0
            self.db.x("UPDATE users SET failed=?, locked_until=? WHERE id=?", (0 if locked else failed, locked, u["id"]))
            if locked:
                self.db.audit(u["username"], "account_locked", "too many failed sign-ins from %s" % ip)

    def _new_ticket(self, uid, stage):
        tok = secrets.token_urlsafe(24)
        with self.lock:
            now = time.time()
            self.tickets = {k: v for k, v in self.tickets.items() if v["expires"] > now}
            self.tickets[tok] = {"user_id": uid, "stage": stage, "expires": now + TICKET_TTL}
        return tok

    def _ticket(self, tok, stage):
        with self.lock:
            t = self.tickets.get(tok or "")
        if not t or t["expires"] < time.time() or t["stage"] != stage:
            raise AuthError("This sign-in has expired. Please start again.")
        return t

    def _next_stage(self, u):
        if u["must_change_password"] or not u["password_hash"]:
            return "password"
        if not u["totp_enabled"]:
            return "enroll"
        return "totp"

    # ---- sign-in flow -----------------------------------------------------
    def login(self, username, password, ip):
        if self._ip_locked(ip):
            raise AuthError("Too many failed attempts from your address. Try again in 15 minutes.")
        u = self.db.one("SELECT * FROM users WHERE username=?", (str(username or "").strip().lower(),))
        if not u:
            verify_password(password or "", _DUMMY_HASH)
            self._fail(ip)
            raise AuthError("Wrong username or password.")
        if u["locked_until"] > time.time():
            raise AuthError("This account is locked after too many failed attempts. Try again in 15 minutes or ask an owner.")
        if u["disabled"]:
            raise AuthError("This account is disabled.")
        if not u["password_hash"] or not verify_password(password or "", u["password_hash"]):
            self._fail(ip, u)
            raise AuthError("Wrong username or password.")
        self.db.x("UPDATE users SET failed=0 WHERE id=?", (u["id"],))
        stage = self._next_stage(u)
        return {"step": stage, "ticket": self._new_ticket(u["id"], stage), "username": u["username"]}

    def set_new_password(self, ticket, new_password):
        t = self._ticket(ticket, "password")
        u = self.user(t["user_id"])
        check_password_policy(new_password or "", u["username"])
        if u["password_hash"] and verify_password(new_password, u["password_hash"]):
            raise AuthError("Choose a different password from the current one.")
        self.db.x("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?", (hash_password(new_password), u["id"]))
        self.db.audit(u["username"], "password_set", "")
        if u["role"] == "owner":
            self.clear_bootstrap_password()
        with self.lock:
            self.tickets.pop(ticket, None)
        u = self.user(u["id"])
        stage = self._next_stage(u)
        return {"step": stage, "ticket": self._new_ticket(u["id"], stage), "username": u["username"]}

    def enroll_start(self, ticket):
        t = self._ticket(ticket, "enroll")
        u = self.user(t["user_id"])
        secret = new_totp_secret()
        # new key -> forget the replay marker of the old key
        self.db.x("UPDATE users SET totp_secret=?, totp_enabled=0, totp_last_step=0 WHERE id=?", (secret, u["id"]))
        issuer = "NetGuard"
        label = "%s:%s" % (issuer, u["username"])
        uri = "otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30" % (quote(label), secret, quote(issuer))
        return {"secret": " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)), "uri": uri}

    def enroll_finish(self, ticket, code, ip, ua):
        t = self._ticket(ticket, "enroll")
        u = self.user(t["user_id"])
        step = totp_match(u["totp_secret"], code, u["totp_last_step"]) if u["totp_secret"] else None
        if not step:
            raise AuthError("That code didn't match. Check the time on your phone and try the newest code.")
        self.db.x("UPDATE users SET totp_enabled=1, totp_last_step=? WHERE id=?", (step, u["id"]))
        self.db.audit(u["username"], "2fa_enabled", "")
        with self.lock:
            self.tickets.pop(ticket, None)
        return self._start_session(u, ip, ua)

    def verify_totp(self, ticket, code, ip, ua):
        t = self._ticket(ticket, "totp")
        u = self.user(t["user_id"])
        if u["locked_until"] > time.time():
            raise AuthError("This account is locked after too many failed attempts. Try again in 15 minutes.")
        step = totp_match(u["totp_secret"], code, u["totp_last_step"])
        if not step:
            self._fail(ip, u)
            raise AuthError("Wrong or already-used code.")
        self.db.x("UPDATE users SET totp_last_step=?, failed=0 WHERE id=?", (step, u["id"]))
        with self.lock:
            self.tickets.pop(ticket, None)
        return self._start_session(u, ip, ua)

    def _start_session(self, u, ip, ua):
        tok = secrets.token_urlsafe(32)
        now = time.time()
        self.db.x("""INSERT INTO sessions(token_hash,user_id,created_at,last_seen,expires_at,ip,user_agent)
                     VALUES(?,?,?,?,?,?,?)""", (_sha256(tok), u["id"], now, now, now + SESSION_MAX, ip, (ua or "")[:200]))
        self.db.x("UPDATE users SET last_login=? WHERE id=?", (now, u["id"]))
        self.db.audit(u["username"], "signed_in", "from %s" % ip)
        return {"session": tok, "user": self.public(self.user(u["id"]))}

    def session_user(self, token):
        if not token:
            return None, None
        s = self.db.one("SELECT * FROM sessions WHERE token_hash=? AND revoked=0", (_sha256(token),))
        now = time.time()
        if not s or s["expires_at"] < now or now - s["last_seen"] > SESSION_IDLE:
            return None, None
        u = self.user(s["user_id"])
        if not u or u["disabled"] or not u["totp_enabled"]:
            return None, None
        if now - s["last_seen"] > 60:
            self.db.x("UPDATE sessions SET last_seen=? WHERE id=?", (now, s["id"]))
        return u, s

    def logout(self, token):
        self.db.x("UPDATE sessions SET revoked=1 WHERE token_hash=?", (_sha256(token or ""),))

    def change_password(self, u, current, new):
        if not verify_password(current or "", u["password_hash"]):
            raise AuthError("Current password is wrong.")
        check_password_policy(new or "", u["username"])
        self.db.x("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new), u["id"]))
        self.db.audit(u["username"], "password_changed", "")
        if u["role"] == "owner":
            self.clear_bootstrap_password()

    # ---- people management (owners) ---------------------------------------
    def list_users(self):
        return [self.public(u) for u in self.db.q("SELECT * FROM users ORDER BY role DESC, username")]

    @staticmethod
    def _clean_hosts(hosts):
        if hosts in (None, "*", ["*"]):
            return "*"
        if not isinstance(hosts, list):
            raise AuthError("hosts must be '*' or a list of server names")
        out = sorted({str(h) for h in hosts if re.match(r"^[A-Za-z0-9_.\-]{1,128}$", str(h))})
        return out

    def create_invite(self, by, role, hosts, note="", kind="invite", user_id=None):
        if role not in ROLES:
            raise AuthError("unknown role")
        tok = secrets.token_urlsafe(32)
        now = time.time()
        self.db.x("""INSERT INTO invites(token_hash,kind,user_id,role,hosts,note,created_by,created_at,expires_at)
                     VALUES(?,?,?,?,?,?,?,?,?)""",
                  (_sha256(tok), kind, user_id, role, json.dumps(self._clean_hosts(hosts)), str(note)[:200],
                   by["username"], now, now + INVITE_TTL))
        self.db.audit(by["username"], "%s_created" % kind, "role=%s hosts=%s %s" % (role, json.dumps(hosts), note))
        return tok

    def invite_info(self, tok):
        i = self.db.one("SELECT * FROM invites WHERE token_hash=?", (_sha256(tok or ""),))
        if not i or i["used_at"] or i["expires_at"] < time.time():
            raise AuthError("This link is invalid, already used, or expired. Ask an owner for a new one.")
        info = {"kind": i["kind"], "role": i["role"], "hosts": json.loads(i["hosts"]), "invited_by": i["created_by"],
                "expires_at": i["expires_at"]}
        if i["kind"] == "reset":
            u = self.user(i["user_id"])
            info["username"] = u["username"] if u else ""
        return i, info

    def accept_invite(self, tok, username, display_name, password):
        i, info = self.invite_info(tok)
        now = time.time()
        if i["kind"] == "reset":
            u = self.user(i["user_id"])
            if not u:
                raise AuthError("That account no longer exists.")
            check_password_policy(password or "", u["username"])
            self.db.x("""UPDATE users SET password_hash=?, must_change_password=0, totp_enabled=0, totp_secret='',
                         failed=0, locked_until=0 WHERE id=?""", (hash_password(password), u["id"]))
            self.db.x("UPDATE sessions SET revoked=1 WHERE user_id=?", (u["id"],))
            uid, uname = u["id"], u["username"]
            self.db.audit(uname, "account_reset_completed", "via link from %s" % i["created_by"])
        else:
            uname = str(username or "").strip().lower()
            if not USERNAME_RE.match(uname):
                raise AuthError("Username: 2-32 characters, lowercase letters, digits, dot, dash or underscore.")
            if self.db.one("SELECT id FROM users WHERE username=?", (uname,)):
                raise AuthError("That username is taken.")
            check_password_policy(password or "", uname)
            uid = self.db.x("""INSERT INTO users(username,display_name,password_hash,role,hosts,created_at,created_by)
                               VALUES(?,?,?,?,?,?,?)""",
                            (uname, str(display_name or uname)[:60], hash_password(password), i["role"], i["hosts"], now,
                             i["created_by"]))
            self.db.audit(uname, "user_created", "accepted invite from %s (role %s)" % (i["created_by"], i["role"]))
        self.db.x("UPDATE invites SET used_at=? WHERE id=?", (now, i["id"]))
        return {"step": "enroll", "ticket": self._new_ticket(uid, "enroll"), "username": uname}

    def update_user(self, by, uid, body):
        u = self.user(uid)
        if not u:
            raise LookupError("user not found")
        role = body.get("role", u["role"])
        if role not in ROLES:
            raise AuthError("unknown role")
        disabled = 1 if body.get("disabled", bool(u["disabled"])) else 0
        hosts = json.dumps(self._clean_hosts(body.get("hosts", json.loads(u["hosts"]))))
        demoting_owner = u["role"] == "owner" and (role != "owner" or disabled)
        if demoting_owner:
            owners = self.db.one("SELECT COUNT(*) n FROM users WHERE role='owner' AND disabled=0")["n"]
            if owners <= 1:
                raise AuthError("There must always be at least one active owner.")
        self.db.x("UPDATE users SET role=?, hosts=?, disabled=? WHERE id=?", (role, hosts, disabled, uid))
        if disabled:
            self.db.x("UPDATE sessions SET revoked=1 WHERE user_id=?", (uid,))
        self.db.audit(by["username"], "user_updated", "%s: role=%s hosts=%s disabled=%s" % (u["username"], role, hosts, disabled))
        return self.public(self.user(uid))

    def delete_user(self, by, uid):
        u = self.user(uid)
        if not u:
            raise LookupError("user not found")
        if u["id"] == by["id"]:
            raise AuthError("You can't delete your own account.")
        if u["role"] == "owner" and self.db.one("SELECT COUNT(*) n FROM users WHERE role='owner' AND disabled=0")["n"] <= 1:
            raise AuthError("There must always be at least one active owner.")
        self.db.x("DELETE FROM sessions WHERE user_id=?", (uid,))
        self.db.x("DELETE FROM users WHERE id=?", (uid,))
        self.db.audit(by["username"], "user_deleted", u["username"])

    def sessions(self, u):
        sql = """SELECT s.id, s.user_id, u.username, s.created_at, s.last_seen, s.expires_at, s.ip, s.user_agent
                 FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.revoked=0 AND s.expires_at > ? AND s.last_seen > ?"""
        args = [time.time(), time.time() - SESSION_IDLE]
        if u["role"] != "owner":
            sql += " AND s.user_id=?"
            args.append(u["id"])
        return self.db.q(sql + " ORDER BY s.last_seen DESC", args)

    def revoke_session(self, by, sid):
        s = self.db.one("SELECT * FROM sessions WHERE id=?", (sid,))
        if not s or (by["role"] != "owner" and s["user_id"] != by["id"]):
            raise LookupError("session not found")
        self.db.x("UPDATE sessions SET revoked=1 WHERE id=?", (sid,))
        self.db.audit(by["username"], "session_revoked", "session %s of user %s" % (sid, s["user_id"]))

    # ---- offline recovery (CLI, run by an administrator on the server) -----
    def reset_from_cli(self, username):
        username = username.lower()
        u = self.db.one("SELECT * FROM users WHERE username=?", (username,))
        pw = secrets.token_urlsafe(12)
        if u:
            self.db.x("""UPDATE users SET password_hash=?, must_change_password=1, totp_enabled=0, totp_secret='',
                         failed=0, locked_until=0, disabled=0 WHERE id=?""", (hash_password(pw), u["id"]))
            self.db.x("UPDATE sessions SET revoked=1 WHERE user_id=?", (u["id"],))
        else:
            self.db.x("""INSERT INTO users(username,display_name,password_hash,role,hosts,must_change_password,created_at,created_by)
                         VALUES(?,?,?,'owner','"*"',1,?,'cli')""", (username, username, hash_password(pw), time.time()))
        self.db.audit("cli", "account_reset", "%s reset from the server console" % username)
        return pw
