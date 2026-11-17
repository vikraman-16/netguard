"""
NetGuard credential vault: encrypted logins, database credentials, S3/cloud keys, API keys and notes.

- Every item is sealed with the master key (AES-256-GCM, bound to the item id).
- Owners can use every item; admins only the items shared with them (or created by them). Viewers: none.
- Listing shows non-secret fields only; revealing a secret needs a fresh 2-factor code (10-minute step-up)
  and is logged. Backup jobs reference items by id; the dashboard decrypts them only to send a signed job
  to the server that runs it.
"""
import json
import re
import time

STEPUP_SECONDS = 600

# kind -> [(field, label, secret)]
KINDS = {
    "login": ("Login", [("url", "Address / URL", False), ("username", "Username", False), ("password", "Password", True),
                        ("notes", "Notes", False)]),
    "database": ("Database", [("engine", "Engine: mysql, postgres, mssql or sqlite", False), ("host", "Host", False),
                              ("port", "Port", False), ("username", "Username", False), ("password", "Password", True),
                              ("database", "Database(s), comma-separated (blank = all)", False), ("notes", "Notes", False)]),
    "s3": ("S3-compatible storage", [("endpoint", "Endpoint (e.g. https://s3.eu-west-1.amazonaws.com)", False),
                                     ("region", "Region (e.g. eu-west-1, auto for R2)", False), ("bucket", "Bucket", False),
                                     ("prefix", "Folder/prefix in the bucket (optional)", False),
                                     ("access_key", "Access key ID", False), ("secret_key", "Secret access key", True),
                                     ("notes", "Notes", False)]),
    "api_key": ("API key / token", [("service", "Service", False), ("key", "Key / token", True), ("notes", "Notes", False)]),
    "secret": ("Secret / recovery key", [("value", "Secret value", True), ("notes", "Notes", False)]),
    "note": ("Secure note", [("notes", "Note", True)]),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, kind TEXT NOT NULL, host TEXT DEFAULT '',
    data TEXT NOT NULL, access TEXT NOT NULL DEFAULT '[]',
    created_by TEXT, created_at REAL, updated_by TEXT, updated_at REAL, system INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS vault_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, item_id INTEGER, item_name TEXT, user TEXT, action TEXT, ip TEXT
);
"""


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, app):
        self.app = app
        self.db = app.db
        with self.db.lock:
            self.db.conn.executescript(SCHEMA)
            cols = [r[1] for r in self.db.conn.execute("PRAGMA table_info(sessions)")]
            if "stepup_at" not in cols:
                self.db.conn.execute("ALTER TABLE sessions ADD COLUMN stepup_at REAL NOT NULL DEFAULT 0")
            self.db.conn.commit()

    # ---- access ---------------------------------------------------------
    @staticmethod
    def _purpose(iid):
        return "vault:%d" % iid

    def _can(self, user, item):
        if user["role"] == "owner":
            return True
        if user["role"] != "admin":
            return False
        return user["username"] in json.loads(item["access"] or "[]") or item["created_by"] == user["username"]

    def _get(self, user, iid):
        item = self.db.one("SELECT * FROM vault_items WHERE id=?", (iid,))
        if not item or not self._can(user, item):
            raise LookupError("vault item not found")
        return item

    def _log(self, user, item, action, ip=""):
        self.db.x("INSERT INTO vault_log(ts,item_id,item_name,user,action,ip) VALUES(?,?,?,?,?,?)",
                  (time.time(), item["id"] if item else None, item["name"] if item else "", user["username"], action, ip))

    # ---- step-up (fresh 2-factor code before secrets are shown) ------------
    def stepup_ok(self, session):
        return session and time.time() - (session.get("stepup_at") or 0) < STEPUP_SECONDS

    def stepup(self, user, session, code):
        from auth import totp_match
        u = self.db.one("SELECT * FROM users WHERE id=?", (user["id"],))
        step = totp_match(u["totp_secret"], code, u["totp_last_step"])
        if not step:
            raise VaultError("Wrong or already-used 2-factor code.")
        self.db.x("UPDATE users SET totp_last_step=? WHERE id=?", (step, u["id"]))
        self.db.x("UPDATE sessions SET stepup_at=? WHERE id=?", (time.time(), session["id"]))
        session["stepup_at"] = time.time()

    # ---- items ----------------------------------------------------------
    def _clean(self, kind, fields, old=None):
        if kind not in KINDS:
            raise VaultError("unknown item type")
        out = {}
        for key, label, secret in KINDS[kind][1]:
            v = str((fields or {}).get(key, "") or "")
            if secret and v == "" and old:
                v = old.get(key, "")          # blank secret on edit = keep
            out[key] = v.strip() if not secret else v
        if kind == "s3":
            if not out["endpoint"].startswith(("https://", "http://127.0.0.1", "http://localhost")):
                raise VaultError("S3 endpoint must start with https://")
            if not out["bucket"] or not out["access_key"] or not out["secret_key"]:
                raise VaultError("bucket, access key and secret key are required")
            out["region"] = out["region"] or "us-east-1"
        if kind == "database" and out["engine"] not in ("mysql", "postgres", "mssql", "sqlite"):
            raise VaultError("engine must be mysql, postgres, mssql or sqlite")
        return out

    def _public(self, item, data):
        kind = KINDS.get(item["kind"], ("", []))
        shown = {k: ("•" * 8 if (secret and data.get(k)) else data.get(k, "")) for k, _, secret in kind[1]}
        return {"id": item["id"], "name": item["name"], "kind": item["kind"], "kind_label": kind[0], "host": item["host"],
                "fields": shown, "access": json.loads(item["access"] or "[]"), "created_by": item["created_by"],
                "updated_at": item["updated_at"], "updated_by": item["updated_by"], "system": bool(item["system"])}

    def list(self, user):
        if user["role"] not in ("owner", "admin"):
            return []
        out = []
        for it in self.db.q("SELECT * FROM vault_items ORDER BY name"):
            if self._can(user, it):
                out.append(self._public(it, self.app.keys.open(it["data"], self._purpose(it["id"]), as_json=True) or {}))
        return out

    def kinds(self):
        return {k: {"label": v[0], "fields": [{"key": f, "label": l, "secret": s} for f, l, s in v[1]]} for k, v in KINDS.items()}

    def save(self, user, body, iid=None, ip="", system=False):
        name = str(body.get("name") or "").strip()[:80]
        if not name:
            raise VaultError("name is required")
        host = str(body.get("host") or "").strip()
        if host and not re.match(r"^[A-Za-z0-9_.\-]{1,128}$", host):
            raise VaultError("bad server name")
        now = time.time()
        if iid:
            item = self._get(user, iid)
            old = self.app.keys.open(item["data"], self._purpose(iid), as_json=True)
            data = self._clean(item["kind"], body.get("fields"), old)
            self.db.x("UPDATE vault_items SET name=?, host=?, data=?, updated_by=?, updated_at=? WHERE id=?",
                      (name, host, self.app.keys.seal(data, self._purpose(iid)), user["username"], now, iid))
            self._log(user, self.db.one("SELECT * FROM vault_items WHERE id=?", (iid,)), "update", ip)
            return iid
        kind = body.get("kind")
        data = self._clean(kind, body.get("fields"))
        iid = self.db.x("""INSERT INTO vault_items(name,kind,host,data,access,created_by,created_at,updated_by,updated_at,system)
                           VALUES(?,?,?,?,?,?,?,?,?,?)""",
                        (name, kind, host, "pending", json.dumps([user["username"]]), user["username"], now, user["username"], now,
                         1 if system else 0))
        self.db.x("UPDATE vault_items SET data=? WHERE id=?", (self.app.keys.seal(data, self._purpose(iid)), iid))
        self._log(user, self.db.one("SELECT * FROM vault_items WHERE id=?", (iid,)), "create", ip)
        return iid

    def reveal(self, user, session, iid, ip=""):
        item = self._get(user, iid)
        if not self.stepup_ok(session):
            raise PermissionError("stepup")
        data = self.app.keys.open(item["data"], self._purpose(iid), as_json=True)
        self._log(user, item, "reveal", ip)
        self.db.audit(user["username"], "vault_reveal", item["name"], host=item["host"] or None)
        return data

    def share(self, user, iid, usernames, ip=""):
        item = self._get(user, iid)
        if user["role"] != "owner" and item["created_by"] != user["username"]:
            raise PermissionError("Only an owner or the item's creator can change who it is shared with.")
        valid = {u["username"] for u in self.db.q("SELECT username FROM users WHERE role IN ('owner','admin')")}
        names = sorted({str(n).lower() for n in usernames if str(n).lower() in valid} | {item["created_by"]})
        self.db.x("UPDATE vault_items SET access=? WHERE id=?", (json.dumps(names), iid))
        self._log(user, item, "share: " + ", ".join(names), ip)
        return names

    def delete(self, user, iid, ip=""):
        item = self._get(user, iid)
        used = self.app.backups.jobs_using_vault(iid) if getattr(self.app, "backups", None) else []
        if used:
            raise VaultError("Used by backup job(s): %s. Change those jobs first." % ", ".join(used))
        self.db.x("DELETE FROM vault_items WHERE id=?", (iid,))
        self._log(user, item, "delete", ip)

    def log(self, user, iid=None):
        if iid:
            self._get(user, iid)
            return self.db.q("SELECT * FROM vault_log WHERE item_id=? ORDER BY id DESC LIMIT 200", (iid,))
        if user["role"] != "owner":
            return self.db.q("SELECT * FROM vault_log WHERE user=? ORDER BY id DESC LIMIT 200", (user["username"],))
        return self.db.q("SELECT * FROM vault_log ORDER BY id DESC LIMIT 300")

    # ---- internal use (backups) -------------------------------------------
    def secret_for(self, user, iid, kind=None):
        """Decrypt an item for a backup job the given user creates/edits (access-checked)."""
        item = self._get(user, iid)
        if kind and item["kind"] != kind:
            raise VaultError("vault item '%s' is a %s, expected %s" % (item["name"], item["kind"], kind))
        return item

    def open_item(self, iid):
        item = self.db.one("SELECT * FROM vault_items WHERE id=?", (iid,))
        if not item:
            return None
        return dict(item, data=self.app.keys.open(item["data"], self._purpose(iid), as_json=True))
