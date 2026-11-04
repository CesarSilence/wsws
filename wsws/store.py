"""Persistencia: un SQLite por workspace + carpeta de evidencias."""
import getpass
import hashlib
import ipaddress
import os
import re
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .parsers import is_ip


def _home():
    if os.environ.get("WSWS_HOME"):
        return Path(os.environ["WSWS_HOME"])
    # con sudo, seguir usando el home del operador y no el de root
    if os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        return Path(os.path.expanduser("~" + os.environ["SUDO_USER"])) / ".wsws"
    return Path.home() / ".wsws"


HOME = _home()
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_NAMES = {v: k for k, v in SEV.items()}
SVC_FIELDS = ("name", "product", "version", "extra")

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts(
  id INTEGER PRIMARY KEY, addr TEXT NOT NULL UNIQUE,
  hostnames TEXT NOT NULL DEFAULT '', os TEXT NOT NULL DEFAULT '', mac TEXT NOT NULL DEFAULT '',
  domain TEXT NOT NULL DEFAULT '', info TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS services(
  id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL, port INTEGER NOT NULL, proto TEXT NOT NULL DEFAULT 'tcp',
  state TEXT NOT NULL DEFAULT 'open', name TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '', extra TEXT NOT NULL DEFAULT '', banner TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, UNIQUE(host_id, port, proto));
CREATE TABLE IF NOT EXISTS web(
  id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL, port INTEGER NOT NULL DEFAULT 0, url TEXT NOT NULL UNIQUE,
  status INTEGER, title TEXT NOT NULL DEFAULT '', tech TEXT NOT NULL DEFAULT '', server TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL, port INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL DEFAULT '', ref TEXT NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT '',
  sev INTEGER NOT NULL DEFAULT 0, location TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, UNIQUE(host_id, port, source, ref, location));
CREATE TABLE IF NOT EXISTS creds(
  id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL DEFAULT 0, port INTEGER NOT NULL DEFAULT 0,
  domain TEXT NOT NULL DEFAULT '', username TEXT NOT NULL, secret TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL DEFAULT 'password', valid INTEGER NOT NULL DEFAULT 0, admin INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  UNIQUE(host_id, domain, username, secret));
CREATE TABLE IF NOT EXISTS notes(
  id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL DEFAULT 0, text TEXT NOT NULL,
  author TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS validations(
  id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL, check_id TEXT NOT NULL, cve TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL, method TEXT NOT NULL DEFAULT 'passive', reason TEXT NOT NULL DEFAULT '',
  evidence TEXT NOT NULL DEFAULT '', limitations TEXT NOT NULL DEFAULT '', recon_age TEXT NOT NULL DEFAULT '',
  evidence_id INTEGER, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  UNIQUE(host_id, check_id));
CREATE TABLE IF NOT EXISTS evidence(
  id INTEGER PRIMARY KEY, ts_start TEXT NOT NULL, ts_end TEXT, operator TEXT NOT NULL DEFAULT '',
  cwd TEXT NOT NULL DEFAULT '', cmd TEXT NOT NULL DEFAULT '', tool TEXT NOT NULL DEFAULT '',
  fmt TEXT NOT NULL DEFAULT '', exit_code INTEGER, files TEXT NOT NULL DEFAULT '',
  sha256 TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS seen(
  evidence_id INTEGER NOT NULL, kind TEXT NOT NULL, ref_id INTEGER NOT NULL,
  PRIMARY KEY(evidence_id, kind, ref_id));
CREATE TABLE IF NOT EXISTS scope(kind TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(kind, value));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS domain_alias(alias TEXT NOT NULL PRIMARY KEY COLLATE NOCASE, canonical TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_services_port ON services(port);
CREATE INDEX IF NOT EXISTS ix_findings_host ON findings(host_id, port);
CREATE INDEX IF NOT EXISTS ix_web_host ON web(host_id, port);
CREATE INDEX IF NOT EXISTS ix_creds_host ON creds(host_id);
CREATE INDEX IF NOT EXISTS ix_seen_ref ON seen(kind, ref_id);
"""


def now():
    return datetime.now(timezone.utc).strftime(TS_FMT)


def operator():
    return os.environ.get("WSWS_OPERATOR") or os.environ.get("SUDO_USER") or getpass.getuser()


def as_net(s):
    try:
        return ipaddress.ip_network(s.strip(), strict=False)
    except (ValueError, AttributeError):
        return None


def ipkey(addr):
    try:
        ip = ipaddress.ip_address(addr)
        return f"{ip.version}{int(ip):040d}"
    except ValueError:
        return "9" + (addr or "")


def _in_net(addr, cidr):
    net = as_net(cidr)
    try:
        return int(net is not None and ipaddress.ip_address(addr) in net)
    except ValueError:
        return 0


def _match(target, rule):
    t, r = as_net(target), as_net(rule)
    if t and r:
        return t.version == r.version and t.subnet_of(r)
    if t or r:
        return False
    rule = rule.lower().lstrip("*").lstrip(".")
    target = target.lower()
    return target == rule or target.endswith("." + rule)


def _overlaps(target, rule):
    t, r = as_net(target), as_net(rule)
    if t and r:
        return t.version == r.version and t.overlaps(r)
    return _match(target, rule)


def split_list(s):
    return [x for x in (s or "").split(",") if x]


EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"


def norm_secret(s):
    """LM:NT con LM vacío -> solo NT, para que el mismo hash no quede dos veces."""
    s = (s or "").strip()
    lm, _, nt = s.partition(":")
    return nt if lm.lower() == EMPTY_LM and re.fullmatch(r"[0-9a-fA-F]{32}", nt) else s


def norm_addr(a):
    a = (a or "").strip().strip("[]")
    return a if is_ip(a) else a.lower().rstrip(".")


# --- workspaces ---------------------------------------------------------------

def workspaces():
    d = HOME / "ws"
    return sorted(p.name for p in d.iterdir() if (p / "wsws.db").exists()) if d.exists() else []


def current_name():
    if os.environ.get("WSWS"):
        return os.environ["WSWS"]
    f = HOME / "current"
    return f.read_text().strip() if f.exists() else None


def set_current(name):
    HOME.mkdir(parents=True, exist_ok=True)
    (HOME / "current").write_text((name or "") + "\n")


def ws_exists(name):
    return (HOME / "ws" / name / "wsws.db").exists()


class Store:
    def __init__(self, name):
        if not NAME_RE.match(name or ""):
            raise SystemExit(f"wsws: nombre de workspace inválido: {name!r} (usa letras, números, . _ -)")
        self.name = name
        self.dir = HOME / "ws" / name
        self.evdir = self.dir / "evidence"
        self.evdir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.dir / "wsws.db", timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self._rules = None
        self.db.create_function("in_net", 2, _in_net, deterministic=True)
        self.db.create_function("ipkey", 1, ipkey, deterministic=True)
        self.db.create_function("in_scope", 1, lambda a: {None: None, True: 1, False: 0}[self.in_scope(a)])
        if self.one("PRAGMA user_version")[0] < 1:  # migración: limpiar creds duplicadas de la v0.1.0
            self.dedupe_creds()
            self.db.execute("PRAGMA user_version = 1")

    def q(self, sql, params=()):
        return self.db.execute(sql, params).fetchall()

    def one(self, sql, params=()):
        return self.db.execute(sql, params).fetchone()

    def _update(self, table, rid, fields):
        if fields:
            cols = ", ".join(f"{k}=?" for k in fields)
            self.db.execute(f"UPDATE {table} SET {cols} WHERE id=?", (*fields.values(), rid))

    def _seen(self, ev, kind, rid):
        if ev:
            self.db.execute("INSERT OR IGNORE INTO seen(evidence_id, kind, ref_id) VALUES(?,?,?)", (ev, kind, rid))

    # --- hosts ----------------------------------------------------------------

    def find_host(self, addr):
        addr = norm_addr(addr)
        row = self.one("SELECT * FROM hosts WHERE addr=?", (addr,))
        if row is None and not is_ip(addr):
            row = self.one("SELECT * FROM hosts WHERE (','||hostnames||',') LIKE ?", (f"%,{addr},%",))
        return row

    def host(self, addr, hostnames=(), os="", mac="", domain="", info="", soft=False, ev=None):
        addr = norm_addr(addr)
        names = []
        for n in hostnames or ():
            n = norm_addr(n)
            if n and n != addr and not is_ip(n) and n not in names:
                names.append(n)
        domain = self.canon_domain(domain)
        row = self.find_host(addr)
        t = now()
        if row is None:
            cur = self.db.execute(
                "INSERT INTO hosts(addr, hostnames, os, mac, domain, info, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?)",
                (addr, ",".join(names), os, mac, domain, info, t, t))
            hid, created = cur.lastrowid, True
        else:
            hid, created = row["id"], False
            old = split_list(row["hostnames"])
            merged = old + [n for n in names if n not in old and n != row["addr"]]
            upd = {"last_seen": t}
            if merged != old:
                upd["hostnames"] = ",".join(merged)
            for k, v in (("os", os), ("mac", mac), ("domain", domain)):
                if v and v != row[k] and (not soft or not row[k]):
                    upd[k] = v
            if info and info not in row["info"]:
                upd["info"] = (row["info"] + "\n" + info).strip()[-20000:]
            self._update("hosts", hid, upd)
        # si el host ya existía registrado solo por nombre, absorberlo en la IP
        if is_ip(addr):
            for n in names:
                other = self.one("SELECT id FROM hosts WHERE addr=?", (n,))
                if other and other["id"] != hid:
                    self._merge(other["id"], hid)
        self._seen(ev, "host", hid)
        return hid, created

    def _merge(self, src, dst):
        s = self.one("SELECT * FROM hosts WHERE id=?", (src,))
        d = self.one("SELECT * FROM hosts WHERE id=?", (dst,))
        names = split_list(d["hostnames"])
        for n in [s["addr"]] + split_list(s["hostnames"]):
            if n not in names and n != d["addr"]:
                names.append(n)
        tags = split_list(d["tags"]) + [x for x in split_list(s["tags"]) if x not in split_list(d["tags"])]
        self._update("hosts", dst, {"hostnames": ",".join(names), "tags": ",".join(tags),
                                    "os": d["os"] or s["os"], "domain": d["domain"] or s["domain"],
                                    "first_seen": min(d["first_seen"], s["first_seen"])})
        for tbl in ("services", "web", "findings", "creds", "notes"):
            self.db.execute(f"UPDATE OR IGNORE {tbl} SET host_id=? WHERE host_id=?", (dst, src))
            self.db.execute(f"DELETE FROM {tbl} WHERE host_id=?", (src,))
        self.db.execute("UPDATE OR IGNORE seen SET ref_id=? WHERE kind='host' AND ref_id=?", (dst, src))
        self.db.execute("DELETE FROM seen WHERE kind='host' AND ref_id=?", (src,))
        self.db.execute("DELETE FROM hosts WHERE id=?", (src,))

    def tag(self, hid, add=(), remove=()):
        row = self.one("SELECT tags FROM hosts WHERE id=?", (hid,))
        tags = [t for t in split_list(row["tags"]) if t not in remove]
        tags += [t for t in add if t not in tags]
        self._update("hosts", hid, {"tags": ",".join(tags)})
        self.db.commit()
        return tags

    # --- servicios, web, hallazgos, creds -------------------------------------

    def service(self, hid, port, proto="tcp", state="open", soft=False, ev=None, **f):
        row = self.one("SELECT * FROM services WHERE host_id=? AND port=? AND proto=?", (hid, port, proto))
        t = now()
        if row is None:
            cur = self.db.execute(
                "INSERT INTO services(host_id, port, proto, state, name, product, version, extra, banner, first_seen, last_seen)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (hid, port, proto, state or "open", *(f.get(k) or "" for k in SVC_FIELDS), f.get("banner") or "", t, t))
            sid, created = cur.lastrowid, True
        else:
            sid, created = row["id"], False
            upd = {"last_seen": t}
            if state and state != row["state"]:
                upd["state"] = state
            for k in SVC_FIELDS:
                v = f.get(k) or ""
                if v and v != row[k] and (not soft or not row[k]):
                    upd[k] = v
            b = f.get("banner") or ""
            if b and b not in row["banner"]:
                upd["banner"] = (row["banner"] + "\n" + b).strip()[-20000:]
            self._update("services", sid, upd)
        self._seen(ev, "service", sid)
        return sid, created

    def web(self, hid, port, url, status=None, title="", tech="", server="", ev=None):
        row = self.one("SELECT * FROM web WHERE url=?", (url,))
        t = now()
        if row is None:
            cur = self.db.execute(
                "INSERT INTO web(host_id, port, url, status, title, tech, server, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?,?)",
                (hid, port, url, status, title, tech, server, t, t))
            wid, created = cur.lastrowid, True
        else:
            wid, created = row["id"], False
            upd = {"last_seen": t}
            for k, v in (("status", status), ("title", title), ("tech", tech), ("server", server)):
                if v and v != row[k]:
                    upd[k] = v
            self._update("web", wid, upd)
        self._seen(ev, "web", wid)
        return wid, created

    def finding(self, hid, port, source="", ref="", title="", severity="info", location="", detail="", ev=None):
        ref = ref or title
        sev = SEV.get(str(severity).lower(), 0)
        row = self.one("SELECT * FROM findings WHERE host_id=? AND port=? AND source=? AND ref=? AND location=?",
                       (hid, port, source, ref, location))
        t = now()
        if row is None:
            cur = self.db.execute(
                "INSERT INTO findings(host_id, port, source, ref, title, sev, location, detail, first_seen, last_seen)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)", (hid, port, source, ref, title, sev, location, detail, t, t))
            fid, created = cur.lastrowid, True
        else:
            fid, created = row["id"], False
            self._update("findings", fid, {"title": title or row["title"], "sev": sev,
                                           "detail": detail or row["detail"], "last_seen": t})
        self._seen(ev, "finding", fid)
        return fid, created

    # --- ajustes por workspace (clave/valor) -----------------------------------

    def setting(self, key, default=None):
        r = self.one("SELECT value FROM settings WHERE key=?", (key,))
        return r["value"] if r else default

    def set_setting(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", (key, str(value)))
        self.db.commit()

    # --- validaciones de vulnerabilidades (motor nativo) -----------------------

    def validation(self, hid, check_id, cve="", status="INCONCLUSIVE", method="passive", reason="",
                   evidence="", limitations="", recon_age="", evidence_id=None):
        """Una fila por (host, check): guarda el último resultado del validador. -> (id, creado)."""
        row = self.one("SELECT * FROM validations WHERE host_id=? AND check_id=?", (hid, check_id))
        t = now()
        vals = dict(cve=cve, status=status, method=method, reason=reason, evidence=evidence,
                    limitations=limitations, recon_age=recon_age, evidence_id=evidence_id, last_seen=t)
        if row is None:
            cols = "host_id, check_id, " + ", ".join(vals) + ", first_seen"
            ph = ",".join(["?"] * (len(vals) + 3))
            cur = self.db.execute(f"INSERT INTO validations({cols}) VALUES({ph})",
                                  (hid, check_id, *vals.values(), t))
            return cur.lastrowid, True
        self._update("validations", row["id"], vals)
        return row["id"], False

    def validations(self, host_id=None):
        if host_id is None:
            return self.q("SELECT v.*, h.addr FROM validations v JOIN hosts h ON h.id = v.host_id"
                          " ORDER BY ipkey(h.addr), v.check_id")
        return self.q("SELECT * FROM validations WHERE host_id=? ORDER BY check_id", (host_id,))

    # --- alias de dominio (CORP = corp.local) ----------------------------------

    def canon_domain(self, d):
        d = (d or "").strip()
        if not d:
            return d
        r = self.one("SELECT canonical FROM domain_alias WHERE alias = ?", (d,))
        return r["canonical"] if r else d

    def aliases(self):
        return self.q("SELECT alias, canonical FROM domain_alias ORDER BY canonical, alias")

    def alias_add(self, alias, canonical):
        """Registra alias -> canónico y normaliza lo ya guardado. Devuelve creds unidas."""
        alias, canonical = alias.strip(), self.canon_domain(canonical)
        if not alias or alias.lower() == canonical.lower():
            raise ValueError("el alias y el dominio canónico deben ser distintos")
        if self.one("SELECT 1 FROM domain_alias WHERE canonical = ? COLLATE NOCASE", (alias,)) and \
                alias.lower() != canonical.lower():
            # el alias era canónico de otros: re-apuntarlos al nuevo canónico
            self.db.execute("UPDATE domain_alias SET canonical = ? WHERE canonical = ? COLLATE NOCASE",
                            (canonical, alias))
        self.db.execute("INSERT OR REPLACE INTO domain_alias(alias, canonical) VALUES(?, ?)", (alias, canonical))
        self.db.execute("DELETE FROM domain_alias WHERE alias = ? COLLATE NOCASE", (canonical,))
        self.db.execute("UPDATE hosts SET domain = ? WHERE domain = ? COLLATE NOCASE", (canonical, alias))
        return self.dedupe_creds()

    def alias_rm(self, alias):
        n = self.db.execute("DELETE FROM domain_alias WHERE alias = ?", (alias,)).rowcount
        self.db.commit()
        return n

    # --- credenciales ------------------------------------------------------------

    def _find_cred(self, hid, domain, username, secret, exclude=None):
        """Identidad de una credencial: dominio + usuario (sin distinguir mayúsculas) + secreto.
        Las de dominio valen en cualquier host; las locales (sin dominio) son por host.
        Un usuario sin secreto y el mismo usuario con secreto son la misma credencial."""
        sql = "SELECT * FROM creds WHERE domain = ? COLLATE NOCASE AND username = ? COLLATE NOCASE AND id != ?"
        params = [domain, username, exclude or 0]
        if not domain:
            sql += " AND host_id = ?"
            params.append(hid)
        rows = self.q(sql + " ORDER BY id", params)
        exact = [r for r in rows if r["secret"] == secret]
        if exact:
            return exact[0]
        if not secret:
            return rows[0] if rows else None
        return next((r for r in rows if not r["secret"]), None)

    def cred(self, hid, port=0, domain="", username="", secret="", kind="password", valid=0, admin=0,
             source="", ev=None):
        domain, username, secret = self.canon_domain(domain), username.strip(), norm_secret(secret)
        row = self._find_cred(hid, domain, username, secret)
        t = now()
        if row is None:
            cur = self.db.execute(
                "INSERT INTO creds(host_id, port, domain, username, secret, kind, valid, admin, source, first_seen, last_seen)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (hid, port, domain, username, secret, kind, int(valid), int(admin), source, t, t))
            cid, created = cur.lastrowid, True
        else:
            cid, created = row["id"], False
            upd = {"valid": max(row["valid"], int(valid)), "admin": max(row["admin"], int(admin)), "last_seen": t}
            if secret and not row["secret"]:
                upd.update(secret=secret, kind=kind)
            if hid and not row["host_id"]:
                upd.update(host_id=hid, port=port)
            try:
                self._update("creds", cid, upd)
            except sqlite3.IntegrityError:
                pass
        self._seen(ev, "cred", cid)
        return cid, created

    def _absorb_cred(self, dst, src, keep_flags=()):
        """Une src en dst (dict con los valores finales de dst) y borra src."""
        upd = {"host_id": dst["host_id"] or src["host_id"], "port": dst["port"] or src["port"],
               "secret": dst["secret"] or src["secret"], "kind": dst["kind"] if dst["secret"] else src["kind"],
               "first_seen": min(dst["first_seen"], src["first_seen"]),
               "last_seen": max(dst["last_seen"], src["last_seen"])}
        for k in ("valid", "admin"):
            upd[k] = dst[k] if k in keep_flags else max(dst[k], src[k])
        # borrar src antes de actualizar dst para no chocar con UNIQUE
        self.db.execute("UPDATE OR IGNORE seen SET ref_id=? WHERE kind='cred' AND ref_id=?", (dst["id"], src["id"]))
        self.db.execute("DELETE FROM seen WHERE kind='cred' AND ref_id=?", (src["id"],))
        self.db.execute("DELETE FROM creds WHERE id=?", (src["id"],))
        dst.update(upd)
        return upd

    def dedupe_creds(self):
        """Une credenciales repetidas (legado, mayúsculas, alias de dominio). Devuelve cuántas eliminó."""
        groups = {}
        for r in self.q("SELECT * FROM creds ORDER BY id"):
            r = dict(r)
            dom, user = r["domain"], r["username"]
            if not dom and ("\\" in user or "/" in user):  # 'corp/user' guardado entero como usuario
                dom, user = re.split(r"[\\/]", user, maxsplit=1)
            r.update(domain=self.canon_domain(dom), username=user, secret=norm_secret(r["secret"]))
            key = (r["domain"].lower(), user.lower(), None if r["domain"] else r["host_id"])
            groups.setdefault(key, []).append(r)
        removed, survivors = 0, []
        for rows in groups.values():
            keep = {}
            has_secret = any(r["secret"] for r in rows)
            for r in rows:
                if has_secret and not r["secret"]:
                    target = next(x for x in rows if x["secret"])
                else:
                    target = keep.setdefault(r["secret"], r)
                if target is r:
                    continue
                self._absorb_cred(target, r)
                removed += 1
            survivors += keep.values()
        for r in survivors:
            self._update("creds", r["id"], {k: r[k] for k in ("domain", "username", "secret", "kind", "host_id",
                                                               "port", "valid", "admin", "first_seen", "last_seen")})
        self.db.commit()
        return removed

    def cred_update(self, cid, fields):
        """Modifica una credencial. Si queda igual a otra, la otra se une a esta. -> (fila, ids_unidos)"""
        row = self.one("SELECT * FROM creds WHERE id=?", (cid,))
        if row is None:
            return None, []
        new = dict(row, **fields)
        new["domain"] = self.canon_domain(new["domain"])
        new["secret"] = norm_secret(new["secret"])
        merged = []
        while True:
            dup = self._find_cred(new["host_id"], new["domain"], new["username"], new["secret"], exclude=cid)
            if dup is None:
                break
            self._absorb_cred(new, dict(dup), keep_flags=[k for k in ("valid", "admin") if k in fields])
            merged.append(dup["id"])
        self._update("creds", cid, {k: new[k] for k in ("domain", "username", "secret", "kind", "host_id", "port",
                                                         "valid", "admin", "source", "first_seen", "last_seen")})
        self.db.commit()
        return self.one("SELECT * FROM creds WHERE id=?", (cid,)), merged

    def cred_rm(self, cid):
        self.db.execute("DELETE FROM seen WHERE kind='cred' AND ref_id=?", (cid,))
        n = self.db.execute("DELETE FROM creds WHERE id=?", (cid,)).rowcount
        self.db.commit()
        return n

    def note(self, hid, text):
        self.db.execute("INSERT INTO notes(host_id, text, author, ts) VALUES(?,?,?,?)", (hid, text, operator(), now()))
        self.db.commit()

    # --- ingesta ---------------------------------------------------------------

    def ingest(self, records, ev=None):
        """Guarda registros normalizados. Devuelve ({tipo: (vistos, nuevos)}, ids de hosts tocados)."""
        seen, new = {}, {}

        def mark(kind, rid, created):
            seen.setdefault(kind, set()).add(rid)
            if created:
                new.setdefault(kind, set()).add(rid)

        for r in records:
            t = r.get("t")
            addr = r.get("addr") or ""
            hid = 0
            if addr:
                # solo los registros "host" traen atributos del host (un cred también tiene "domain")
                attrs = {k: r.get(k) or "" for k in ("os", "mac", "domain", "info")} if t == "host" else {}
                hid, c = self.host(addr, r.get("hostnames") or (), soft=t == "host" and r.get("soft", False),
                                   ev=ev, **attrs)
                mark("hosts", hid, c)
            port = int(r.get("port") or 0)
            proto = r.get("proto") or "tcp"
            if t == "service" and hid:
                mark("services", *self.service(hid, port, proto, state=r.get("state") or "open",
                                                soft=r.get("soft", False), ev=ev,
                                                **{k: r.get(k) or "" for k in (*SVC_FIELDS, "banner")}))
            elif port and hid:
                self.service(hid, port, proto, soft=True, ev=ev)
            if t == "web" and hid:
                mark("web", *self.web(hid, port, r["url"], r.get("status"), r.get("title") or "",
                                      r.get("tech") or "", r.get("server") or "", ev=ev))
            elif t == "finding" and hid:
                mark("findings", *self.finding(hid, port, r.get("source") or "", r.get("ref") or "",
                                               r.get("title") or "", r.get("severity") or "info",
                                               r.get("location") or "", r.get("detail") or "", ev=ev))
            elif t == "cred" and r.get("username"):
                mark("creds", *self.cred(hid, port, r.get("domain") or "", r["username"], r.get("secret") or "",
                                         r.get("kind") or "password", r.get("valid", 0), r.get("admin", 0),
                                         r.get("source") or "", ev=ev))
        self.db.commit()
        stats = {k: (len(v), len(new.get(k, ()))) for k, v in seen.items()}
        return stats, sorted(seen.get("hosts", ()))

    # --- evidencia -------------------------------------------------------------

    def ev_start(self, cmd, tool):
        cur = self.db.execute("INSERT INTO evidence(ts_start, operator, cwd, cmd, tool) VALUES(?,?,?,?,?)",
                              (now(), operator(), os.getcwd(), cmd, tool))
        self.db.commit()
        return cur.lastrowid

    def ev_finish(self, eid, raw=None, tool=None, fmt="", exit_code=None, attach=(), summary="", cmd=None):
        tool = tool or self.one("SELECT tool FROM evidence WHERE id=?", (eid,))["tool"]
        safe = re.sub(r"[^\w.-]", "_", tool)[:40] or "raw"
        files, digest = [], hashlib.sha256()
        if raw:
            p = self.evdir / f"{eid:04d}-{safe}.log"
            p.write_text(raw)
            files.append(p.name)
            digest.update(raw.encode())
        for a in attach:
            a = Path(a)
            if a.is_file():
                dest = self.evdir / f"{eid:04d}-{a.name}"
                shutil.copy2(a, dest)
                files.append(dest.name)
                digest.update(dest.read_bytes())
        fields = {"ts_end": now(), "tool": tool, "fmt": fmt or "", "exit_code": exit_code,
                  "files": ",".join(files), "sha256": digest.hexdigest(), "summary": summary}
        if cmd:
            fields["cmd"] = cmd
        self._update("evidence", eid, fields)
        self.db.commit()

    # --- scope -----------------------------------------------------------------

    def rules(self):
        if self._rules is None:
            rows = self.q("SELECT kind, value FROM scope ORDER BY kind, value")
            self._rules = ([r["value"] for r in rows if r["kind"] == "include"],
                           [r["value"] for r in rows if r["kind"] == "exclude"])
        return self._rules

    def scope_set(self, kind, values):
        for v in values:
            self.db.execute("INSERT OR IGNORE INTO scope(kind, value) VALUES(?,?)", (kind, v.strip().lower()))
        self.db.commit()
        self._rules = None

    def scope_rm(self, values):
        for v in values:
            self.db.execute("DELETE FROM scope WHERE value=?", (v.strip().lower(),))
        self.db.commit()
        self._rules = None

    def in_scope(self, target):
        """True/False según las reglas; None si no hay scope definido."""
        inc, exc = self.rules()
        if not inc and not exc:
            return None
        target = norm_addr(target)
        if any(_overlaps(target, r) for r in exc):
            return False
        return not inc or any(_match(target, r) for r in inc)
