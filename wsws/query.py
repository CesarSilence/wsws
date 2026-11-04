"""Lenguaje de búsqueda: 'clave:valor', números = puertos, IP/CIDR = red, resto = texto libre.

Ejemplos:  445 os:windows        svc:http -tag:revisado        sev:high new:2h
"""
import re
from datetime import datetime, timedelta, timezone

from .parsers import is_ip
from .store import SEV, TS_FMT, as_net

ALIASES = {
    "p": "port", "port": "port", "proto": "proto", "s": "svc", "svc": "svc", "service": "svc",
    "product": "product", "prod": "product", "ver": "product", "version": "product", "os": "os",
    "h": "host", "host": "host", "name": "host", "net": "net", "cidr": "net", "ip": "net",
    "tag": "tag", "t": "tag", "domain": "domain", "dom": "domain", "sev": "sev", "severity": "sev",
    "vuln": "vuln", "cve": "vuln", "finding": "vuln", "title": "title", "tech": "tech", "url": "url",
    "new": "new", "since": "new", "scope": "scope", "has": "has", "state": "state", "user": "user",
    "src": "source", "source": "source", "text": "text", "q": "text",
}
# nombre común -> (nombres que usa nmap, puertos típicos). svc:smb encuentra microsoft-ds y netbios-ssn,
# y también 139/445 sin nombre (naabu, masscan y listas no traen el servicio).
SVC_SYNONYMS = {
    "smb": (["smb", "microsoft-ds", "netbios-ssn"], [139, 445]), "rdp": (["rdp", "ms-wbt-server"], [3389]),
    "winrm": (["winrm", "wsman"], [5985, 5986]), "mssql": (["mssql", "ms-sql"], [1433]),
    "dns": (["dns", "domain"], [53]), "kerberos": (["kerberos"], [88]), "ldap": (["ldap"], [389, 636, 3268, 3269]),
    "vnc": (["vnc"], [5900]), "nfs": (["nfs"], [2049]), "rpc": (["rpc"], [135]),
}
PORT_LIST_RE = re.compile(r"\d+(-\d+)?(,\d+(-\d+)?)*")
HOST_TEXT = ("COALESCE(h.addr,'')||' '||COALESCE(h.hostnames,'')||' '||COALESCE(h.os,'')||' '||"
             "COALESCE(h.domain,'')||' '||COALESCE(h.tags,'')||' '||COALESCE(h.info,'')")
VIEWS = {
    "svc": {"port": "s.port", "ts": "COALESCE(s.first_seen, h.first_seen)", "pm": "(x.port = s.port OR x.port = 0)",
            "text": HOST_TEXT + "||' '||COALESCE(s.name,'')||' '||COALESCE(s.product,'')||' '||COALESCE(s.version,'')"
                                "||' '||COALESCE(s.extra,'')||' '||COALESCE(s.banner,'')"},
    "finding": {"port": "f.port", "ts": "f.first_seen", "pm": "x.port = f.port",
                "text": "f.title||' '||f.ref||' '||f.detail||' '||f.location||' '||f.source||' '||" + HOST_TEXT},
    "web": {"port": "w.port", "ts": "w.first_seen", "pm": "x.port = w.port",
            "text": "w.url||' '||w.title||' '||w.tech||' '||w.server||' '||" + HOST_TEXT},
    "cred": {"port": "c.port", "ts": "c.first_seen", "pm": "1",
             "text": "c.domain||' '||c.username||' '||c.kind||' '||c.source||' '||" + HOST_TEXT},
}


class QueryError(ValueError):
    pass


def parse_terms(tokens):
    """-> [(negado, clave, valor)]"""
    terms, neg = [], False
    for tok in tokens:
        if tok.lower() == "not":
            neg = True
            continue
        n, neg = neg, False
        if tok.startswith("-") and len(tok) > 1:
            n, tok = True, tok[1:]
        key = val = None
        if ":" in tok and not is_ip(tok):
            k, v = tok.split(":", 1)
            if k.lower() in ALIASES and v:
                key, val = ALIASES[k.lower()], v
        if key is None:
            if PORT_LIST_RE.fullmatch(tok):
                key, val = "port", tok
            elif as_net(tok):
                key, val = "net", tok
            else:
                key, val = "text", tok
        terms.append((n, key, val))
    return terms


def _since(v):
    m = re.fullmatch(r"(\d+)([mhdw])", v)
    if m:
        delta = timedelta(**{{"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}[m.group(2)]: int(m.group(1))})
        return (datetime.now(timezone.utc) - delta).strftime(TS_FMT)
    try:
        return datetime.fromisoformat(v).astimezone(timezone.utc).strftime(TS_FMT)
    except ValueError:
        raise QueryError(f"new:/since: espera 30m, 2h, 3d, 1w o una fecha (2026-10-19): {v!r}")


def _like(v):
    return f"%{v}%"


def _clause(view, key, val):
    V = VIEWS[view]

    def exists(table, cond, *params, port=True):
        pm = f" AND {V['pm']}" if port else ""
        return f"EXISTS(SELECT 1 FROM {table} x WHERE x.host_id = h.id{pm} AND {cond})", list(params)

    if key == "port":
        parts, params = [], []
        for p in val.split(","):
            if not p:
                continue
            a, _, b = p.partition("-")
            if not a.isdigit() or (b and not b.isdigit()):
                raise QueryError(f"puerto inválido: {p!r}")
            parts.append(f"{V['port']} BETWEEN ? AND ?" if b else f"{V['port']} = ?")
            params += [int(a), int(b)] if b else [int(a)]
        return "(" + " OR ".join(parts) + ")", params
    if key == "svc" and val.lower() in SVC_SYNONYMS:
        names, ports = SVC_SYNONYMS[val.lower()]
        cond = ("(" + " OR ".join(["{a}.name LIKE ?"] * len(names)) +
                f" OR (COALESCE({{a}}.name, '') = '' AND {{a}}.port IN ({','.join(map(str, ports))})))")
        params = [_like(n) for n in names]
        if view == "svc":
            return cond.format(a="s"), params
        return exists("services", cond.format(a="x"), *params)
    if key in ("svc", "product", "proto", "state"):
        col = {"svc": "name", "product": "product||' '||{a}.version", "proto": "proto", "state": "state"}[key]
        if view == "svc":
            return f"(s.{col.format(a='s')} LIKE ?)", [_like(val)]
        if key == "state":
            return "1", []
        return exists("services", f"x.{col.format(a='x')} LIKE ?", _like(val))
    if key == "os":
        return "h.os LIKE ?", [_like(val)]
    if key == "host":
        return "(h.addr LIKE ? OR h.hostnames LIKE ?)", [_like(val)] * 2
    if key == "net":
        if not as_net(val):
            raise QueryError(f"red inválida: {val!r}")
        return "in_net(h.addr, ?) = 1", [val]
    if key == "tag":
        return "(','||h.tags||',') LIKE ?", [f"%,{val},%"]
    if key == "domain":
        if view == "cred":
            return "(c.domain LIKE ? OR COALESCE(h.domain, '') LIKE ?)", [_like(val)] * 2
        return "(h.domain LIKE ? OR h.hostnames LIKE ?)", [_like(val)] * 2
    if key == "scope":
        if val not in ("in", "out"):
            raise QueryError("scope: espera 'in' u 'out'")
        return f"in_scope(h.addr) = {1 if val == 'in' else 0}", []
    if key == "sev":
        v = val.lower()
        n = int(v) if v.isdigit() else SEV.get(v, SEV.get({"crit": "critical", "med": "medium"}.get(v, ""), None))
        if n is None:
            raise QueryError("sev: espera info|low|medium|high|critical (significa 'o mayor')")
        return ("f.sev >= ?", [n]) if view == "finding" else exists("findings", "x.sev >= ?", n)
    if key in ("vuln", "source") and view == "finding":
        return ("(f.title||' '||f.ref||' '||f.detail) LIKE ?" if key == "vuln" else "f.source LIKE ?"), [_like(val)]
    if key == "vuln":
        return exists("findings", "(x.title||' '||x.ref||' '||x.detail) LIKE ?", _like(val))
    if key == "source":
        if view == "cred":
            return "c.source LIKE ?", [_like(val)]
        return exists("findings", "x.source LIKE ?", _like(val))
    if key in ("title", "tech", "url"):
        if view == "web":
            return f"w.{key} LIKE ?", [_like(val)]
        return exists("web", f"x.{key} LIKE ?", _like(val))
    if key == "user":
        if view == "cred":
            return "c.username LIKE ?", [_like(val)]
        return exists("creds", "x.username LIKE ?", _like(val), port=False)
    if key == "has":
        conds = {"creds": ("creds", "1"), "cred": ("creds", "1"), "admin": ("creds", "x.admin = 1"),
                 "vuln": ("findings", "x.sev >= 1"), "vulns": ("findings", "x.sev >= 1"),
                 "web": ("web", "1"), "notes": ("notes", "1"), "note": ("notes", "1")}
        if val not in conds:
            raise QueryError("has: espera creds|admin|vuln|web|notes")
        table, cond = conds[val]
        return exists(table, cond, port=False)
    if key == "new":
        return f"{V['ts']} >= ?", [_since(val)]
    if key == "text":
        sql, params = f"(({V['text']}) LIKE ?", [_like(val)]
        if view == "svc":
            for table, cols in (("web", "x.url||' '||x.title||' '||x.tech||' '||x.server"),
                                ("findings", "x.title||' '||x.ref||' '||x.detail"), ("notes", "x.text")):
                pm = "" if table == "notes" else f" AND {V['pm']}"
                sql += f" OR EXISTS(SELECT 1 FROM {table} x WHERE x.host_id = h.id{pm} AND ({cols}) LIKE ?)"
                params.append(_like(val))
        return sql + ")", params
    raise QueryError(f"filtro desconocido: {key}")


def build(view, terms):
    where, params = [], []
    for neg, key, val in terms:
        sql, p = _clause(view, key, val)
        where.append(f"NOT COALESCE(({sql}), 0)" if neg else sql)
        params += p
    return where, params


def _run(st, view, select, terms, order, extra=()):
    where, params = build(view, terms)
    where += list(extra)
    return [dict(r) for r in st.q(f"{select} WHERE {' AND '.join(where) or '1'} ORDER BY {order}", params)]


def find(st, terms, all_states=False):
    extra = [] if all_states or any(k == "state" for _, k, _ in terms) else ["(s.id IS NULL OR s.state LIKE 'open%')"]
    return _run(st, "svc",
                "SELECT h.id hid, h.addr, h.hostnames, h.os, h.domain, h.tags, s.id sid, s.port, s.proto, s.state,"
                " s.name, s.product, s.version, s.extra, s.banner, COALESCE(s.first_seen, h.first_seen) first_seen,"
                " COALESCE(s.last_seen, h.last_seen) last_seen FROM hosts h LEFT JOIN services s ON s.host_id = h.id",
                terms, "ipkey(h.addr), s.port", extra)


def findings(st, terms):
    return _run(st, "finding", "SELECT f.*, h.addr, h.hostnames FROM findings f JOIN hosts h ON h.id = f.host_id",
                terms, "f.sev DESC, ipkey(h.addr), f.port")


def web(st, terms):
    return _run(st, "web", "SELECT w.*, h.addr, h.hostnames FROM web w JOIN hosts h ON h.id = w.host_id",
                terms, "ipkey(h.addr), w.port, w.url")


def creds(st, terms):
    return _run(st, "cred", "SELECT c.*, h.addr, h.hostnames FROM creds c LEFT JOIN hosts h ON h.id = c.host_id",
                terms, "c.admin DESC, c.valid DESC, c.domain, c.username")
