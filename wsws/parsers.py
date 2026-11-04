"""Parsers: convierten la salida de herramientas en registros normalizados.

Cada registro es un dict con "t" en {host, service, web, finding, cred} y "addr"
(IP u hostname). Store.ingest() sabe consumirlos. parse() detecta el formato solo.
"""
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from urllib.parse import urlsplit

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\r")
HOSTNAME_RE = re.compile(r"(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}", re.I)
SEV_WORDS = ("info", "low", "medium", "high", "critical")
DEFAULT_PORTS = {"http": 80, "https": 443}


def strip_ansi(text):
    return ANSI_RE.sub("", text)


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_hostname(s):
    return bool(s) and bool(HOSTNAME_RE.fullmatch(s))


def split_target(s):
    """'https://a.b:8443/x' | 'a.b:22' | '[::1]:80' | 'a.b' -> (host, port|None, scheme)."""
    s = (s or "").strip()
    if not s:
        return "", None, ""
    if is_ip(s):
        return s, None, ""
    if "://" not in s:
        s = "//" + s
    try:
        u = urlsplit(s)
        port = u.port
    except ValueError:
        return "", None, ""
    scheme = u.scheme.lower()
    return (u.hostname or ""), port or DEFAULT_PORTS.get(scheme), scheme


def norm_svc(name):
    name = (name or "").rstrip("?").replace("|", "/")
    if name.startswith("ssl/") and name[4:].startswith("http"):
        return "https"
    return name


# --- constructores de registros ------------------------------------------------

def host(addr, **kw):
    return {"t": "host", "addr": addr, **kw}


def service(addr, port, **kw):
    return {"t": "service", "addr": addr, "port": int(port), **kw}


def web(addr, port, url, **kw):
    return {"t": "web", "addr": addr, "port": int(port or 0), "url": url, **kw}


def finding(addr, port, **kw):
    return {"t": "finding", "addr": addr, "port": int(port or 0), **kw}


def cred(addr, **kw):
    return {"t": "cred", "addr": addr, **kw}


# --- nmap ----------------------------------------------------------------------

VULN_STATE_RE = re.compile(r"State:\s*(LIKELY )?VULNERABLE", re.I)


def nse_findings(addr, port, scripts):
    """Convierte salidas NSE con 'State: VULNERABLE' en hallazgos."""
    out = []
    for sid, text in scripts:
        if not VULN_STATE_RE.search(text):
            continue
        lines = [ln.strip(" |_") for ln in text.splitlines()]
        title = sid
        for i, ln in enumerate(lines):
            if ln.upper().startswith("VULNERABLE"):
                nxt = next((x for x in lines[i + 1:] if x), "")
                if nxt and not nxt.startswith("State:"):
                    title = nxt
                break
        risk = re.search(r"Risk factor:\s*(\w+)", text, re.I)
        sev = risk.group(1).lower() if risk and risk.group(1).lower() in SEV_WORDS else "high"
        cves = sorted({c.upper() for c in re.findall(r"CVE-\d{4}-\d+", text, re.I)})
        out.append(finding(addr, port, source="nmap", ref=sid, title=title, severity=sev,
                           location=f"{addr}:{port}" if port else addr,
                           detail=(" ".join(cves) + "\n" + text).strip()[:4000]))
    return out


def parse_nmap_xml(text):
    start = text.find("<?xml")
    text = text[start if start >= 0 else text.find("<nmaprun"):]
    end = text.rfind("</nmaprun>")
    try:
        root = ET.fromstring(text[:end + 10] if end >= 0 else text)
    except ET.ParseError:
        # scan interrumpido (Ctrl-C): rescatar los hosts completos
        cut = text.rfind("</host>")
        if cut < 0:
            return []
        root = ET.fromstring(text[:cut + 7] + "</nmaprun>")
    out = []
    for h in root.iter("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        addr, mac = None, ""
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6") and not addr:
                addr = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac = a.get("addr", "") + (f" ({a.get('vendor')})" if a.get("vendor") else "")
        if not addr:
            continue
        names = [n.get("name") for n in h.findall("hostnames/hostname") if n.get("name")]
        osm = h.find("os/osmatch")
        out.append(host(addr, hostnames=names, os=osm.get("name", "") if osm is not None else "", mac=mac))
        for p in h.findall("ports/port"):
            state_el = p.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if not state.startswith("open"):
                continue
            port = int(p.get("portid"))
            sv = p.find("service")
            f = {"name": "", "product": "", "version": "", "extra": ""}
            if sv is not None:
                name = sv.get("name", "")
                if sv.get("tunnel") == "ssl" and name.startswith("http"):
                    name = "https"
                # method="table" = nmap solo adivinó por el número de puerto: no pisar datos de -sV
                f = {"name": name, "product": sv.get("product", ""), "version": sv.get("version", ""),
                     "extra": sv.get("extrainfo", ""), "soft": sv.get("method") == "table"}
                if sv.get("ostype"):
                    out.append(host(addr, os=sv.get("ostype"), soft=True))
            scripts = [(s.get("id"), (s.get("output") or "").strip()) for s in p.findall("script")]
            out.append(service(addr, port, proto=p.get("protocol", "tcp"), state=state,
                               banner="\n".join(f"{i}: {o}" for i, o in scripts), **f))
            out += nse_findings(addr, port, scripts)
        hs = [(s.get("id"), (s.get("output") or "").strip()) for s in h.findall("hostscript/script")]
        if hs:
            out.append(host(addr, info="\n".join(f"{i}: {o}" for i, o in hs)))
            out += nse_findings(addr, 0, hs)
    return out


REPORT_RE = re.compile(r"^Nmap scan report for (\S+)(?: \(([^)]+)\))?(.*)$")
PORT_RE = re.compile(r"^(\d+)/(tcp|udp|sctp)\s+(\S+)\s+(\S+)(?:\s+(.*?))?\s*$")
SCRIPT_RE = re.compile(r"^ ?([a-z0-9]+(?:-[\w.]+)+|banner):(?: (.*))?$", re.I)


def parse_nmap_text(text):
    """Salida normal de nmap (la que ves en pantalla / -oN)."""
    out, addr, bucket, hostscripts = [], None, None, {}
    for raw in text.splitlines():
        line = raw.rstrip()
        m = REPORT_RE.match(line)
        if m:
            name, ip, rest = m.groups()
            bucket = None
            addr = None if "host down" in rest else (ip or name)
            if addr:
                out.append(host(addr, hostnames=[name] if ip else []))
            continue
        if addr is None:
            continue
        m = PORT_RE.match(line)
        if m:
            port, proto, state, svc, ver = m.groups()
            bucket = None
            if state.startswith("open"):
                rec = service(addr, port, proto=proto, state=state, name=norm_svc(svc), product=ver or "",
                              soft=ver is None, _scripts=[])
                out.append(rec)
                bucket = rec["_scripts"]
            continue
        if line.startswith("Host script results"):
            bucket = hostscripts.setdefault(addr, [])
            continue
        if line.startswith("|") and bucket is not None:
            body = line[1:]
            body = body[1:] if body.startswith("_") else body
            m = SCRIPT_RE.match(body)
            if m:
                bucket.append([m.group(1), [m.group(2) or ""]])
            elif bucket:
                bucket[-1][1].append(body.strip())
            continue
        bucket = None
        if line.startswith("MAC Address:"):
            out.append(host(addr, mac=line.split(":", 1)[1].strip()))
        elif line.startswith(("Running:", "OS details:")):
            out.append(host(addr, os=line.split(":", 1)[1].strip()))
        elif line.startswith("Service Info:"):
            m_os = re.search(r"OS: ([^;]+)", line)
            m_host = re.search(r"Host: ([^;]+)", line)
            out.append(host(addr, os=m_os.group(1).strip() if m_os else "",
                            hostnames=[m_host.group(1).strip()] if m_host else [], soft=True))
    final = []
    for r in out:
        sc = r.pop("_scripts", None)
        final.append(r)
        if sc:
            pairs = [(sid, "\n".join(lines).strip()) for sid, lines in sc]
            r["banner"] = "\n".join(f"{s}: {o}" for s, o in pairs)
            final += nse_findings(r["addr"], r["port"], pairs)
    for a, sc in hostscripts.items():
        pairs = [(sid, "\n".join(lines).strip()) for sid, lines in sc]
        final.append(host(a, info="\n".join(f"{s}: {o}" for s, o in pairs)))
        final += nse_findings(a, 0, pairs)
    return final


GNMAP_RE = re.compile(r"^Host: (\S+) \(([^)]*)\)\t(.*)$", re.M)


def parse_gnmap(text):
    out = []
    for m in GNMAP_RE.finditer(text):
        addr, name, rest = m.groups()
        fields = dict(f.split(": ", 1) for f in rest.split("\t") if ": " in f)
        if fields.get("Status", "Up") != "Up":
            continue
        out.append(host(addr, hostnames=[name] if name else [], os=fields.get("OS", "")))
        for entry in fields.get("Ports", "").split(", "):
            parts = entry.split("/")
            if len(parts) < 7 or not parts[1].startswith("open"):
                continue
            port, state, proto, _, svc, _, ver = parts[:7]
            out.append(service(addr, port, proto=proto, state=state, name=norm_svc(svc),
                               product=ver.replace("|", "/")))
    return out


# --- Nessus --------------------------------------------------------------------

NESSUS_SEV = {1: "low", 2: "medium", 3: "high", 4: "critical"}


def parse_nessus(text):
    root = ET.fromstring(text[text.find("<"):])
    out = []
    for rh in root.iter("ReportHost"):
        props = {t.get("name"): (t.text or "") for t in rh.findall("HostProperties/tag")}
        addr = props.get("host-ip") or rh.get("name")
        names = [x for x in (props.get("host-fqdn"), props.get("netbios-name")) if x]
        out.append(host(addr, hostnames=names, os=props.get("operating-system", "").split("\n")[0],
                        mac=props.get("mac-address", "").split("\n")[0]))
        for it in rh.findall("ReportItem"):
            port, proto = int(it.get("port", "0")), it.get("protocol", "tcp")
            svc = it.get("svc_name", "")
            svc = {"www": "http", "general": "", "unknown": ""}.get(svc, svc)
            if port:
                out.append(service(addr, port, proto=proto, name=norm_svc(svc), soft=True))
            sev = int(it.get("severity", "0"))
            if sev >= 1:
                cves = " ".join(c.text for c in it.findall("cve") if c.text)
                pout = (it.findtext("plugin_output") or "").strip()
                out.append(finding(addr, port, source="nessus", ref=it.get("pluginID", ""),
                                   title=it.get("pluginName", ""), severity=NESSUS_SEV.get(sev, "critical"),
                                   location=f"{addr}:{port}/{proto}", detail=(cves + "\n" + pout).strip()[:4000]))
    return out


# --- JSON (ProjectDiscovery, masscan) -----------------------------------------

def parse_nuclei(o):
    info = o.get("info") or {}
    tid = o.get("template-id") or o.get("templateID") or ""
    target = o.get("host") or ""
    matched = o.get("matched-at") or o.get("matched") or target
    hn, port, scheme = split_target(target or matched)
    port = port or (int(o["port"]) if str(o.get("port", "")).isdigit() else None)
    addr = o.get("ip") or hn
    if not addr:
        return []
    title = info.get("name") or tid
    if o.get("matcher-name"):
        title += f" [{o['matcher-name']}]"
    cls = info.get("classification") or {}
    cves = cls.get("cve-id") or []
    cves = [cves] if isinstance(cves, str) else cves
    detail = "\n".join(x for x in (" ".join(c.upper() for c in cves),
                                   ", ".join(o.get("extracted-results") or []),
                                   (info.get("description") or "").strip()[:1000]) if x)
    recs = [host(addr, hostnames=[hn] if hn and hn != addr and not is_ip(hn) else [])]
    if port:
        recs.append(service(addr, port, name=scheme, soft=True))
    sev = str(info.get("severity", "info")).lower()
    recs.append(finding(addr, port, source="nuclei", ref=tid, title=title,
                        severity=sev if sev in SEV_WORDS else "info", location=matched, detail=detail))
    return recs


def parse_httpx(o):
    if o.get("failed"):
        return []
    url = o.get("url") or ""
    hn, port, scheme = split_target(url)
    if str(o.get("port", "")).isdigit():
        port = int(o["port"])
    ip = o.get("host") if is_ip(o.get("host") or "") else ((o.get("a") or [None])[0])
    addr = ip or hn
    if not addr or not port:
        return []
    tech = o.get("tech") or o.get("technologies") or []
    return [host(addr, hostnames=[hn] if hn and not is_ip(hn) and hn != addr else []),
            service(addr, port, name=scheme, soft=True),
            web(addr, port, url, status=o.get("status_code", o.get("status-code")), title=o.get("title") or "",
                tech=", ".join(tech) if isinstance(tech, list) else str(tech), server=o.get("webserver") or "")]


def parse_naabu(o):
    hn = o.get("host") or ""
    addr = o.get("ip") or hn
    if not addr:
        return []
    return [host(addr, hostnames=[hn] if hn and hn != addr and not is_ip(hn) else []),
            service(addr, o["port"], proto=o.get("protocol") or "tcp")]


def parse_masscan_obj(o):
    out = []
    for p in o.get("ports") or []:
        if not p.get("port"):
            continue
        sv = p.get("service") or {}
        out.append(service(o["ip"], p["port"], proto=p.get("proto", "tcp"), state=p.get("status", "open"),
                           name=sv.get("name", ""), banner=sv.get("banner", ""), soft=True))
    return out


def from_json(o):
    if "template-id" in o or "templateID" in o:
        return parse_nuclei(o), "nuclei"
    if "ports" in o and "ip" in o:
        return parse_masscan_obj(o), "masscan"
    if "url" in o and any(k in o for k in ("status_code", "status-code", "title", "webserver", "tech")):
        return parse_httpx(o), "httpx"
    if "port" in o and ("ip" in o or "host" in o):
        return parse_naabu(o), "naabu"
    return [], None


# --- formatos de línea (nxc, masscan, rustscan, nuclei/httpx texto, listas) -----

NXC_RE = re.compile(r"^([A-Z][A-Z0-9]{1,9})\s+(\S+)\s+(\d{1,5})\s+(\S+)\s+(.*)$")
SAMDUMP_RE = re.compile(r"^(?:([^\\\s]+)\\)?([^:\s]+):(\d+):([0-9a-f]{32}):([0-9a-f]{32}):::", re.I)
HASH_RE = re.compile(r"(?:[0-9a-f]{32}:)?[0-9a-f]{32}", re.I)
MASSCAN_DISC_RE = re.compile(r"^Discovered open port (\d+)/(\w+) on (\S+)")
MASSCAN_LIST_RE = re.compile(r"^(open|banner) (tcp|udp|sctp) (\d+) (\S+) \d+(?: (\S+) (.*))?$")
RUSTSCAN_RE = re.compile(r"^Open (\S+):(\d+)$")
NUCLEI_TXT_RE = re.compile(r"\[([\w.:/-]+)\] \[(\w+)\] \[(info|low|medium|high|critical|unknown)\] (\S+)(.*)$", re.I)
URL_RE = re.compile(r"^(https?://\S+)(.*)$", re.I)


def parse_cred(s):
    """'corp\\user:pass' | 'corp/user:pass@10.0.0.5' (impacket) | 'user@corp.local:pass' (UPN) | 'user'
    -> (dominio, usuario, secreto, host)"""
    s = s.strip()
    head, sep, secret = s.partition(":")
    m = re.match(r"^([^\\/]+)[\\/](.+)$", head)
    domain, user = (m.group(1), m.group(2)) if m else ("", head)
    target = ""
    if "@" in (secret if sep else user):  # @host al final, estilo impacket (o UPN si no hay dominio)
        base, _, tail = (secret if sep else user).rpartition("@")
        if is_ip(tail) or is_hostname(tail):
            if not sep and not domain and not is_ip(tail):
                domain, user = tail, base
            elif sep:
                secret, target = base, tail
            else:
                user, target = base, tail
    if not domain and "@" in user:
        user, _, domain = user.rpartition("@")
    return domain, user, secret, target


def parse_nxc(proto, addr, port, name, msg):
    if not (is_ip(addr) or is_hostname(addr)):
        return None
    svc = proto.lower()
    recs = [service(addr, port, name=svc, soft=True)]
    kv = dict(re.findall(r"\((\w+):([^)]*)\)", msg))
    if msg.startswith("[*]") and ("name" in kv or "domain" in kv):
        hn, dom = kv.get("name") or name, kv.get("domain", "")
        names = [hn]
        if dom and "." in dom and hn.lower() != dom.lower():
            names.append(f"{hn}.{dom}")
        recs.insert(0, host(addr, hostnames=names, os=msg[3:].split(" (", 1)[0].strip(), domain=dom))
        loc = f"{addr}:{port}"
        if svc == "smb" and kv.get("signing", "").lower() == "false":
            recs.append(finding(addr, port, source="nxc", ref="smb-signing-disabled", severity="medium",
                                title="SMB signing no requerido (NTLM relay posible)", location=loc))
        if kv.get("SMBv1", "").lower() == "true":
            recs.append(finding(addr, port, source="nxc", ref="smbv1-enabled", severity="medium",
                                title="SMBv1 habilitado", location=loc))
        return recs
    if msg.startswith("[+]"):
        body = msg[3:].strip()
        tok = body.split()[0] if body else ""
        if "\\" in tok or ":" in tok:
            dom, _, up = tok.rpartition("\\")
            user, _, secret = up.partition(":")
            if user:
                recs.append(cred(addr, port=int(port), domain=dom, username=user, secret=secret,
                                 kind="hash" if HASH_RE.fullmatch(secret) else "password",
                                 valid=1, admin=int("Pwn3d!" in body), source=f"nxc {svc}"))
        return recs
    m = SAMDUMP_RE.match(msg)
    if m:
        dom, user, _, _, nt = m.groups()
        recs.append(cred(addr, port=int(port), domain=dom or name, username=user, secret=nt,
                         kind="ntlm", valid=0, admin=0, source=f"nxc {svc} dump"))
    return recs


def parse_httpx_text(url, rest):
    hn, port, scheme = split_target(url)
    if not hn or not port:
        return []
    bits = re.findall(r"\[([^\]]*)\]", rest)
    status = next((int(b) for b in bits if re.fullmatch(r"\d{3}", b)), None)
    others = [b for b in bits if b and not re.fullmatch(r"[\d,]+", b)]
    return [service(hn, port, name=scheme, soft=True),
            web(hn, port, url, status=status, title=others[0] if others else "", tech=", ".join(others[1:]))]


def parse_line(line):
    if line.startswith(("{", ",{")):
        try:
            o = json.loads(line.strip(","))
        except ValueError:
            o = None
        if isinstance(o, dict):
            return from_json(o)
    m = NXC_RE.match(line)
    if m:
        recs = parse_nxc(*m.groups())
        if recs is not None:
            return recs, "nxc"
    m = MASSCAN_DISC_RE.match(line)
    if m:
        return [service(m.group(3), m.group(1), proto=m.group(2))], "masscan"
    m = MASSCAN_LIST_RE.match(line)
    if m:
        kind, proto, port, addr, svc, banner = m.groups()
        if kind == "open":
            return [service(addr, port, proto=proto)], "masscan"
        return [service(addr, port, proto=proto, name=svc or "", banner=banner or "", soft=True)], "masscan"
    m = RUSTSCAN_RE.match(line)
    if m:
        return [service(m.group(1), m.group(2))], "rustscan"
    m = NUCLEI_TXT_RE.search(line)
    if m:
        tid, _, sev, target, extra = m.groups()
        hn, port, scheme = split_target(target)
        if hn:
            recs = [host(hn)]
            if port:
                recs.append(service(hn, port, name=scheme, soft=True))
            recs.append(finding(hn, port, source="nuclei", ref=tid, title=tid, severity=sev.lower()
                                if sev.lower() in SEV_WORDS else "info", location=target, detail=extra.strip()))
            return recs, "nuclei"
    m = URL_RE.match(line)
    if m:
        return parse_httpx_text(*m.groups()), "httpx"
    if " " in line or "\t" in line:
        return [], None
    h, port, _ = split_target(line)
    if port and (is_ip(h) or is_hostname(h)):
        return [service(h, port)], "lista"
    if is_ip(line) or is_hostname(line):
        return [host(line)], "lista"
    return [], None


def parse_lines(text):
    out, kinds = [], Counter()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        recs, kind = parse_line(line)
        if recs:
            out += recs
            kinds[kind] += 1
    return (kinds.most_common(1)[0][0] if kinds else "desconocido"), out


def parse(text):
    """Detecta el formato y devuelve (nombre_formato, registros)."""
    text = strip_ansi(text)
    head = text[:4096]
    if "<nmaprun" in head:
        return "nmap-xml", parse_nmap_xml(text)
    if "NessusClientData_v2" in head:
        return "nessus", parse_nessus(text)
    if "Nmap scan report for" in text:
        return "nmap", parse_nmap_text(text)
    if GNMAP_RE.search(text):
        return "gnmap", parse_gnmap(text)
    s = text.lstrip()
    if s.startswith("["):
        try:
            data = json.loads(s)
        except ValueError:
            data = None
        if isinstance(data, list):
            out, kinds = [], Counter()
            for o in data:
                if isinstance(o, dict):
                    recs, kind = from_json(o)
                    out += recs
                    if kind:
                        kinds[kind] += 1
            if out:
                return kinds.most_common(1)[0][0], out
    return parse_lines(text)
