"""Validador de vulnerabilidades conocidas a partir del recon guardado (solo detección, nada de explotación).

Cada check toma los objetivos desde el workspace (p. ej. hosts con 445 abierto), ejecuta un checker externo
conocido y guarda el resultado: hallazgo validado si es vulnerable y una etiqueta por host (<check>:vuln / :no).

    eternalblue     nmap --script smb-vuln-ms17-010,smb-double-pulsar-backdoor   (445)
    bluekeep        rdpscan                                                      (3389)
    printnightmare  printnightmare_check_combo.py (github.com/CesarSilence/PrintNightmare), requiere creds (445)
"""
import json
import re
import shlex
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

from . import store as S

CHECKS = {
    "eternalblue": {"title": "EternalBlue (MS17-010) + DoublePulsar", "port": 445, "tool": "nmap",
                    "aliases": ("ms17", "ms17-010", "eb", "doublepulsar", "dp")},
    "bluekeep": {"title": "BlueKeep (CVE-2019-0708)", "port": 3389, "tool": "rdpscan",
                 "aliases": ("bk", "cve-2019-0708")},
    "printnightmare": {"title": "PrintNightmare (CVE-2021-34527)", "port": 445, "tool": "printnightmare",
                       "aliases": ("pn", "cve-2021-34527", "cve-2021-1675"), "creds": True},
}
ALIASES = {a: k for k, v in CHECKS.items() for a in (k, *v["aliases"])}

# resultado -> hallazgo (solo cuando es vulnerable)
FINDINGS = {
    "eternalblue": ("CVE-2017-0144", "EternalBlue (MS17-010) - vulnerable (validado)", 445),
    "doublepulsar": ("doublepulsar", "DoublePulsar - backdoor SMB detectado (validado)", 445),
    "bluekeep": ("CVE-2019-0708", "BlueKeep (CVE-2019-0708) - vulnerable (validado)", 3389),
    "printnightmare": ("CVE-2021-34527", "PrintNightmare (CVE-2021-34527) - vulnerable (validado)", 445),
}
SOURCE = "wsws-check"
PN_SCRIPT = "printnightmare_check_combo.py"


class CheckError(Exception):
    pass


# --- configuración (rutas de los checkers) --------------------------------------------

def config_path():
    return S.HOME / "config.json"


def load_config():
    try:
        return json.loads(config_path().read_text())
    except (OSError, ValueError):
        return {}


def save_config(cfg):
    config_path().parent.mkdir(parents=True, exist_ok=True)
    config_path().write_text(json.dumps(cfg, indent=2))


def tool_status():
    """{tool: (ruta o None, cómo obtenerlo)}"""
    cfg = load_config()
    pn_dir = cfg.get("printnightmare") or ""
    pn = Path(pn_dir).expanduser() / PN_SCRIPT if pn_dir else None
    return {
        "nmap": (shutil.which("nmap"), "brew install nmap  /  apt install nmap"),
        "rdpscan": (shutil.which(cfg.get("rdpscan") or "rdpscan"),
                    "github.com/robertdavidgraham/rdpscan  →  wsws check set rdpscan=/ruta/rdpscan"),
        "printnightmare": (str(pn) if pn and pn.is_file() else None,
                           "git clone github.com/CesarSilence/PrintNightmare + pip3 install impacket  →  "
                           "wsws check set printnightmare=/ruta/PrintNightmare"),
    }


# --- objetivos ------------------------------------------------------------------------

def targets(st, name, terms, force=False):
    """IPs del workspace con el puerto del check abierto (más los filtros del usuario). -> (en_scope, fuera)"""
    from . import query
    port = CHECKS[name]["port"]
    rows = query.find(st, list(terms) + [(False, "port", str(port))])
    addrs = list(dict.fromkeys(r["addr"] for r in rows if r["port"] == port))
    out = [a for a in addrs if st.in_scope(a) is False]
    return ([a for a in addrs if a not in out] + (out if force else [])), out


# --- comandos -------------------------------------------------------------------------

def command(name, tfile, tmp, creds=None):
    """-> (argv, cwd, archivos de salida, texto para mostrar con el secreto enmascarado)"""
    if name == "eternalblue":
        xml = Path(tmp) / "nmap.xml"
        argv = ["nmap", "-Pn", "-p445", "--script", "smb-vuln-ms17-010,smb-double-pulsar-backdoor",
                "-iL", str(tfile), "-oX", str(xml)]
        return argv, None, [xml], shlex.join(argv)
    if name == "bluekeep":
        exe = tool_status()["rdpscan"][0] or "rdpscan"
        argv = [exe, "--file", str(tfile)]
        return argv, None, [], shlex.join(argv)
    if name == "printnightmare":
        script = Path(tool_status()["printnightmare"][0] or f"<repo PrintNightmare>/{PN_SCRIPT}")
        dom, user, secret = creds
        if "'" in secret:
            raise CheckError("el combo de PrintNightmare arma el comando con comillas simples: "
                             "la contraseña no puede contener '")
        argv = ["python3", script.name, "-d", dom or ".", "-u", user, "-p", secret, "-f", str(tfile)]
        shown = shlex.join(argv[:-3] + ["****", "-f", str(tfile)])
        return argv, str(script.parent), [], shown
    raise CheckError(f"check desconocido: {name}")


# --- parsers de resultados ------------------------------------------------------------
# cada resultado: {"check", "addr", "status": "vuln" | "no" | "?", "detail"}

def parse_eternalblue(xml_text):
    out = []
    root = ET.fromstring(xml_text)
    for h in root.iter("host"):
        addr = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not addr:
            continue
        port = h.find("ports/port[@portid='445']")
        state = port.find("state").get("state") if port is not None and port.find("state") is not None else ""
        scripts = {s.get("id"): s.get("output") or "" for s in h.findall("hostscript/script")}
        for check, sid in (("eternalblue", "smb-vuln-ms17-010"), ("doublepulsar", "smb-double-pulsar-backdoor")):
            text = scripts.get(sid, "")
            if re.search(r"State:\s*VULNERABLE", text, re.I):
                status, detail = "vuln", " ".join(text.split())[:300]
            elif state != "open":
                status, detail = "?", f"445 {state or 'sin respuesta'}"
            else:
                status, detail = "no", "NSE no reporta vulnerable"
            out.append({"check": check, "addr": addr, "status": status, "detail": detail})
    return out


RDPSCAN_RE = re.compile(r"^\s*(\S+)\s+-\s+(SAFE|VULNERABLE|UNKNOWN)\s+-\s*(.*)$", re.M)


def parse_rdpscan(text):
    st = {"VULNERABLE": "vuln", "SAFE": "no", "UNKNOWN": "?"}
    return [{"check": "bluekeep", "addr": a, "status": st[s], "detail": d.strip()} for a, s, d in RDPSCAN_RE.findall(text)]


PN_TARGET_RE = re.compile(r"^Executing: .*@(\S+) -check\s*$")


def parse_printnightmare(text):
    out, cur = [], None
    for line in text.splitlines():
        m = PN_TARGET_RE.match(line.strip())
        if m:
            cur = {"check": "printnightmare", "addr": m.group(1), "status": "?", "detail": "sin respuesta del checker"}
            out.append(cur)
            continue
        if cur is None or not line.strip():
            continue
        low = line.lower()
        if "does not appear to be vulnerable" in low:
            cur.update(status="no", detail=line.strip())
        elif "appears to be vulnerable" in low:
            cur.update(status="vuln", detail=line.strip())
        elif cur["status"] == "?" and ("[-]" in line or "error" in low or "traceback" in low or "status_" in low):
            cur["detail"] = line.strip()[:200]
    return out


def parse(name, raw, files):
    if name == "eternalblue":
        xml = next((f for f in files if Path(f).is_file() and Path(f).stat().st_size), None)
        return parse_eternalblue(Path(xml).read_text()) if xml else []
    return parse_rdpscan(raw) if name == "bluekeep" else parse_printnightmare(raw)


# --- guardar --------------------------------------------------------------------------

def record(st, results, eid):
    """Hallazgos validados + etiquetas <check>:vuln / <check>:no. -> stats de ingest"""
    from . import parsers
    recs = []
    for r in results:
        if r["status"] == "vuln":
            ref, title, port = FINDINGS[r["check"]]
            recs.append(parsers.finding(r["addr"], port, source=SOURCE, ref=ref, title=title, severity="critical",
                                        location=f"{r['addr']}:{port}", detail=f"{r['detail']}\nevidencia #{eid}"))
    stats, _ = st.ingest(recs, eid)
    for r in results:
        if r["status"] == "?":
            continue
        h = st.find_host(r["addr"])
        if h:
            other = "no" if r["status"] == "vuln" else "vuln"
            st.tag(h["id"], [f"{r['check']}:{r['status']}"], [f"{r['check']}:{other}"])
    return stats
