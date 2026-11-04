"""wsws — WorkSpace With Steroids."""
import csv
import json
import os
import shlex
import shutil
import stat
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, checks, helptext, parsers, query, runner, validate
from .validate import engine as vengine
from . import store as S
from .store import SEV_NAMES, Store

HELP = """\
wsws — WorkSpace With Steroids                                       v{v}

WORKSPACES
  wsws use <nombre>            crea/activa un workspace (WSWS=<nombre> o -w <nombre> para uno puntual)
  wsws ls | rm <nombre>        listar / borrar
  wsws                         resumen del workspace activo

METER DATOS (sin entrar a nada)
  nmap -p 22 10.0.0.0/24 | wsws          pipe directo: detecta el formato solo
  wsws nmap -sV 10.0.0.0/24              wrapper: ves la salida normal + se guarda todo + evidencia
  wsws sudo nmap -sS ...                 igual, con sudo
  wsws run -- <cualquier comando>        wrapper genérico
  wsws add scan.xml res.nessus out.jsonl importar archivos
  Formatos: nmap (normal, -oX, -oG), masscan, naabu, rustscan, httpx, nuclei, nxc/netexec, Nessus, listas

BUSCAR (lo que importa)
  wsws <términos...>           atajo de `wsws find`
  wsws find|f   ...            servicios        wsws hosts|h ...   hosts
  wsws vulns|v  ...            hallazgos        wsws web|w   ...   web
  wsws creds|c  ...            credenciales     wsws show <ip|nombre>  ficha completa del host

  Términos (se combinan con AND; -término o `not término` niega):
    445  22,80,8000-8100       puertos            10.0.0.0/24  10.0.0.5    red / IP
    svc:smb  product:apache    servicio/versión   os:windows  host:dc01   domain:corp
    sev:high  vuln:ms17        hallazgos          title:login  tech:wordpress
    tag:dc  has:admin|creds|vuln|web  new:2h  scope:out  user:admin
    cualquier otra palabra = texto libre (banner, títulos, scripts NSE, notas...)

  Salida: -f <formato> (cada comando tiene los suyos: wsws vulns -h)   -n N   --all (incluye cerrados)
  Por pipe sale "ip" por defecto:   wsws 445 os:windows | nxc smb - -u u -p p

OTROS
  wsws tag <ip|-> tag... [-tag]  wsws note [ip] texto
  wsws creds add [dom\\]user:secret [--host ip] [--admin]   wsws creds mod <ID> [campo=valor...]   wsws creds rm <ID>
  wsws domain [alias <alias> <canónico> | rm <alias>]     ej: wsws domain alias CORP corp.local
  wsws scope [add|exclude|rm|check] valores...           wsws log [id]   evidencias / línea de tiempo

VALIDAR VULNERABILIDADES CONOCIDAS (solo detección, sobre el recon guardado)
  wsws check                       checks disponibles, objetivos y herramientas
  wsws check eternalblue|bluekeep|printnightmare|all [filtros] [--dry-run]

AYUDA DE CADA COMANDO
  wsws <comando> -h   (o help)     ej: wsws vulns -h · wsws creds add -h · wsws help scope
"""

COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
ECOLOR = sys.stderr.isatty() and not os.environ.get("NO_COLOR")
FORCE = bool(os.environ.get("WSWS_FORCE"))
COMMANDS = {}


def _paint(code, on):
    return lambda s: f"\x1b[{code}m{s}\x1b[0m" if on else str(s)


bold, dim, red, yellow, green, cyan, magenta = (_paint(c, COLOR) for c in ("1", "2", "31", "33", "32", "36", "1;35"))
plain = str
SEV_COLOR = {4: magenta, 3: red, 2: yellow, 1: cyan, 0: dim}
SEV_SHORT = {4: "crit", 3: "high", 2: "med", 1: "low", 0: "info"}


def msg(s):
    print(_paint("36", ECOLOR)("[wsws] ") + s, file=sys.stderr)


def warn(s):
    print(_paint("33", ECOLOR)("[wsws] ⚠ ") + s, file=sys.stderr)


def die(s, code=1):
    print(_paint("31", ECOLOR)("[wsws] ✗ ") + s, file=sys.stderr)
    sys.exit(code)


def ask_tty(prompt):
    """Pregunta por la terminal aunque stdin venga por pipe (usa /dev/tty). None si no hay terminal."""
    try:
        if sys.stdin.isatty():
            return input(prompt)
        with open("/dev/tty", "r") as tin, open("/dev/tty", "w") as tout:
            tout.write(prompt)
            tout.flush()
            line = tin.readline()
            return line if line else None
    except (OSError, EOFError):
        return None


def command(*names):
    def deco(fn):
        for n in names:
            COMMANDS[n] = fn
        return fn
    return deco


def local_ts(s, fmt="%Y-%m-%d %H:%M"):
    if not s:
        return ""
    try:
        return datetime.strptime(s, S.TS_FMT).replace(tzinfo=timezone.utc).astimezone().strftime(fmt)
    except ValueError:
        return s


def trunc(s, n):
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[:max(n - 1, 0)] + "…"


def open_ws():
    name = S.current_name()
    if not name:
        die("no hay workspace activo. Crea uno: wsws use <nombre>")
    if not S.ws_exists(name):
        die(f"el workspace '{name}' no existe. Créalo: wsws use {name}")
    return Store(name)


# --- tabla ---------------------------------------------------------------------

def _vis(cell):
    return cell if isinstance(cell, str) else " ".join(t for t, _ in cell)


def table(headers, rows, colors=None, caps=None, flex=None):
    """rows: celdas str o lista de fragmentos (texto, color). flex: columna que se recorta si no cabe."""
    if not rows:
        return
    n = len(headers)
    colors = colors or [plain] * n
    caps = caps or [60] * n
    rows = [[trunc(c, caps[i]) if isinstance(c, str) else c for i, c in enumerate(r)] for r in rows]
    widths = [max(len(headers[i]), *(len(_vis(r[i])) for r in rows)) for i in range(n)]
    term = shutil.get_terminal_size((220, 40)).columns
    over = sum(widths) + 2 * (n - 1) - term
    if over > 0 and flex is not None:
        widths[flex] = max(10, widths[flex] - over)
    print("  ".join(bold(h.ljust(widths[i])) for i, h in enumerate(headers)).rstrip())
    for r in rows:
        cells = []
        for i, c in enumerate(r):
            if isinstance(c, str):
                c = trunc(c, widths[i])
                cells.append(colors[i](c) + " " * (widths[i] - len(c)) if c else " " * widths[i])
            else:
                cells.append(" ".join(fn(t) for t, fn in c) + " " * (widths[i] - len(_vis(c))))
        print("  ".join(cells).rstrip())


# --- utilidades de salida -----------------------------------------------------

def is_web(name, port):
    return "http" in (name or "") or port in (80, 443, 8000, 8008, 8080, 8443, 8888, 9443)


def svc_url(addr, port, name):
    scheme = "https" if ("https" in (name or "") or "ssl" in (name or "") or port in (443, 8443, 9443)) else "http"
    host = f"[{addr}]" if ":" in addr else addr
    return f"{scheme}://{host}" + ("" if (scheme, port) in (("http", 80), ("https", 443)) else f":{port}")


def uniq(seq):
    return list(dict.fromkeys(x for x in seq if x))


def dump(rows, fmt):
    if fmt == "json":
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    elif fmt == "jsonl":
        for r in rows:
            print(json.dumps(r, ensure_ascii=False))
    elif fmt == "csv":
        if rows:
            w = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    else:
        return False
    return True


DATA_FMTS = ("json", "jsonl", "csv")
FORMATS = {
    "find": ("table", "ip", "hp", "url", "ports") + DATA_FMTS,
    "hosts": ("table", "ip") + DATA_FMTS,
    "vulns": ("table", "ip", "hp", "url") + DATA_FMTS,
    "web": ("table", "url", "ip") + DATA_FMTS,
    "creds": ("table", "cred", "user", "secret", "ip") + DATA_FMTS,
}


def qargs(args, pipe_default="ip", cmd="find"):
    fmt, limit, all_states, rest = None, None, False, []
    it = iter(args)
    for a in it:
        if a in ("-f", "--format"):
            fmt = next(it, "")
        elif a in ("-n", "--limit"):
            limit = int(next(it, "0") or 0)
        elif a in ("-a", "--all"):
            all_states = True
        elif a in ("-j", "--json"):
            fmt = "json"
        else:
            rest.append(a)
    if fmt == "hostport":
        fmt = "hp"
    if fmt is not None and fmt not in FORMATS[cmd]:
        die(f"formato {'inválido: ' + repr(fmt) if fmt else 'faltante'} para `wsws {cmd}`. "
            f"Disponibles: {', '.join(FORMATS[cmd])}   (más detalle: wsws {cmd} -h)")
    try:
        terms = query.parse_terms(rest)
    except query.QueryError as e:
        die(str(e))
    return fmt or ("table" if sys.stdout.isatty() else pipe_default), limit, all_states, terms


def run_query(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except query.QueryError as e:
        die(str(e))


def no_results(st):
    if sys.stdout.isatty():
        print(dim(f"sin resultados en '{st.name}'  (wsws help para ver comandos y filtros)"))
    return 1


def finding_counts(st):
    out = {}
    for r in st.q("SELECT host_id, port, sev, COUNT(*) n FROM findings WHERE sev >= 1 GROUP BY host_id, port, sev"):
        out.setdefault((r["host_id"], r["port"]), Counter())[r["sev"]] += r["n"]
    return out


def cred_counts(st):
    return {r["host_id"]: (r["n"], r["admin"]) for r in
            st.q("SELECT host_id, COUNT(*) n, MAX(admin) admin FROM creds WHERE host_id > 0 GROUP BY host_id")}


def flag_frags(sevs, creds=None, tags=""):
    frags = [(f"{SEV_SHORT[s]}:{sevs[s]}", SEV_COLOR[s]) for s in sorted(sevs, reverse=True) if sevs[s]]
    if creds:
        frags.append(("ADMIN" if creds[1] else f"creds:{creds[0]}", red if creds[1] else green))
    frags += [(f"#{t}", cyan) for t in S.split_list(tags)]
    return frags


# --- workspaces -----------------------------------------------------------------

@command("use")
def cmd_use(args):
    if not args:
        cur = S.current_name()
        print(f"activo: {bold(cur) if cur else dim('(ninguno)')}")
        return 0
    name = args[0]
    created = not S.ws_exists(name)
    Store(name)
    S.set_current(name)
    msg(f"workspace {'creado y ' if created else ''}activo: {name}")
    if created:
        msg(f"tip: define el alcance → wsws scope add 10.0.0.0/24 *.cliente.cl")
    return 0


@command("ls")
def cmd_ls(args):
    cur = S.current_name()
    rows = []
    for name in S.workspaces():
        st = Store(name)
        c = {t: st.one(f"SELECT COUNT(*) n FROM {t}")["n"] for t in ("hosts", "services", "findings", "creds")}
        last = st.one("SELECT MAX(ts_start) t FROM evidence")["t"]
        rows.append([("* " if name == cur else "  ") + name, str(c["hosts"]), str(c["services"]),
                     str(c["findings"]), str(c["creds"]), local_ts(last)])
    if not rows:
        print(dim("no hay workspaces. Crea uno: wsws use <nombre>"))
        return 0
    table(["WORKSPACE", "HOSTS", "SERVICIOS", "VULNS", "CREDS", "ÚLTIMA ACTIVIDAD"], rows, [bold] + [plain] * 5)
    return 0


@command("rm")
def cmd_rm(args):
    if not args or not S.ws_exists(args[0]):
        die("uso: wsws rm <workspace existente>")
    name = args[0]
    if input(f"Esto borra '{name}' con toda su evidencia. Escribe el nombre para confirmar: ").strip() != name:
        die("cancelado")
    shutil.rmtree(S.HOME / "ws" / name)
    if S.current_name() == name and not os.environ.get("WSWS"):
        S.set_current("")
    msg(f"borrado: {name}")
    return 0


# --- ingesta --------------------------------------------------------------------

def summary(stats):
    parts = []
    for kind, label in (("hosts", "hosts"), ("services", "servicios"), ("web", "web"),
                        ("findings", "vulns"), ("creds", "creds")):
        if kind in stats:
            n, new = stats[kind]
            parts.append(f"{label} {n}" + (f" (+{new} nuevos)" if new else ""))
    return " · ".join(parts) or "sin datos reconocidos"


def report(st, eid, fmt, stats, hids):
    msg(f"{st.name} ← {fmt} · {summary(stats)} · evidencia #{eid}")
    if hids:
        addrs = [r["addr"] for r in st.q(f"SELECT addr FROM hosts WHERE id IN ({','.join('?' * len(hids))})", hids)]
        out = [a for a in addrs if st.in_scope(a) is False]
        if out:
            warn(f"{len(out)} host(s) FUERA de scope: {', '.join(out[:6])}{' …' if len(out) > 6 else ''}")


def ingest_text(st, text, cmd, tool=None, attach=()):
    if not text.strip():
        warn("entrada vacía, nada que guardar")
        return {}
    eid = st.ev_start(cmd, tool or "import")
    fmt, recs = parsers.parse(text)
    stats, hids = st.ingest(recs, eid)
    st.ev_finish(eid, raw=None if attach else parsers.strip_ansi(text), tool=tool or fmt, fmt=fmt,
                 attach=attach, summary=summary(stats), cmd=f"{cmd} ({fmt})" if cmd == "stdin" else None)
    report(st, eid, fmt, stats, hids)
    return stats


@command("add", "import")
def cmd_add(args):
    quiet = "-q" in args
    files = [a for a in args if a != "-q"]
    st = open_ws()
    if files:
        for f in files:
            p = Path(f)
            if not p.is_file():
                warn(f"no existe: {f}")
                continue
            ingest_text(st, p.read_text(errors="replace"), f"import {p.resolve()}", attach=[p])
        return 0
    if sys.stdin.isatty():
        die("nada que leer. Uso: <herramienta> | wsws   o   wsws add <archivo>")
    tee = not quiet and sys.stdout.isatty()
    chunks = []
    for line in sys.stdin.buffer:
        chunks.append(line)
        if tee:
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
    ingest_text(st, b"".join(chunks).decode("utf-8", "replace"), "stdin")
    return 0


def reverse_dns_server(st, opts):
    """Decide qué DNS usar para `reverse` y lo recuerda por workspace. -> IP (str) o '' (resolver del sistema).

    --dns IP|system lo fija explícitamente. Si nunca se configuró en este workspace, la PRIMERA vez
    pregunta si el DNS apunta al DC; si no, pide la IP del DC y la guarda en el workspace.
    """
    if opts.get("dns") is not None:
        val = opts["dns"].strip()
        server = "" if val.lower() in ("system", "sistema", "local") else val
        if server and not parsers.is_ip(server):
            die(f"--dns espera una IP o 'system': {val!r}")
        st.set_setting("reverse_dns_server", server)
        st.set_setting("reverse_dns_asked", "1")
        msg(f"DNS para reverse guardado en '{st.name}': {server or 'resolver del sistema'}")
        return server

    if st.setting("reverse_dns_asked"):
        return st.setting("reverse_dns_server", "")

    # primera vez en este workspace
    ans = ask_tty("[wsws] ¿El DNS de este equipo apunta al DC del dominio? [s/N] ")
    if ans is None:
        warn("primera vez sin terminal interactiva: uso el resolver del sistema. "
             "Configúralo con: wsws reverse --dns <ip-del-DC>")
        return ""
    if ans.strip().lower() in ("s", "si", "sí", "y", "yes"):
        st.set_setting("reverse_dns_server", "")
        st.set_setting("reverse_dns_asked", "1")
        msg("ok, uso el resolver del sistema para este workspace")
        return ""
    ipv = (ask_tty("[wsws] IP del DNS/DC a usar para las resoluciones: ") or "").strip()
    if parsers.is_ip(ipv):
        st.set_setting("reverse_dns_server", ipv)
        st.set_setting("reverse_dns_asked", "1")
        msg(f"guardado: '{st.name}' resolverá PTR usando {ipv} (cámbialo con: wsws reverse --dns <ip|system>)")
        return ipv
    warn("no ingresaste una IP válida; uso el resolver del sistema por ahora (no se guardó)")
    return ""


def reverse_list(args):
    """Lista los hosts resueltos por `wsws reverse` (los que entraron con evidencia tool='reverse')."""
    st = open_ws()
    fmt, terms, it = "table", [], iter(args)
    for a in it:
        if a in ("-f", "--format"):
            fmt = next(it, "table")
        else:
            terms.append(a)
    rows = st.q("SELECT DISTINCT h.addr, h.hostnames FROM hosts h "
                "JOIN seen s ON s.kind='host' AND s.ref_id = h.id "
                "JOIN evidence e ON e.id = s.evidence_id "
                "WHERE e.tool='reverse' AND h.hostnames != '' ORDER BY ipkey(h.addr)")
    if terms:
        f = terms[0]
        net = S.as_net(f)
        if net is not None:
            import ipaddress
            def keep(r):
                try:
                    return ipaddress.ip_address(r["addr"]) in net
                except ValueError:
                    return False
        else:
            def keep(r):
                return f.lower() in (r["addr"] + " " + r["hostnames"]).lower()
        rows = [r for r in rows if keep(r)]
    if fmt == "ip":
        for r in rows:
            print(r["addr"])
        return 0
    if not rows:
        print(dim("sin resultados de reverse en este workspace. Corre: wsws reverse <CIDR>"))
        return 0
    table(["IP", "HOSTNAME(S) (PTR)"], [[r["addr"], r["hostnames"].replace(",", ", ")] for r in rows],
          [cyan, plain], flex=1)
    print(dim(f"{len(rows)} host(s) con PTR  ·  filtra: wsws reverse list 10.20.0.0/16  ·  IPs: wsws reverse list -f ip"))
    return 0


@command("reverse", "rdns", "ptr")
def cmd_reverse(args):
    """Reverse DNS (PTR) sobre uno o más CIDR/IP, nativo (sin ipcalc/host), e ingiere los hostnames."""
    if args and args[0] in ("list", "ls"):
        return reverse_list(args[1:])
    from concurrent.futures import ThreadPoolExecutor

    from .validate.net import dnsc

    opts = {"threads": 64, "timeout": 2.0, "save": True, "dns": None}
    raw_targets, it = [], iter(args)
    for a in it:
        if a in ("--threads", "-t"):
            v = next(it, None)
            if not (v and v.isdigit()):
                die("--threads requiere un entero")
            opts["threads"] = max(1, min(512, int(v)))
        elif a == "--timeout":
            v = next(it, None)
            if not (v and v.replace(".", "", 1).isdigit()):
                die("--timeout requiere segundos")
            opts["timeout"] = float(v)
        elif a == "--dns":
            v = next(it, None)
            if v is None:
                die("--dns requiere una IP o 'system'")
            opts["dns"] = v
        elif a in ("--no-save", "-n"):
            opts["save"] = False
        elif a == "--force":
            opts["force"] = True
        elif a == "-":
            if sys.stdin.isatty():
                die("'-' lee objetivos desde stdin, pero no hay pipe")
            raw_targets += [ln.strip() for ln in sys.stdin if ln.strip() and not ln.startswith("#")]
        else:
            raw_targets.append(a)
    if not raw_targets and not sys.stdin.isatty():
        raw_targets = [ln.strip() for ln in sys.stdin if ln.strip() and not ln.startswith("#")]
    if not raw_targets:
        die("uso: wsws reverse <CIDR|IP> [...]  ·  ej: wsws reverse 10.10.10.0/24  ·  wsws 445 | wsws reverse -")

    ips = []
    for t in raw_targets:
        net = S.as_net(t)
        if net is not None:
            ips += [str(h) for h in net.hosts()] or [str(net.network_address)]
        elif parsers.is_ip(t):
            ips.append(t)
        else:
            warn(f"ignorado (no es IP ni CIDR): {t}")
    ips = list(dict.fromkeys(ips))
    if not ips:
        die("no hay IPs válidas para resolver")
    force = FORCE or opts.get("force")
    if len(ips) > 65536 and not force:
        die(f"{len(ips)} IPs es demasiado; acota el rango o usa --force")

    st = open_ws()
    if not force:
        out = [a for a in ips if st.in_scope(a) is False]
        if out:
            msg(f"{len(out)} IP(s) fuera de scope omitidas (usa --force para incluirlas)")
            ips = [a for a in ips if a not in out]
    if not ips:
        die("no quedan IPs dentro del scope (usa --force)")

    dns_server = reverse_dns_server(st, opts)

    def lookup(ip):
        return ip, dnsc.reverse_lookup(ip, dns_server or None, opts["timeout"])

    via = f" vía {dns_server}" if dns_server else " (resolver del sistema)"
    msg(f"resolviendo PTR de {len(ips)} IP(s) con {opts['threads']} hilos{via}…")
    results = []
    with ThreadPoolExecutor(max_workers=opts["threads"]) as ex:
        for ip, name in ex.map(lookup, ips):
            if name:
                results.append((ip, name))
    results.sort(key=lambda r: S.ipkey(r[0]))

    if results:
        table(["IP", "HOSTNAME (PTR)"], [[ip, name] for ip, name in results], [cyan, plain], flex=1)
    print(dim(f"{len(results)}/{len(ips)} con PTR"))

    if opts["save"] and results:
        eid = st.ev_start("wsws reverse " + " ".join(raw_targets), "reverse")
        recs = [parsers.host(ip, hostnames=[name]) for ip, name in results]
        stats, hids = st.ingest(recs, eid)
        st.ev_finish(eid, raw="\n".join(f"{ip}\t{name}" for ip, name in results),
                     tool="reverse", fmt="reverse", exit_code=0, summary=summary(stats))
        report(st, eid, "reverse", stats, hids)
    elif opts["save"]:
        print(dim("nada que guardar (ningún PTR)"))
    return 0


@command("run")
def cmd_run(argv):
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        die("uso: wsws run -- <comando> [args]")
    prefix = []
    if argv[0] == "sudo" and len(argv) > 1:
        prefix, argv = ["sudo"], argv[1:]
    tool = Path(argv[0]).name
    if not shutil.which(argv[0]):
        die(f"no encuentro '{argv[0]}' en el PATH", 127)
    st = open_ws()
    bad = [t for t in runner.targets(tool, argv[1:]) if st.in_scope(t) is False]
    if bad and not FORCE:
        die(f"objetivo(s) FUERA de scope: {', '.join(bad)}\n"
            f"        revisa `wsws scope` o, si es intencional: wsws --force {shlex.join(prefix + argv)}", 3)
    if bad:
        warn(f"--force: ejecutando contra objetivos fuera de scope: {', '.join(bad)}")
    if not st.rules()[0]:
        msg(dim("sin scope definido (wsws scope add ...) — no se valida alcance"))
    with tempfile.TemporaryDirectory(prefix="wsws-") as tmp:
        args, files = runner.prepare(tool, argv[1:], Path(tmp))
        eid = st.ev_start(shlex.join(prefix + argv), tool)
        msg(dim(f"{st.name} · evidencia #{eid} · {shlex.join(prefix + argv)}"))
        try:
            rc, raw = runner.capture(prefix + [argv[0]] + args)
        except OSError as e:
            st.ev_finish(eid, raw=str(e), exit_code=127, summary="no se pudo ejecutar")
            die(f"no se pudo ejecutar: {e}", 127)
        text = parsers.strip_ansi(raw.decode("utf-8", "replace"))
        fmt, recs = None, []
        for f in files:
            p = Path(f)
            if p.is_file() and p.stat().st_size:
                fmt, r = parsers.parse(p.read_text(errors="replace"))
                recs += r
        if not recs:
            fmt, recs = parsers.parse(text)
        stats, hids = st.ingest(recs, eid)
        note = f" · FUERA DE SCOPE (--force): {', '.join(bad)}" if bad else ""
        st.ev_finish(eid, raw=text, fmt=fmt, exit_code=rc, attach=[f for f in files if Path(f).is_file()],
                     summary=summary(stats) + note)
    report(st, eid, fmt, stats, hids)
    return rc


# --- búsqueda -------------------------------------------------------------------

@command("find", "f", "services", "svc")
def cmd_find(args):
    fmt, limit, all_states, terms = qargs(args, cmd="find")
    st = open_ws()
    rows = run_query(query.find, st, terms, all_states)[:limit or None]
    if dump(rows, fmt):
        return 0
    if not rows:
        return no_results(st)
    if fmt == "ip":
        print("\n".join(uniq(r["addr"] for r in rows)))
    elif fmt in ("hp", "hostport"):
        print("\n".join(uniq(f"{r['addr']}:{r['port']}" for r in rows if r["port"])))
    elif fmt == "ports":
        print(",".join(str(p) for p in sorted({r["port"] for r in rows if r["port"]})))
    elif fmt == "url":
        urls = []
        for r in rows:
            if r["port"]:
                known = [w["url"] for w in st.q("SELECT url FROM web WHERE host_id=? AND port=?", (r["hid"], r["port"]))]
                urls += known or ([svc_url(r["addr"], r["port"], r["name"])] if is_web(r["name"], r["port"]) else [])
        print("\n".join(uniq(urls)))
    else:
        fc, cc, rows_out, last = finding_counts(st), cred_counts(st), [], None
        for r in rows:
            first, last = r["hid"] != last, r["hid"]
            sevs = Counter(fc.get((r["hid"], r["port"] or 0), {}))
            if first and r["port"]:
                sevs.update(fc.get((r["hid"], 0), {}))
            port = "" if r["port"] is None else (str(r["port"]) + ("" if r["proto"] == "tcp" else "/" + r["proto"]))
            ver = " ".join(x for x in (r["product"], r["version"], f"({r['extra']})" if r["extra"] else "") if x)
            names = S.split_list(r["hostnames"])
            rows_out.append([r["addr"], port, r["name"] or "", ver, names[0] if names else "", r["os"],
                             flag_frags(sevs, cc.get(r["hid"]) if first else None, r["tags"] if first else "")])
        table(["ADDR", "PORT", "SERVICIO", "VERSIÓN", "HOSTNAME", "OS", "FLAGS"], rows_out,
              [cyan, bold, plain, plain, plain, dim, plain], [40, 9, 20, 60, 36, 28, 60], flex=3)
        if sys.stdout.isatty():
            print(dim(f"{len(rows)} servicio(s) en {len(uniq(r['addr'] for r in rows))} host(s)"))
    return 0


@command("hosts", "h")
def cmd_hosts(args):
    fmt, limit, all_states, terms = qargs(args, cmd="hosts")
    st = open_ws()
    rows = run_query(query.find, st, terms, all_states)
    hosts = {}
    for r in rows:
        h = hosts.setdefault(r["hid"], {k: r[k] for k in ("hid", "addr", "hostnames", "os", "domain", "tags")} | {"ports": []})
        if r["port"]:
            h["ports"].append(r["port"])
    hosts = list(hosts.values())[:limit or None]
    if dump(hosts, fmt):
        return 0
    if not hosts:
        return no_results(st)
    if fmt == "ip":
        print("\n".join(h["addr"] for h in hosts))
        return 0
    fc, cc = finding_counts(st), cred_counts(st)
    out = []
    for h in hosts:
        sevs = Counter()
        for (hid, _), c in fc.items():
            if hid == h["hid"]:
                sevs.update(c)
        out.append([h["addr"], ",".join(S.split_list(h["hostnames"])), h["os"], ",".join(map(str, h["ports"])),
                    flag_frags(sevs, cc.get(h["hid"]), h["tags"])])
    table(["ADDR", "HOSTNAMES", "OS", "PUERTOS", "FLAGS"], out, [cyan, plain, dim, bold, plain],
          [40, 50, 36, 80, 60], flex=3)
    if sys.stdout.isatty():
        print(dim(f"{len(hosts)} host(s)"))
    return 0


@command("vulns", "v", "findings")
def cmd_vulns(args):
    fmt, limit, _, terms = qargs(args, pipe_default="table", cmd="vulns")
    st = open_ws()
    rows = run_query(query.findings, st, terms)[:limit or None]
    for r in rows:
        r["severity"] = SEV_NAMES.get(r["sev"], "info")
    if dump(rows, fmt):
        return 0
    if not rows:
        return no_results(st)
    if fmt == "ip":
        print("\n".join(uniq(r["addr"] for r in rows)))
    elif fmt in ("hp", "url"):
        print("\n".join(uniq(r["location"] or f"{r['addr']}:{r['port']}" for r in rows)))
    else:
        table(["SEV", "ADDR", "PORT", "HALLAZGO", "REF", "FUENTE"],
              [[[(SEV_SHORT[r["sev"]].upper(), SEV_COLOR[r["sev"]])], r["addr"], str(r["port"] or ""),
                r["title"], r["ref"], r["source"]] for r in rows],
              [plain, cyan, bold, plain, dim, dim], [6, 40, 6, 80, 40, 10], flex=3)
        if sys.stdout.isatty():
            print(dim(f"{len(rows)} hallazgo(s)  ·  detalle: wsws show <ip>  ·  -f json para todo"))
    return 0


@command("web", "w")
def cmd_web(args):
    fmt, limit, _, terms = qargs(args, pipe_default="url", cmd="web")
    st = open_ws()
    rows = run_query(query.web, st, terms)[:limit or None]
    if dump(rows, fmt):
        return 0
    if not rows:
        return no_results(st)
    if fmt == "url":
        print("\n".join(uniq(r["url"] for r in rows)))
    elif fmt == "ip":
        print("\n".join(uniq(r["addr"] for r in rows)))
    else:
        def scol(s):
            return green if s and s < 300 else yellow if s and s < 400 else red if s else dim
        table(["STATUS", "URL", "TÍTULO", "TECNOLOGÍAS", "SERVIDOR"],
              [[[(str(r["status"] or "-"), scol(r["status"]))], r["url"], r["title"], r["tech"], r["server"]]
               for r in rows], [plain, cyan, bold, plain, dim], [6, 70, 50, 50, 24], flex=2)
    return 0


def cred_str(r):
    return f"{r['domain']}\\{r['username']}:{r['secret']}" if r["domain"] else f"{r['username']}:{r['secret']}"


@command("creds", "c")
def cmd_creds(args):
    sub = {"add": cred_add, "mod": cred_mod, "edit": cred_mod, "rm": cred_rm, "del": cred_rm}
    if args and args[0] in sub:
        return sub[args[0]](args[1:])
    fmt, limit, _, terms = qargs(args, pipe_default="cred", cmd="creds")
    st = open_ws()
    rows = run_query(query.creds, st, terms)[:limit or None]
    if dump(rows, fmt):
        return 0
    if not rows:
        return no_results(st)
    if fmt in ("cred", "user", "secret", "ip"):
        get = {"cred": cred_str, "user": lambda r: r["username"], "secret": lambda r: r["secret"],
               "ip": lambda r: r["addr"]}[fmt]
        print("\n".join(uniq(get(r) for r in rows)))
    else:
        table(["ID", "HOST", "USUARIO", "SECRETO", "TIPO", "ESTADO", "FUENTE"],
              [[str(r["id"]), r["addr"] or "-", f"{r['domain']}\\{r['username']}" if r["domain"] else r["username"],
                r["secret"], r["kind"], cred_state(r), r["source"]] for r in rows],
              [dim, cyan, bold, plain, dim, plain, dim], [6, 40, 40, 70, 9, 7, 20], flex=3)
        if sys.stdout.isatty():
            print(dim(f"{len(rows)} credencial(es)  ·  editar: wsws creds mod <ID>  ·  borrar: wsws creds rm <ID>"))
    return 0


def cred_state(r):
    return [("ADMIN", red)] if r["admin"] else [("válida", green)] if r["valid"] else [("?", dim)]


def get_cred(st, ref):
    if not ref.lstrip("#").isdigit():
        die(f"ID inválido: {ref!r} (míralo en la columna ID de `wsws creds`)")
    r = st.one("SELECT c.*, h.addr FROM creds c LEFT JOIN hosts h ON h.id = c.host_id WHERE c.id=?",
               (int(ref.lstrip("#")),))
    if r is None:
        die(f"no existe la credencial #{ref.lstrip('#')}")
    return r


def print_cred(r):
    print(f"{dim('#' + str(r['id']))} {bold(cred_str(r))}  {dim('host')} {r['addr'] or '-'}  {dim('tipo')} {r['kind']}"
          f"  {' '.join(fn(t) for t, fn in cred_state(r))}  {dim(r['source'])}")


YES = {"1", "s", "si", "sí", "y", "yes", "true"}
NO = {"0", "n", "no", "false"}
MOD_KEYS = {"domain": "domain", "dom": "domain", "dominio": "domain", "user": "username", "username": "username",
            "usuario": "username", "secret": "secret", "pass": "secret", "password": "secret", "hash": "secret",
            "secreto": "secret", "kind": "kind", "tipo": "kind", "host": "host", "valid": "valid", "valida": "valid",
            "válida": "valid", "admin": "admin", "source": "source", "fuente": "source"}


def _bool(v, key):
    v = v.strip().lower()
    if v in YES:
        return 1
    if v in NO:
        return 0
    die(f"{key}: usa s/n (o 1/0)")


def _mod_interactive(r):
    if not sys.stdin.isatty():
        die("modo interactivo necesita terminal. Sin terminal: wsws creds mod <ID> secret=... --admin ...")
    print_cred(r)
    print(dim("Enter = mantener · '-' = dejar vacío · Ctrl-C = cancelar"))
    fields = {}
    prompts = [("domain", "Dominio", r["domain"]), ("username", "Usuario", r["username"]),
               ("secret", "Secreto", r["secret"]), ("kind", "Tipo (password/hash/ntlm/...)", r["kind"]),
               ("host", "Host", r["addr"] or ""), ("valid", "¿Válida? (s/n)", "s" if r["valid"] else "n"),
               ("admin", "¿Admin? (s/n)", "s" if r["admin"] else "n")]
    try:
        for key, label, cur in prompts:
            v = input(f"  {label} [{cur}]: ")
            if v == "":
                continue
            v = "" if v.strip() == "-" else v
            if key in ("valid", "admin"):
                v = _bool(v, label)
                if v == r[key]:
                    continue
            elif v == cur:
                continue
            fields[key] = v
    except (KeyboardInterrupt, EOFError):
        print()
        die("cancelado, no se modificó nada")
    return fields


def cred_mod(args):
    if not args:
        die("uso: wsws creds mod <ID>                          (interactivo)\n"
            "        wsws creds mod <ID> secret=Nueva --admin    (directo)\n"
            "        campos: domain= user= secret= kind= host= valid=s/n admin=s/n source=  ·  "
            "o una cred completa: 'corp\\user:pass'")
    st = open_ws()
    r = get_cred(st, args[0])
    if len(args) == 1:
        fields = _mod_interactive(r)
    else:
        fields = {}
        for a in args[1:]:
            flag = {"--admin": ("admin", 1), "--no-admin": ("admin", 0), "--valid": ("valid", 1),
                    "--invalid": ("valid", 0), "--hash": ("kind", "hash")}.get(a)
            if flag:
                fields[flag[0]] = flag[1]
            elif "=" in a and a.split("=", 1)[0].lower() in MOD_KEYS:
                k, v = a.split("=", 1)
                k = MOD_KEYS[k.lower()]
                fields[k] = _bool(v, k) if k in ("valid", "admin") else v
            elif any(c in a for c in ":\\/@"):
                dom, user, secret, target = parsers.parse_cred(a)
                fields.update(domain=dom, username=user, secret=secret)
                if target:
                    fields["host"] = target
            else:
                die(f"no entiendo {a!r}. Usa campo=valor (domain, user, secret, kind, host, valid, admin, source)")
    if not fields:
        msg("sin cambios")
        return 0
    if "username" in fields and not fields["username"]:
        die("el usuario no puede quedar vacío")
    if "host" in fields:
        h = fields.pop("host")
        fields["host_id"] = st.host(h)[0] if h else 0
        if not h:
            fields["port"] = 0
    if "secret" in fields and "kind" not in fields and fields["secret"]:
        fields["kind"] = "hash" if parsers.HASH_RE.fullmatch(fields["secret"]) else "password"
    new, merged = st.cred_update(r["id"], fields)
    print_cred(st.one("SELECT c.*, h.addr FROM creds c LEFT JOIN hosts h ON h.id = c.host_id WHERE c.id=?",
                      (new["id"],)))
    msg(f"credencial #{r['id']} modificada"
        + (f" · quedó igual a {', '.join('#' + str(m) for m in merged)}, se unieron en #{r['id']}" if merged else ""))
    return 0


def cred_rm(args):
    if not args:
        die("uso: wsws creds rm <ID> [<ID>...]")
    st = open_ws()
    for ref in args:
        r = get_cred(st, ref)
        st.cred_rm(r["id"])
        msg(f"borrada #{r['id']}: {cred_str(r)}")
    return 0


def cred_add(args):
    if not args:
        die("uso: wsws creds add [dominio\\]usuario:secreto [--host ip] [--admin] [--hash] [--invalid]")
    st = open_ws()
    dom, user, secret, target = parsers.parse_cred(args[0])
    if not user:
        die(f"no entiendo la credencial {args[0]!r}. Formatos: dom\\user:pass  dom/user:pass[@host]  user@dom:pass")
    if "--host" in args:
        i = args.index("--host")
        if i + 1 >= len(args):
            die("--host requiere un valor")
        target = args[i + 1]
    hid = st.host(target)[0] if target else 0
    kind = "hash" if "--hash" in args or parsers.HASH_RE.fullmatch(secret) else "password"
    cid, created = st.cred(hid, 0, dom, user, secret, kind, valid=int("--invalid" not in args),
                           admin=int("--admin" in args), source="manual")
    st.db.commit()
    r = st.one("SELECT * FROM creds WHERE id=?", (cid,))
    msg(("credencial agregada: " if created else "ya existía, actualizada: ") + cred_str(r)
        + (f"  @{target}" if target else ""))
    return 0


# --- ficha de host ----------------------------------------------------------------

def resolve_host(st, target):
    row = st.find_host(target)
    if row:
        return row
    cands = st.q("SELECT * FROM hosts WHERE addr LIKE ? OR hostnames LIKE ? ORDER BY ipkey(addr)",
                 (f"%{target}%", f"%{target}%"))
    if len(cands) == 1:
        return cands[0]
    if not cands:
        die(f"no encuentro el host '{target}'")
    print(f"'{target}' coincide con {len(cands)} hosts:")
    for c in cands[:30]:
        print(f"  {cyan(c['addr'])}  {dim(c['hostnames'])}")
    sys.exit(1)


def section(title, n):
    print(f"\n{bold(title)} {dim(f'({n})')}")


@command("show", "info")
def cmd_show(args):
    if not args:
        die("uso: wsws show <ip|hostname>")
    st = open_ws()
    h = resolve_host(st, args[0])
    hid = h["id"]
    scope = {True: green("en scope"), False: red("FUERA DE SCOPE"), None: dim("sin scope")}[st.in_scope(h["addr"])]
    tags = " ".join(cyan("#" + t) for t in S.split_list(h["tags"]))
    print(f"{bold(cyan(h['addr']))}  {', '.join(S.split_list(h['hostnames']))}   [{scope}] {tags}")
    meta = [("OS", h["os"]), ("Dominio", h["domain"]), ("MAC", h["mac"]),
            ("Visto", f"{local_ts(h['first_seen'])} → {local_ts(h['last_seen'])}")]
    print("  " + dim(" · ").join(f"{dim(k + ':')} {v}" for k, v in meta if v))

    svcs = st.q("SELECT * FROM services WHERE host_id=? ORDER BY port", (hid,))
    if svcs:
        section("SERVICIOS", len(svcs))
        table(["PORT", "ESTADO", "SERVICIO", "VERSIÓN", "NSE / BANNER"],
              [[f"{s['port']}/{s['proto']}", s["state"], s["name"],
                " ".join(x for x in (s["product"], s["version"], f"({s['extra']})" if s["extra"] else "") if x),
                s["banner"].split("\n")[0]] for s in svcs], [bold, dim, plain, plain, dim], [10, 14, 20, 60, 80], flex=4)
    webs = st.q("SELECT * FROM web WHERE host_id=? ORDER BY port, url", (hid,))
    if webs:
        section("WEB", len(webs))
        table(["STATUS", "URL", "TÍTULO", "TECNOLOGÍAS"],
              [[str(w["status"] or "-"), w["url"], w["title"], w["tech"]] for w in webs], [bold, cyan, plain, dim],
              flex=2)
    fnd = st.q("SELECT * FROM findings WHERE host_id=? ORDER BY sev DESC, port", (hid,))
    if fnd:
        section("HALLAZGOS", len(fnd))
        table(["SEV", "PORT", "HALLAZGO", "REF", "UBICACIÓN"],
              [[[(SEV_SHORT[f["sev"]].upper(), SEV_COLOR[f["sev"]])], str(f["port"] or ""), f["title"], f["ref"],
                f["location"]] for f in fnd], [plain, bold, plain, dim, dim], [6, 6, 70, 36, 60], flex=2)
    crs = st.q("SELECT * FROM creds WHERE host_id=? ORDER BY admin DESC, valid DESC", (hid,))
    if crs:
        section("CREDENCIALES", len(crs))
        table(["ID", "USUARIO", "SECRETO", "TIPO", "ESTADO", "FUENTE"],
              [[str(c["id"]), f"{c['domain']}\\{c['username']}" if c["domain"] else c["username"], c["secret"],
                c["kind"], cred_state(c), c["source"]] for c in crs],
              [dim, bold, plain, dim, plain, dim], flex=2)
    vlds = st.q("SELECT * FROM validations WHERE host_id=? ORDER BY check_id", (hid,))
    if vlds:
        section("VALIDACIONES", len(vlds))
        table(["VALIDADOR", "CVE", "RESULTADO", "MÉTODO", "RAZÓN"],
              [[v["check_id"], v["cve"], [VSTATUS.get(v["status"], (v["status"], plain))], v["method"], v["reason"]]
               for v in vlds], [bold, dim, plain, dim, dim], [16, 16, 14, 8, 70], flex=4)
        for v in vlds:
            if v["limitations"]:
                print(dim(f"  {v['check_id']} — limitaciones: ") + dim(v["limitations"].replace("\n", " · ")))
    notes = st.q("SELECT * FROM notes WHERE host_id=? ORDER BY ts", (hid,))
    if notes:
        section("NOTAS", len(notes))
        for n in notes:
            print(f"  {dim(local_ts(n['ts']))} {dim(n['author'])}  {n['text']}")
    evs = st.q("SELECT DISTINCT e.* FROM evidence e JOIN seen s ON s.evidence_id = e.id WHERE "
               "(s.kind='host' AND s.ref_id=?) ORDER BY e.id", (hid,))
    if evs:
        section("LÍNEA DE TIEMPO", len(evs))
        for e in evs:
            print(f"  {dim('#' + str(e['id']))} {local_ts(e['ts_start'])} {dim(e['operator'])}  {trunc(e['cmd'], 100)}")
    return 0


# --- anotaciones ------------------------------------------------------------------

def hosts_from_arg(st, target):
    if target == "-":
        if sys.stdin.isatty():
            die("'-' lee hosts desde stdin, pero no hay pipe")
        addrs = [ln.strip().split()[0] for ln in sys.stdin if ln.strip()]
        rows = [st.find_host(parsers.split_target(a)[0] or a) for a in addrs]
        return [r for r in rows if r]
    return [resolve_host(st, target)]


@command("tag")
def cmd_tag(args):
    if len(args) < 2:
        die("uso: wsws tag <ip|hostname|-> tag1 [tag2] [-tag_a_quitar]")
    st = open_ws()
    add = [t for t in args[1:] if not t.startswith("-")]
    rm = [t[1:] for t in args[1:] if t.startswith("-")]
    hosts = hosts_from_arg(st, args[0])
    for h in hosts:
        st.tag(h["id"], add, rm)
    msg(f"{len(hosts)} host(s) etiquetado(s): {' '.join('#' + t for t in add)}"
        + (f"  quitado: {' '.join('#' + t for t in rm)}" if rm else ""))
    return 0


@command("note", "n")
def cmd_note(args):
    st = open_ws()
    if not args:
        rows = st.q("SELECT n.*, h.addr FROM notes n LEFT JOIN hosts h ON h.id = n.host_id ORDER BY n.ts")
        for n in rows:
            print(f"{dim(local_ts(n['ts']))} {cyan(n['addr'] or 'general'):<20} {n['text']}  {dim(n['author'])}")
        return 0
    h = st.find_host(args[0])
    if h and len(args) == 1:
        return cmd_show([args[0]])
    text = " ".join(args[1:] if h else args)
    st.note(h["id"] if h else 0, text)
    msg(f"nota guardada{' en ' + h['addr'] if h else ' (general)'}")
    return 0


# --- scope ------------------------------------------------------------------------

@command("scope")
def cmd_scope(args):
    st = open_ws()
    sub, vals = (args[0], args[1:]) if args else ("ls", [])
    if not vals and sub in ("add", "exclude", "rm", "check") and not sys.stdin.isatty():
        vals = [ln.strip() for ln in sys.stdin if ln.strip() and not ln.startswith("#")]
    if sub == "add":
        st.scope_set("include", vals)
    elif sub in ("exclude", "ex"):
        st.scope_set("exclude", vals)
    elif sub == "rm":
        st.scope_rm(vals)
    elif sub == "check":
        for v in vals:
            r = st.in_scope(parsers.split_target(v)[0] or v)
            print(f"{v}: " + {True: green("en scope"), False: red("FUERA"), None: dim("sin scope definido")}[r])
        return 0
    elif sub != "ls":
        die("uso: wsws scope [ls|add|exclude|rm|check] valores...  (IP, CIDR, dominio, *.dominio)")
    inc, exc = st.rules()
    if not inc and not exc:
        print(dim("sin scope definido. Ej: wsws scope add 10.0.0.0/24 *.cliente.cl  ·  wsws scope exclude 10.0.0.1"))
        return 0
    print(bold("incluido: ") + (", ".join(inc) or dim("(todo salvo exclusiones)")))
    if exc:
        print(bold("excluido: ") + ", ".join(exc))
    out = [r["addr"] for r in st.q("SELECT addr FROM hosts WHERE in_scope(addr) = 0")]
    if out:
        warn(f"{len(out)} host(s) del workspace fuera de scope: {', '.join(out[:8])}{' …' if len(out) > 8 else ''}")
    return 0


# --- dominios -----------------------------------------------------------------------

def alias_suggestions(st, domains):
    """'corp' y 'corp.local' presentes a la vez -> probablemente NetBIOS y FQDN del mismo dominio."""
    known = {a["alias"].lower() for a in st.aliases()}
    fqdns = [d for d in domains if "." in d]
    out = []
    for d in domains:
        if "." in d or d.lower() in known:
            continue
        for f in fqdns:
            if f.split(".")[0].lower() == d.lower():
                out.append((d, f))
    return out


@command("domain", "domains", "dom")
def cmd_domain(args):
    st = open_ws()
    sub = args[0] if args else "ls"
    if sub == "alias":
        if len(args) != 3:
            die("uso: wsws domain alias <alias> <dominio_canónico>    ej: wsws domain alias CORP corp.local")
        try:
            merged = st.alias_add(args[1], args[2])
        except ValueError as e:
            die(str(e))
        msg(f"alias: {args[1]} → {st.canon_domain(args[2])}"
            + (f" · {merged} credencial(es) duplicada(s) unida(s)" if merged else ""))
        return 0
    if sub == "rm":
        if len(args) < 2:
            die("uso: wsws domain rm <alias>")
        for a in args[1:]:
            msg(f"alias {a} quitado" if st.alias_rm(a) else f"no existe el alias {a}")
        return 0
    if sub != "ls":
        die("uso: wsws domain [ls] | alias <alias> <canónico> | rm <alias>")
    rows = st.q("SELECT d, SUM(c) creds, SUM(h) hosts FROM ("
                " SELECT domain d, 1 c, 0 h FROM creds WHERE domain != ''"
                " UNION ALL SELECT domain d, 0 c, 1 h FROM hosts WHERE domain != '')"
                " GROUP BY d COLLATE NOCASE ORDER BY d COLLATE NOCASE")
    aliases = {}
    for a in st.aliases():
        aliases.setdefault(a["canonical"].lower(), []).append(a["alias"])
    if not rows and not aliases:
        print(dim("todavía no hay dominios en este workspace"))
        return 0
    table(["DOMINIO", "CREDS", "HOSTS", "ALIAS"],
          [[r["d"], str(r["creds"]), str(r["hosts"]), ", ".join(aliases.get(r["d"].lower(), []))] for r in rows],
          [bold, plain, plain, cyan])
    for alias, fqdn in alias_suggestions(st, [r["d"] for r in rows]):
        print(yellow(f"¿'{alias}' es el NetBIOS de '{fqdn}'?  →  wsws domain alias {alias} {fqdn}"))
    return 0


# --- validador de vulnerabilidades conocidas ------------------------------------------

CHECK_STATUS = {"vuln": ("VULNERABLE", red), "no": ("no vulnerable", green), "?": ("sin respuesta", dim)}

# estado del motor nativo -> (etiqueta, color)
VSTATUS = {
    validate.VULNERABLE: ("VULNERABLE", magenta), validate.LIKELY_VULNERABLE: ("probable", red),
    validate.INCONCLUSIVE: ("inconcluso", yellow), validate.NOT_VULNERABLE: ("no vulnerable", green),
    validate.NOT_APPLICABLE: ("no aplica", dim), validate.ERROR: ("error", red),
}


def check_overview_legacy(st):
    tools = checks.tool_status()
    rows = []
    for name, c in checks.CHECKS.items():
        path = tools[c["tool"]][0]
        tg, out = checks.targets(st, name, [])
        rows.append([name, c["title"], str(c["port"]), str(len(tg)) + (f" (+{len(out)} fuera de scope)" if out else ""),
                     [("listo", green)] if path else [("falta " + c["tool"], red)]])
    table(["CHECK", "VALIDA", "PUERTO", "OBJETIVOS", "HERRAMIENTA"], rows, [bold, plain, plain, cyan, plain])
    for name, (path, how) in tools.items():
        if not path:
            print(dim(f"  {name}: {how}"))
    print(dim("uso: wsws check <eternalblue|bluekeep|printnightmare|all> [filtros] [--dry-run]   ·   wsws check -h"))
    return 0


def check_creds(st, opts):
    if opts.get("cred"):
        r = get_cred(st, opts["cred"])
        if r["kind"] not in ("password", "") or not r["secret"]:
            die(f"la credencial #{r['id']} no es una contraseña: el combo de PrintNightmare solo acepta -p")
        return r["domain"], r["username"], r["secret"]
    if opts.get("u") and opts.get("p") is not None:
        return opts.get("d", ""), opts["u"], opts["p"]
    die("PrintNightmare necesita credenciales: --cred <ID de wsws creds>  o  -d dominio -u usuario -p clave")


# --- motor nativo de validación (por omisión) ---------------------------------------

def resolve_creds_native(st, opts):
    """Credenciales para la sonda RPC: --cred <ID> o -d/-u/-p. -> ((dom,user,secret), is_hash) | (None, False)."""
    if opts.get("cred"):
        r = get_cred(st, opts["cred"])
        return (r["domain"], r["username"], r["secret"]), r["kind"] in ("hash", "ntlm")
    if opts.get("u") and opts.get("p") is not None:
        return (opts.get("d", ""), opts["u"], opts["p"]), False
    return None, False


def check_overview(st):
    rows = []
    for name in validate.names():
        v = validate.get(name)
        keep, out = run_query(vengine.targets, st, v, [])
        mode = [("activo+pasivo", cyan)] if vengine.has_probe(v) else [("pasivo", dim)]
        rows.append([name, v.title, "/".join(map(str, v.ports)),
                     str(len(keep)) + (f" (+{len(out)} fuera de scope)" if out else ""), mode])
    table(["VALIDADOR", "VALIDA", "PUERTOS", "OBJETIVOS", "MODO"], rows, [bold, plain, plain, cyan, plain])
    print(dim("activo = sonda nativa contra el objetivo (detección) · pasivo = razona sobre el Recon guardado"))
    print(dim("uso: wsws check <" + "|".join(validate.names()) + "|all> [filtros] [--passive] [--timeout N]"))
    print(dim("estados: VULNERABLE · probable · inconcluso · no vulnerable · no aplica · error   ·   "
              "checkers externos (legacy): wsws check --legacy ..."))
    return 0


def check_native(args):
    st = open_ws()
    if not args or args[0] in ("ls", "tools", "status"):
        return check_overview(st)
    vals = []
    for n in args[0].lower().split(","):
        if n == "all":
            vals += [validate.get(x) for x in validate.names()]
        elif validate.get(n):
            vals.append(validate.get(n))
        else:
            die(f"validador desconocido: {n!r}. Disponibles: {', '.join(validate.names())}, all")
    vals = list(dict.fromkeys(vals))
    opts, terms, it = {}, [], iter(args[1:])
    for a in it:
        if a in ("--dry-run", "--dry", "-n"):
            opts["dry"] = True
        elif a == "--force":
            opts["force"] = True
        elif a == "--passive":
            opts["passive"] = True
        elif a == "--bluekeep-active":
            opts["bluekeep_active"] = True
        elif a == "--timeout":
            v = next(it, None)
            if v is None or not v.replace(".", "", 1).isdigit():
                die("--timeout requiere un número de segundos")
            opts["timeout"] = float(v)
        elif a in ("--cred", "-c", "-u", "-p", "-d"):
            v = next(it, None)
            if v is None:
                die(f"{a} requiere un valor")
            opts[a.lstrip("-")] = v
        else:
            terms.append(a)
    try:
        terms = query.parse_terms(terms)
    except query.QueryError as e:
        die(str(e))
    force = FORCE or opts.get("force")
    results = []
    for v in vals:
        active = not opts.get("passive") and vengine.has_probe(v)
        ctx = {"timeout": opts.get("timeout", 5.0)}
        # BlueKeep activo es opt-in explícito (toca RDP): sonda de solo lectura, nunca el check que crashea
        if v.id == "bluekeep" and active and not opts.get("bluekeep_active"):
            active = False
            msg("bluekeep: sonda activa requiere --bluekeep-active (RDP solo lectura); se evalúa pasivo")
        # PrintNightmare activo necesita credenciales
        if active and v.requires_creds:
            creds, is_hash = resolve_creds_native(st, opts)
            if not creds:
                msg(f"{v.id}: la sonda RPC necesita credenciales (--cred/-u/-p); se evalúa pasivo")
                active = False
            else:
                ctx["creds"], ctx["is_hash"] = creds, is_hash
        tag = cyan("activo") if active else dim("pasivo")
        print(bold(f"\n▶ {v.title}  ({v.cve})  ") + f"[{tag}]", flush=True)
        if not opts.get("passive") and not vengine.has_probe(v):
            print(dim("  sin sonda activa nativa aún: se evalúa sobre el Recon guardado"))
        keep, out = run_query(vengine.targets, st, v, terms, force)
        if out:
            (warn if force else msg)(f"{len(out)} objetivo(s) fuera de scope "
                                     f"{'incluidos (--force)' if force else 'omitidos'}: {', '.join(out[:6])}")
        if not keep:
            warn(f"sin objetivos con {'/'.join(map(str, v.ports))} abierto en '{st.name}'"
                 + (" para esos filtros" if terms else "") + " (primero recon)")
            continue
        msg(f"{len(keep)} objetivo(s): {', '.join(keep[:8])}{' …' if len(keep) > 8 else ''}")
        if opts.get("dry"):
            print(dim(f"  (--dry-run) {'sondearía' if active else 'evaluaría (pasivo)'}: {', '.join(keep)}"))
            continue
        mode = "activo" if active else "pasivo"
        eid = st.ev_start(f"wsws check {v.id} · {len(keep)} objetivo(s) ({mode})", f"validate-{v.id}")
        res = [vengine.evaluate(st, v, a, active=active, ctx=ctx) for a in keep]
        for r in res:
            vengine.record(st, r, eid)
        cnt = Counter(r.status for r in res)
        st.ev_finish(eid, raw="\n".join(f"{r.addr} {r.status} · {r.reason}" for r in res), fmt="validate",
                     exit_code=0, summary=f"{v.id}: " + " · ".join(f"{k} {n}" for k, n in cnt.items()))
        results += res
    if not results:
        return 0
    from .validate.base import ORDER
    results.sort(key=lambda r: (ORDER[r.status], r.check, S.ipkey(r.addr)))
    print()
    table(["VALIDADOR", "ADDR", "RESULTADO", "MÉTODO", "RAZÓN"],
          [[r.check, r.addr, [VSTATUS[r.status]], r.method, r.reason] for r in results],
          [bold, cyan, plain, dim, dim], [16, 24, 14, 8, 90], flex=4)
    nv = sum(r.status == validate.VULNERABLE for r in results)
    nl = sum(r.status == validate.LIKELY_VULNERABLE for r in results)
    print(dim(f"{nv} vulnerable(s) y {nl} probable(s) guardado(s) como hallazgo · "
              f"ver: wsws vulns source:wsws-validate · detalle por host: wsws show <host>"))
    return 0


@command("check", "chk")
def cmd_check(args):
    if args and args[0] == "set":
        cfg = checks.load_config()
        for kv in args[1:]:
            k, _, v = kv.partition("=")
            if k not in ("printnightmare", "rdpscan") or not v:
                die("uso: wsws check set printnightmare=/ruta/al/repo  rdpscan=/ruta/rdpscan")
            cfg[k] = str(Path(v).expanduser().resolve())
            msg(f"{k} = {cfg[k]}")
        checks.save_config(cfg)
        return 0
    if "--legacy" not in args:
        return check_native(args)
    args = [a for a in args if a != "--legacy"]
    st = open_ws()
    if not args or args[0] in ("ls", "tools", "status"):
        return check_overview_legacy(st)
    names = []
    for n in args[0].lower().split(","):
        if n == "all":
            names += list(checks.CHECKS)
        elif n in checks.ALIASES:
            names.append(checks.ALIASES[n])
        else:
            die(f"check desconocido: {n!r}. Disponibles: {', '.join(checks.CHECKS)}, all")
    names = list(dict.fromkeys(names))
    opts, terms, it = {}, [], iter(args[1:])
    for a in it:
        if a in ("--dry-run", "--dry", "-n"):
            opts["dry"] = True
        elif a == "--force":
            opts["force"] = True
        elif a in ("--cred", "-c", "-u", "-p", "-d"):
            v = next(it, None)
            if v is None:
                die(f"{a} requiere un valor")
            opts[a.lstrip("-")] = v
        else:
            terms.append(a)
    try:
        terms = query.parse_terms(terms)
    except query.QueryError as e:
        die(str(e))
    force = FORCE or opts.get("force")
    tools = checks.tool_status()
    results = []
    for name in names:
        c = checks.CHECKS[name]
        print(bold(f"\n▶ {c['title']}"), flush=True)
        if not tools[c["tool"]][0] and not opts.get("dry"):
            warn(f"falta {c['tool']}: {tools[c['tool']][1]}")
            continue
        tg, out = run_query(checks.targets, st, name, terms, force)
        if out:
            (warn if force else msg)(f"{len(out)} objetivo(s) fuera de scope "
                                     f"{'incluidos (--force)' if force else 'omitidos'}: {', '.join(out[:6])}")
        if not tg:
            warn(f"sin objetivos con {c['port']} abierto en '{st.name}'"
                 + (" para esos filtros" if terms else "") + " (primero recon: wsws nmap -p445,3389 ...)")
            continue
        creds = check_creds(st, opts) if c.get("creds") else None
        with tempfile.TemporaryDirectory(prefix="wsws-check-") as tmp:
            tfile = Path(tmp) / "targets.txt"
            tfile.write_text("\n".join(tg) + "\n")
            try:
                argv, cwd, files, shown = checks.command(name, tfile, tmp, creds)
            except checks.CheckError as e:
                warn(str(e))
                continue
            msg(f"{len(tg)} objetivo(s): {', '.join(tg[:8])}{' …' if len(tg) > 8 else ''}")
            if opts.get("dry"):
                print(dim("  (--dry-run) se ejecutaría: ") + shown.replace(tmp, "<tmp>")
                      + (dim(f"   [en {cwd}]") if cwd else ""))
                continue
            eid = st.ev_start(f"wsws check {name} · {shown}", f"check-{name}")
            msg(dim(f"{st.name} · evidencia #{eid}"))
            try:
                rc, raw = runner.capture(argv, cwd=cwd)
            except OSError as e:
                st.ev_finish(eid, raw=str(e), exit_code=127, summary="no se pudo ejecutar")
                warn(f"no se pudo ejecutar: {e}")
                continue
            text = parsers.strip_ansi(raw.decode("utf-8", "replace"))
            if creds and creds[2]:
                text = text.replace(creds[2], "****")
            res = checks.parse(name, text, files)
            checks.record(st, res, eid)
            cnt = Counter(r["status"] for r in res)
            summ = f"{name}: vulnerables {cnt['vuln']} · no {cnt['no']} · sin respuesta {cnt['?']}"
            st.ev_finish(eid, raw=text, fmt="check", exit_code=rc, attach=[f for f in files if Path(f).is_file()],
                         summary=summ)
            if not res:
                warn(f"no pude leer resultados de {c['tool']} (exit {rc}). Revisa: wsws log {eid} --raw")
            results += res
    if not results:
        return 0 if opts.get("dry") else 1
    order = {"vuln": 0, "?": 1, "no": 2}
    results.sort(key=lambda r: (order[r["status"]], r["check"], S.ipkey(r["addr"])))
    print()
    table(["CHECK", "ADDR", "RESULTADO", "DETALLE"],
          [[r["check"], r["addr"], [CHECK_STATUS[r["status"]]], r["detail"]] for r in results],
          [bold, cyan, plain, dim], [16, 40, 14, 100], flex=3)
    n = sum(r["status"] == "vuln" for r in results)
    print(dim(f"{n} vulnerable(s) guardado(s) como hallazgo validado · ver: wsws vulns source:{checks.SOURCE}"
              f" · etiquetas: wsws tag:<check>:vuln"))
    return 0


# --- evidencia y resumen ------------------------------------------------------------

@command("log", "timeline", "ev")
def cmd_log(args):
    st = open_ws()
    if args and args[0].lstrip("#").isdigit():
        e = st.one("SELECT * FROM evidence WHERE id=?", (int(args[0].lstrip("#")),))
        if not e:
            die("evidencia no encontrada")
        print(bold(f"#{e['id']} {e['cmd']}"))
        print(dim(f"{local_ts(e['ts_start'], '%Y-%m-%d %H:%M:%S')} → {local_ts(e['ts_end'], '%H:%M:%S')} · "
                  f"{e['operator']} · cwd {e['cwd']} · exit {e['exit_code']} · formato {e['fmt']}"))
        print(dim(f"sha256 {e['sha256']}"))
        print(f"{e['summary']}")
        for f in S.split_list(e["files"]):
            print(f"  {st.evdir / f}")
        log = next((f for f in S.split_list(e["files"]) if f.endswith(".log")), None)
        if log and "--raw" in args:
            print((st.evdir / log).read_text())
        return 0
    n = int(args[args.index("-n") + 1]) if "-n" in args else 30
    rows = st.q("SELECT * FROM (SELECT * FROM evidence ORDER BY id DESC LIMIT ?) ORDER BY id", (n,))
    if not rows:
        print(dim("sin evidencias todavía"))
        return 0
    table(["#", "INICIO", "OPERADOR", "COMANDO", "RESULTADO"],
          [[str(e["id"]), local_ts(e["ts_start"]), e["operator"], e["cmd"], e["summary"]] for e in rows],
          [dim, plain, dim, bold, plain], [6, 16, 14, 90, 90], flex=3)
    return 0


@command("stats", "status")
def cmd_stats(args):
    st = open_ws()
    one = lambda sql: st.one(sql)["n"]  # noqa: E731
    sev = {r["sev"]: r["n"] for r in st.q("SELECT sev, COUNT(*) n FROM findings GROUP BY sev")}
    print(f"{bold('wsws')} · {bold(cyan(st.name))}   {dim('operador ' + S.operator())}")
    vul = ", ".join(SEV_COLOR[s](f"{SEV_SHORT[s]} {sev[s]}") for s in sorted(sev, reverse=True) if s >= 1)
    n_hosts = one("SELECT COUNT(*) n FROM hosts")
    n_svc = one("SELECT COUNT(*) n FROM services WHERE state LIKE 'open%'")
    n_web = one("SELECT COUNT(*) n FROM web")
    n_creds = one("SELECT COUNT(*) n FROM creds")
    n_admin = one("SELECT COUNT(*) n FROM creds WHERE admin=1")
    n_ev = one("SELECT COUNT(*) n FROM evidence")
    print(f"  hosts {bold(n_hosts)} · servicios {bold(n_svc)} · web {bold(n_web)} · vulns "
          f"{bold(sum(v for k, v in sev.items() if k >= 1))}{' (' + vul + ')' if vul else ''} · creds {bold(n_creds)}"
          f"{' (' + red(f'{n_admin} admin') + ')' if n_admin else ''} · evidencias {bold(n_ev)}")
    inc, exc = st.rules()
    print(f"  scope: {', '.join(inc) or dim('sin definir')}" + (f"  {dim('excl.')} {', '.join(exc)}" if exc else ""))
    top = st.q("SELECT port, name, COUNT(*) n FROM services WHERE state LIKE 'open%' GROUP BY port "
               "ORDER BY n DESC, port LIMIT 12")
    if top:
        print("  top puertos: " + "  ".join(f"{bold(r['port'])}{dim('/' + r['name'] if r['name'] else '')}"
                                             f"{dim('×')}{r['n']}" for r in top))
    evs = st.q("SELECT * FROM evidence ORDER BY id DESC LIMIT 5")
    if evs:
        print("  últimas acciones:")
        for e in reversed(evs):
            print(f"    {dim('#' + str(e['id']))} {local_ts(e['ts_start'], '%m-%d %H:%M')} "
                  f"{trunc(e['cmd'], 60):<60} {dim(e['summary'])}")
    else:
        print(dim("  vacío. Prueba: wsws nmap -sV <objetivo>   o   nmap ... | wsws"))
    return 0


HELP_FLAGS = ("-h", "--help", "help")


@command("help", "-h", "--help")
def cmd_help(args):
    if args:
        text = helptext.get(" ".join(args))
        if text is None:
            die(f"no hay ayuda para '{' '.join(args)}'. Comandos: find hosts vulns web creds show add run use ls rm "
                "tag note scope domain log stats")
        print(text)
        return 0
    print(HELP.format(v=__version__))
    return 0


def help_topic(cmd, rest):
    """Si el usuario pidió ayuda (`wsws vulns -h`, `wsws creds add help`...), el tema; si no, None."""
    if not rest:
        return None
    if helptext.ALIASES.get(cmd, cmd) == "creds" and rest[0] in ("add", "mod", "edit", "rm", "del"):
        return f"creds {rest[0]}" if help_topic(cmd, rest[1:]) else None
    if rest[0] in HELP_FLAGS:
        return cmd
    # al final también vale (wsws vulns sev:high -h), salvo en run: ahí -h es de la herramienta
    if cmd != "run" and rest[-1] in ("-h", "--help"):
        return cmd
    return None


@command("version", "-V", "--version")
def cmd_version(args):
    print(f"wsws {__version__}")
    return 0


def stdin_has_input():
    """True solo si stdin es un pipe (`cmd | wsws`) o un archivo (`wsws < f`).

    Un stdin heredado que no es terminal (scripts, cron, procesos en segundo plano) no cuenta:
    leerlo dejaría a `wsws` esperando para siempre.
    """
    try:
        mode = os.fstat(sys.stdin.fileno()).st_mode
    except (OSError, ValueError):
        return False
    return stat.S_ISFIFO(mode) or stat.S_ISREG(mode)


def dispatch(argv):
    global FORCE
    while argv and argv[0] in ("-w", "--workspace", "--force"):
        a = argv.pop(0)
        if a == "--force":
            FORCE = True
        elif not argv:
            die("-w requiere un nombre de workspace")
        else:
            os.environ["WSWS"] = argv.pop(0)
    if not argv:
        return cmd_add([]) if stdin_has_input() else cmd_stats([])
    cmd, rest = argv[0], argv[1:]
    if cmd in COMMANDS:
        topic = help_topic(cmd, rest)
        return cmd_help([topic]) if topic and cmd not in HELP_FLAGS else COMMANDS[cmd](rest)
    if cmd in runner.KNOWN_TOOLS or (cmd == "sudo" and rest):
        return cmd_run(argv)
    if argv[-1] in ("-h", "--help"):
        return cmd_help(["find"])
    return cmd_find(argv)


def _fix_owner():
    """Si corrió con sudo, devolver los archivos al operador."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() != 0 or not uid or not S.HOME.exists():
        return
    for root, dirs, files in os.walk(S.HOME):
        for p in [root] + [os.path.join(root, x) for x in dirs + files]:
            try:
                os.chown(p, int(uid), int(gid or uid))
            except OSError:
                pass


def main(argv=None):
    try:
        rc = dispatch(list(sys.argv[1:] if argv is None else argv))
    except KeyboardInterrupt:
        rc = 130
    except BrokenPipeError:
        # `wsws ... | head`: el lector cerró antes; no es un error
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        rc = 0
    _fix_owner()
    sys.exit(rc or 0)
