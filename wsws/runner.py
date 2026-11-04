"""Modo wrapper: ejecuta la herramienta, muestra su salida tal cual y la deja lista para ingerir."""
import os
import signal
import subprocess
import sys
from pathlib import Path

from .parsers import is_hostname, is_ip, split_target
from .store import as_net

# herramientas que se pueden llamar directo: `wsws nmap ...`
KNOWN_TOOLS = {"nmap", "masscan", "naabu", "nuclei", "httpx", "nxc", "netexec", "crackmapexec", "rustscan"}
CRED_TOOLS = {"nxc", "netexec", "crackmapexec"}
PD_TOOLS = {"nuclei", "httpx", "naabu"}

# flags cuyo valor NO es un objetivo (para el chequeo de scope)
VALUE_FLAGS = {
    "-p", "-P", "--port", "--ports", "--top-ports", "-o", "-oN", "-oX", "-oG", "-oA", "-oS", "-oJ", "-oL",
    "--script", "--script-args", "--script-timeout", "--exclude", "--excludefile", "--rate", "--min-rate",
    "--max-rate", "--max-retries", "--host-timeout", "-D", "-S", "-g", "--source-port", "--data-length",
    "--ttl", "--spoof-mac", "--dns-servers", "-e", "-c", "-rl", "-rate-limit", "-timeout", "-retries",
    "-H", "-header", "-t", "-tags", "-etags", "-severity", "-s", "-es", "-w", "-x", "-X", "-M", "-d",
    "-jle", "-je", "-json-export", "-jsonl-export", "-a", "-b",
}
CRED_FLAGS = {"-u", "--username", "-p", "--password", "-H", "--hash", "-d", "--domain", "-k"}
LIST_FLAGS = {"nmap": {"-iL"}, "masscan": {"-iL", "--includefile"}}


def _read_list(path):
    try:
        return [ln.strip() for ln in Path(path).read_text().splitlines() if ln.strip() and not ln.startswith("#")]
    except OSError:
        return []


def targets(tool, args):
    """Extrae los objetivos (IP, CIDR, hostname, URL) de la línea de comandos."""
    raw, i = [], 0
    value_flags = VALUE_FLAGS | (CRED_FLAGS if tool in CRED_TOOLS else set())
    list_flags = LIST_FLAGS.get(tool, {"-l", "-list"} if tool in PD_TOOLS else set())
    target_flags = {"-u", "-target", "-host"} if tool in PD_TOOLS else set()
    while i < len(args):
        a = args[i]
        if a in list_flags and i + 1 < len(args):
            raw += _read_list(args[i + 1])
            i += 2
        elif a in target_flags and i + 1 < len(args):
            raw += args[i + 1].split(",")
            i += 2
        elif a in value_flags:
            i += 2
        elif a.startswith("-") or "=" in a or os.path.exists(a):
            i += 1
        else:
            raw.append(a)
            i += 1
    out = []
    for t in raw:
        for part in t.split(","):
            if as_net(part):
                out.append(part)
                continue
            h, _, _ = split_target(part)
            if is_ip(h) or is_hostname(h):
                out.append(h)
    return out


def prepare(tool, args, tmpdir):
    """Inyecta salida estructurada sin cambiar lo que ve el operador. -> (args, archivos_a_parsear)"""
    files = []
    if tool == "nmap":
        for i, a in enumerate(args[:-1]):
            if a == "-oX" and args[i + 1] != "-":
                files.append(args[i + 1])
            elif a == "-oA":
                files.append(args[i + 1] + ".xml")
        if not files and "-oX" not in args:
            files.append(str(tmpdir / "nmap.xml"))
            args = args + ["-oX", files[0]]
    elif tool == "nuclei":
        if not any(a in ("-je", "-json-export", "-jle", "-jsonl-export") for a in args):
            files.append(str(tmpdir / "nuclei.jsonl"))
            args = args + ["-jle", files[0]]
    return args, files


def capture(argv, cwd=None):
    """Ejecuta argv mostrando la salida en vivo (con colores si hay TTY). -> (exit_code, bytes)"""
    buf = bytearray()
    # el hijo recibe Ctrl-C; nosotros sobrevivimos para guardar lo que alcanzó a salir
    old = signal.signal(signal.SIGINT, lambda *_: None)
    try:
        if sys.stdout.isatty():
            import fcntl
            import pty
            import termios
            master, slave = pty.openpty()
            try:
                size = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, b"\0" * 8)
                fcntl.ioctl(slave, termios.TIOCSWINSZ, size)
            except OSError:
                pass
            try:
                p = subprocess.Popen(argv, stdout=slave, stderr=slave, cwd=cwd)
            finally:
                os.close(slave)
            while True:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    break
                if not data:
                    break
                os.write(sys.stdout.fileno(), data)
                buf += data
            os.close(master)
        else:
            p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd)
            while True:
                data = p.stdout.read1(65536)
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
                buf += data
        rc = p.wait()
    finally:
        signal.signal(signal.SIGINT, old)
    return rc, bytes(buf)
