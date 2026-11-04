"""SMB1 mínimo para la detección de MS17-010 (EternalBlue) — solo librería estándar.

Detección canónica y de SOLO LECTURA: se abre una sesión nula, se conecta a `IPC$` y se hace un
PeekNamedPipe sobre un FID inexistente (0x0000). El código NT_STATUS de la respuesta distingue:

  * STATUS_INSUFF_SERVER_RESOURCES (0xC0000205)  -> patrón de un sistema vulnerable a MS17-010
  * STATUS_INVALID_HANDLE / INVALID_PARAMETER     -> el servidor trata el handle como parcheado

No modifica el objetivo (no instala, no escribe, no ejecuta): solo lee un código de error. Ante
cualquier respuesta no esperada, la conclusión es INCONCLUSIVE, nunca un falso "no vulnerable".
"""
import socket
import struct

# NT_STATUS relevantes
STATUS_SUCCESS = 0x00000000
STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205   # vulnerable
STATUS_INVALID_HANDLE = 0xC0000008            # parcheado
STATUS_INVALID_PARAMETER = 0xC000000D         # parcheado (algunas builds)

CMD_NEGOTIATE = 0x72
CMD_SESSION_SETUP = 0x73
CMD_TREE_CONNECT = 0x75
CMD_TRANSACTION = 0x25
TRANS_PEEK_NMPIPE = 0x0023

FLAGS = 0x18                 # case-insensitive + canonical paths
FLAGS2 = 0x4001             # NT_STATUS + long names (sin unicode: cadenas ASCII)
PID = 0xFEFF


class SMBError(Exception):
    pass


# --- NetBIOS / framing ----------------------------------------------------------------

def _nbss(payload):
    """Session message NetBIOS: 1 byte tipo (0x00) + 3 de longitud + payload."""
    return struct.pack(">I", len(payload) & 0xFFFFFF) + payload


def smb_header(command, tid=0, uid=0, mid=0):
    return (b"\xffSMB" + struct.pack("<B", command) + struct.pack("<I", 0)   # status (0 en request)
            + struct.pack("<B", FLAGS) + struct.pack("<H", FLAGS2)
            + struct.pack("<H", 0) + b"\x00" * 8 + struct.pack("<H", 0)      # PIDHigh, firma, reservado
            + struct.pack("<H", tid) + struct.pack("<H", PID)
            + struct.pack("<H", uid) + struct.pack("<H", mid))


# --- constructores de paquetes --------------------------------------------------------

def build_negotiate():
    dialects = b"\x02NT LM 0.12\x00"
    body = b"\x00" + struct.pack("<H", len(dialects)) + dialects   # WordCount=0 + ByteCount + dialectos
    return _nbss(smb_header(CMD_NEGOTIATE) + body)


def build_session_setup():
    # Session Setup AndX, WordCount=13 (seguridad NO extendida), sesión nula (passwords de largo 0)
    params = struct.pack("<BBHHHHIHHII",
                         0xFF, 0x00, 0,       # AndX: sin comando encadenado
                         0xFFFF, 2, 1,        # MaxBuffer, MaxMpx, VcNumber
                         0,                   # SessionKey
                         0, 0,                # OEMPasswordLen, UnicodePasswordLen (sesión nula)
                         0, 0)                # Reserved, Capabilities (0 = sin extended security)
    data = b"\x00" + b"\x00" + b"Python\x00" + b"wsws\x00"   # Account, Domain, NativeOS, NativeLanMan (ASCII)
    body = struct.pack("<B", 13) + params + struct.pack("<H", len(data)) + data
    return _nbss(smb_header(CMD_SESSION_SETUP) + body)


def build_tree_connect(host, uid):
    path = ("\\\\%s\\IPC$" % host).upper().encode() + b"\x00"
    service = b"?????\x00"
    data = b"\x00" + path + service                     # Password (1 byte) + Path + Service
    params = struct.pack("<BBHHH", 0xFF, 0x00, 0, 0, 1)  # AndX..., Flags=0, PasswordLength=1
    body = struct.pack("<B", 4) + params + struct.pack("<H", len(data)) + data
    return _nbss(smb_header(CMD_TREE_CONNECT, uid=uid) + body)


def build_trans_peek(uid, tid, fid=0x0000):
    setup = struct.pack("<HH", TRANS_PEEK_NMPIPE, fid)
    name = b"\\PIPE\\\x00"
    # 14 words + SetupCount(2) = 16 words
    params = struct.pack("<HHHHBBHIHHHHHBB",
                         0, 0,            # TotalParameterCount, TotalDataCount
                         0xFFFF, 0xFFFF,  # MaxParameterCount, MaxDataCount
                         0, 0,            # MaxSetupCount, Reserved1
                         0,               # Flags
                         0,               # Timeout
                         0,               # Reserved2
                         0, 0,            # ParameterCount, ParameterOffset
                         0, 0,            # DataCount, DataOffset
                         2, 0)            # SetupCount=2, Reserved3
    body = struct.pack("<B", 16) + params + setup + struct.pack("<H", len(name)) + name
    return _nbss(smb_header(CMD_TRANSACTION, tid=tid, uid=uid, mid=1) + body)


# --- parseo ---------------------------------------------------------------------------

def parse_status(resp):
    """NT_STATUS del header SMB (offset 5..8), o None si la respuesta es muy corta."""
    if len(resp) < 9 or resp[:4] != b"\xffSMB":
        return None
    return struct.unpack("<I", resp[5:9])[0]


def _uid(resp):
    return struct.unpack("<H", resp[28:30])[0] if len(resp) >= 30 else 0


def _tid(resp):
    return struct.unpack("<H", resp[24:26])[0] if len(resp) >= 26 else 0


def interpret(nt):
    if nt == STATUS_INSUFF_SERVER_RESOURCES:
        return {"status": "vuln",
                "detail": "STATUS_INSUFF_SERVER_RESOURCES: patrón de respuesta de un host MS17-010", "nt": nt}
    if nt in (STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER):
        return {"status": "no",
                "detail": "el servidor maneja el handle inválido como un sistema parcheado", "nt": nt}
    return {"status": "inconclusive",
            "detail": "respuesta SMB no concluyente para MS17-010", "nt": nt}


# --- E/S ------------------------------------------------------------------------------

def _send(sock, pkt):
    sock.sendall(pkt)


def _recv_smb(sock):
    """Lee un mensaje NetBIOS (4 bytes de cabecera + payload) y devuelve el payload SMB."""
    hdr = _recv_exact(sock, 4)
    length = struct.unpack(">I", hdr)[0] & 0xFFFFFF
    if length == 0 or length > 0x1FFFF:
        raise SMBError(f"longitud NBSS fuera de rango: {length}")
    return _recv_exact(sock, length)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SMBError("conexión cerrada por el servidor")
        buf += chunk
    return buf


def _nb_session_request(sock, host):
    """Para puerto 139: solicitud de sesión NetBIOS (nombres codificados de 16 bytes)."""
    def enc(name):
        name = (name.upper()[:15]).ljust(15) + "\x00"
        out = bytearray()
        for ch in name.encode("latin-1"):
            out += bytes([(ch >> 4) + 0x41, (ch & 0xF) + 0x41])
        return b"\x20" + bytes(out) + b"\x00"
    payload = enc("*SMBSERVER") + enc("WSWS")
    _send(sock, struct.pack(">BBH", 0x81, 0x00, len(payload)) + payload)
    resp = _recv_exact(sock, 4)
    if resp[0] != 0x82:   # 0x82 = positive session response
        raise SMBError("NetBIOS rechazó la sesión (139)")


# --- comprobación completa ------------------------------------------------------------

def check_ms17_010(host, port=445, timeout=5.0):
    """Conecta y aplica la detección MS17-010. -> {status, detail, nt}.

    status: 'vuln' | 'no' | 'inconclusive' | 'error'. Nunca modifica el objetivo.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return {"status": "error", "detail": f"conexión a {host}:{port} fallida: {e}", "nt": None}
    sock.settimeout(timeout)
    try:
        if port == 139:
            _nb_session_request(sock, host)
        _send(sock, build_negotiate())
        _recv_smb(sock)
        _send(sock, build_session_setup())
        ss = _recv_smb(sock)
        if parse_status(ss) != STATUS_SUCCESS:
            return {"status": "inconclusive",
                    "detail": "sesión nula rechazada: se requieren credenciales para comprobar", "nt": parse_status(ss)}
        uid = _uid(ss)
        _send(sock, build_tree_connect(host, uid))
        tc = _recv_smb(sock)
        if parse_status(tc) != STATUS_SUCCESS:
            return {"status": "inconclusive", "detail": "no se pudo conectar a IPC$", "nt": parse_status(tc)}
        tid = _tid(tc)
        _send(sock, build_trans_peek(uid, tid))
        tr = _recv_smb(sock)
        return interpret(parse_status(tr))
    except (OSError, SMBError) as e:
        return {"status": "error", "detail": str(e), "nt": None}
    finally:
        sock.close()
