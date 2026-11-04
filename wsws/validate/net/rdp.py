"""Sonda RDP de SOLO LECTURA: negociación X.224 para detectar si el host exige NLA/CredSSP.

Envía una Connection Request estándar (como cualquier cliente RDP al iniciar) y lee la Connection
Confirm. NO toca la ruta vulnerable de BlueKeep (canal MS_T120): no puede provocar el crash del CVE.
Sirve para saber si NLA está impuesto (mitiga la explotación no autenticada) y qué protocolo ofrece.
"""
import socket
import struct

# protocolos RDP (selectedProtocol)
PROTOCOL_RDP = 0x00
PROTOCOL_SSL = 0x01
PROTOCOL_HYBRID = 0x02       # CredSSP (NLA)
PROTOCOL_HYBRID_EX = 0x08

TYPE_NEG_RSP = 0x02
TYPE_NEG_FAILURE = 0x03


def _connection_request():
    cookie = b"Cookie: mstshash=wsws\r\n"
    neg_req = struct.pack("<BBHI", 0x01, 0x00, 0x0008, PROTOCOL_SSL | PROTOCOL_HYBRID)
    fixed = struct.pack(">BHHB", 0xE0, 0, 0, 0)          # CR+CDT, DST-REF, SRC-REF, class
    variable = cookie + neg_req
    li = len(fixed) + len(variable)
    x224 = bytes([li]) + fixed + variable
    return struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224


def probe_security(host, port=3389, timeout=5.0):
    """-> {status, nla, selected, detail}. status: 'ok' | 'error'. No modifica el objetivo."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return {"status": "error", "nla": None, "selected": None, "detail": f"conexión fallida: {e}"}
    sock.settimeout(timeout)
    try:
        sock.sendall(_connection_request())
        hdr = _recv_exact(sock, 4)
        total = struct.unpack(">H", hdr[2:4])[0]
        body = _recv_exact(sock, max(0, total - 4))
    except OSError as e:
        return {"status": "error", "nla": None, "selected": None, "detail": f"sin respuesta X.224: {e}"}
    finally:
        sock.close()

    # neg structure tras: LI(1) + parte fija X.224 (6) => offset 7 dentro de body
    if len(body) < 7 + 8:
        return {"status": "ok", "nla": None, "selected": None,
                "detail": "el servidor no devolvió rdpNegResp (RDP antiguo o sin negociación)"}
    neg = body[7:15]
    ntype = neg[0]
    if ntype == TYPE_NEG_RSP:
        selected = struct.unpack("<I", neg[4:8])[0]
        nla = bool(selected & (PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX))
        return {"status": "ok", "nla": nla, "selected": selected,
                "detail": f"selectedProtocol=0x{selected:02X} ({'NLA/CredSSP' if nla else 'RDP/SSL'})"}
    if ntype == TYPE_NEG_FAILURE:
        code = struct.unpack("<I", neg[4:8])[0]
        # failureCode 0x00000005 = HYBRID_REQUIRED_BY_SERVER -> NLA obligatorio
        nla = code == 0x00000005
        return {"status": "ok", "nla": nla, "selected": None,
                "detail": f"negFailure code=0x{code:08X}" + (" (NLA obligatorio)" if nla else "")}
    return {"status": "ok", "nla": None, "selected": None, "detail": "respuesta X.224 no reconocida"}


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("conexión cerrada por el servidor")
        buf += chunk
    return buf
