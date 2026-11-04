"""DCERPC v5 mínimo sobre un named pipe SMB2 (bind + request) — solo librería estándar.

Lo justo para enlazar una interfaz y hacer una llamada, leyendo el código de retorno / fault. No
marshalla estructuras genéricas: el stub de cada llamada lo arma quien la usa.
"""
import struct

# PTYPE
PT_REQUEST = 0
PT_RESPONSE = 2
PT_FAULT = 3
PT_BIND = 11
PT_BIND_ACK = 12
PT_BIND_NAK = 13

PFC_FIRST = 0x01
PFC_LAST = 0x02
DREP = b"\x10\x00\x00\x00"   # little-endian, ASCII

# sintaxis de transferencia NDR 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0
NDR_SYNTAX = bytes.fromhex("045d888aeb1cc91100" "9fe808002b104860") + struct.pack("<HH", 2, 0)


def uuid_to_bin(uuid, ver_major, ver_minor=0):
    """UUID 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -> binario DCE (3 campos LE + 2 as-is) + versión."""
    a, b, c, d, e = uuid.split("-")
    bin_ = (struct.pack("<I", int(a, 16)) + struct.pack("<H", int(b, 16)) + struct.pack("<H", int(c, 16))
            + bytes.fromhex(d) + bytes.fromhex(e))
    return bin_ + struct.pack("<HH", ver_major, ver_minor)


def _header(ptype, frag_len, call_id, auth_len=0):
    return struct.pack("<BBBB4sHHI", 5, 0, ptype, PFC_FIRST | PFC_LAST, DREP, frag_len, auth_len, call_id)


def build_bind(iface_uuid, ver_major, ver_minor=0, call_id=1):
    ctx = (struct.pack("<HBB", 0, 1, 0)                        # ctx_id=0, num_trans=1, reserved
           + uuid_to_bin(iface_uuid, ver_major, ver_minor)     # abstract syntax
           + NDR_SYNTAX)                                       # transfer syntax
    body = struct.pack("<HHIBBH", 4280, 4280, 0, 1, 0, 0) + ctx
    return _header(PT_BIND, 16 + len(body), call_id) + body


def build_request(opnum, stub, call_id=1, ctx_id=0):
    body = struct.pack("<IHH", len(stub), ctx_id, opnum) + stub
    return _header(PT_REQUEST, 16 + len(body), call_id) + body


def parse(pdu):
    """-> dict con ptype y, según el caso, 'ret' (código de retorno) o 'fault'."""
    if len(pdu) < 16:
        return {"ptype": None, "error": "PDU demasiado corta"}
    ptype = pdu[2]
    out = {"ptype": ptype}
    if ptype == PT_FAULT:
        out["fault"] = struct.unpack("<I", pdu[24:28])[0] if len(pdu) >= 28 else None
    elif ptype == PT_RESPONSE:
        stub = pdu[24:]
        out["stub"] = stub
        out["ret"] = struct.unpack("<I", stub[-4:])[0] if len(stub) >= 4 else None
    return out
