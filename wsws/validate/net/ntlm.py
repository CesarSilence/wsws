"""NTLM (v2) para autenticar las sondas SMB2 — solo librería estándar.

Incluye MD4 en Python puro (RFC 1320, de dominio público) porque OpenSSL 3 ya no lo expone, y el
cálculo NTLMv2 de MS-NLMP: NTOWFv2, NTProofStr, respuesta NTLMv2 y clave de sesión (para firmar SMB2).
Acepta contraseña o hash NT. No es criptografía ofensiva: es el cliente de autenticación mínimo.
"""
import hashlib
import hmac
import os
import struct
import time

# flags NTLMSSP
NEG_UNICODE = 0x00000001
NEG_OEM = 0x00000002
NEG_REQUEST_TARGET = 0x00000004
NEG_NTLM = 0x00000200
NEG_ALWAYS_SIGN = 0x00008000
NEG_EXTENDED_SEC = 0x00080000
NEG_TARGET_INFO = 0x00800000
NEG_128 = 0x20000000
NEG_56 = 0x80000000

TYPE1_FLAGS = (NEG_UNICODE | NEG_OEM | NEG_REQUEST_TARGET | NEG_NTLM | NEG_ALWAYS_SIGN
               | NEG_EXTENDED_SEC | NEG_TARGET_INFO | NEG_128 | NEG_56)


def md4(data):
    """MD4 (RFC 1320) en Python puro. Devuelve 16 bytes."""
    def lrot(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    bitlen = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += struct.pack("<Q", bitlen)

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        a, b, c, d = a0, b0, c0, d0

        def F(x, y, z):
            return (x & y) | (~x & z)

        def G(x, y, z):
            return (x & y) | (x & z) | (y & z)

        def H(x, y, z):
            return x ^ y ^ z

        for i in (0, 4, 8, 12):   # ronda 1
            a = lrot(a + F(b, c, d) + X[i], 3)
            d = lrot(d + F(a, b, c) + X[i + 1], 7)
            c = lrot(c + F(d, a, b) + X[i + 2], 11)
            b = lrot(b + F(c, d, a) + X[i + 3], 19)
        for i in (0, 1, 2, 3):    # ronda 2
            a = lrot(a + G(b, c, d) + X[i] + 0x5A827999, 3)
            d = lrot(d + G(a, b, c) + X[i + 4] + 0x5A827999, 5)
            c = lrot(c + G(d, a, b) + X[i + 8] + 0x5A827999, 9)
            b = lrot(b + G(c, d, a) + X[i + 12] + 0x5A827999, 13)
        for i in (0, 2, 1, 3):    # ronda 3 (orden 0,8,4,12 / 2,10,6,14 / 1,9,5,13 / 3,11,7,15)
            a = lrot(a + H(b, c, d) + X[i] + 0x6ED9EBA1, 3)
            d = lrot(d + H(a, b, c) + X[i + 8] + 0x6ED9EBA1, 9)
            c = lrot(c + H(d, a, b) + X[i + 4] + 0x6ED9EBA1, 11)
            b = lrot(b + H(c, d, a) + X[i + 12] + 0x6ED9EBA1, 15)
        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF
    return struct.pack("<4I", a0, b0, c0, d0)


def nt_hash(password):
    return md4(password.encode("utf-16-le"))


def ntowfv2(nt_hash_bytes, user, domain):
    return hmac.new(nt_hash_bytes, (user.upper() + domain).encode("utf-16-le"), hashlib.md5).digest()


def _filetime():
    return int((time.time() + 11644473600) * 10_000_000)


def compute_ntlmv2(user, domain, secret, is_hash, server_challenge, target_info, client_challenge=None):
    """Devuelve (nt_response, session_key). secret = contraseña o hash NT (hex) según is_hash."""
    nth = bytes.fromhex(secret.split(":")[-1]) if is_hash else nt_hash(secret)
    key = ntowfv2(nth, user, domain)
    cc = client_challenge or os.urandom(8)
    temp = (b"\x01\x01" + b"\x00" * 6 + struct.pack("<Q", _filetime()) + cc + b"\x00" * 4
            + target_info + b"\x00" * 4)
    proof = hmac.new(key, server_challenge + temp, hashlib.md5).digest()
    nt_response = proof + temp
    session_key = hmac.new(key, proof, hashlib.md5).digest()   # SMB2 2.1: clave base = exportada (sin KEY_EXCH)
    return nt_response, session_key


# --- mensajes NTLMSSP -----------------------------------------------------------------

SIG = b"NTLMSSP\x00"


def make_type1():
    return (SIG + struct.pack("<I", 1) + struct.pack("<I", TYPE1_FLAGS)
            + struct.pack("<HHI", 0, 0, 0) + struct.pack("<HHI", 0, 0, 0))   # dominio/workstation vacíos


def parse_type2(blob):
    """-> (server_challenge 8B, target_info bytes)."""
    if blob[:8] != SIG or struct.unpack("<I", blob[8:12])[0] != 2:
        raise ValueError("mensaje NTLM type2 inválido")
    server_challenge = blob[24:32]
    ti_len, _, ti_off = struct.unpack("<HHI", blob[40:48])
    target_info = blob[ti_off:ti_off + ti_len]
    return server_challenge, target_info


def make_type3(user, domain, workstation, nt_response, session_key, flags):
    sig_dom = domain.encode("utf-16-le")
    sig_user = user.encode("utf-16-le")
    sig_ws = workstation.encode("utf-16-le")
    lm = b"\x00" * 24
    # payload: LM, NT, Domain, User, Workstation, EncryptedSessionKey(vacío)
    base = 64
    off = base
    fields = []
    chunks = []
    for blob in (lm, nt_response, sig_dom, sig_user, sig_ws, b""):
        fields.append(struct.pack("<HHI", len(blob), len(blob), off))
        chunks.append(blob)
        off += len(blob)
    # orden en cabecera: LM, NT, Domain, User, Workstation, SessionKey
    header = (SIG + struct.pack("<I", 3)
              + fields[0] + fields[1] + fields[2] + fields[3] + fields[4] + fields[5]
              + struct.pack("<I", flags))
    # cabecera real son 64 bytes: ajustar offsets ya calculados desde 64
    return header + b"".join(chunks)
