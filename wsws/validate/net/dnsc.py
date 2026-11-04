"""Resolución DNS inversa (PTR) — solo librería estándar.

Dos modos:
  - `server=None`  -> usa el resolver del sistema (`socket.gethostbyaddr`).
  - `server="IP"`  -> arma una consulta PTR y la manda por UDP a ese servidor (p. ej. el DC del dominio),
                      sin depender del resolver del sistema. Soporta IPv4; IPv6 cae al resolver del sistema.
"""
import os
import socket
import struct


def reverse_lookup(ip, server=None, timeout=2.0):
    """-> hostname (sin punto final) o None."""
    if not server:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror, socket.gaierror):
            return None
    if ":" in ip:   # IPv6: sin cliente propio, usar el del sistema
        try:
            return socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror, socket.gaierror):
            return None
    try:
        return _ptr_query(server, ip, timeout)
    except (OSError, ValueError):
        return None


def _ptr_name(ip):
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def build_query(ip, tid=None):
    tid = tid if tid is not None else int.from_bytes(os.urandom(2), "big")
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)   # RD=1, 1 pregunta
    qname = b"".join(struct.pack("B", len(p)) + p.encode("ascii") for p in _ptr_name(ip).split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 12, 1)          # QTYPE=PTR, QCLASS=IN


def _read_name(data, off):
    labels, jumped, start = [], False, off
    while True:
        length = data[off]
        if length & 0xC0 == 0xC0:                 # puntero de compresión
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                start = off + 2
            off, jumped = ptr, True
            continue
        off += 1
        if length == 0:
            break
        labels.append(data[off:off + length].decode("latin-1"))
        off += length
    return ".".join(labels), (start if jumped else off)


def parse_answer(data):
    """Extrae el primer nombre PTR de una respuesta DNS, o None."""
    if len(data) < 12:
        return None
    qd, an = struct.unpack(">HH", data[4:8])
    off = 12
    for _ in range(qd):                           # saltar preguntas
        _, off = _read_name(data, off)
        off += 4
    for _ in range(an):
        _, off = _read_name(data, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype == 12:                           # PTR
            name, _ = _read_name(data, off)
            return name.rstrip(".") or None
        off += rdlen
    return None


def _ptr_query(server, ip, timeout):
    pkt = build_query(ip)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    return parse_answer(data)
