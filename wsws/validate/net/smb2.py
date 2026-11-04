"""Cliente SMB2 mínimo (dialecto 2.1) para hablar con un named pipe RPC — solo librería estándar.

Hace lo justo para: negociar 2.1, autenticar con NTLMv2, conectar a IPC$, abrir un pipe (p. ej.
`spoolss`) y transceiver PDUs DCERPC vía FSCTL_PIPE_TRANSCEIVE, con firma SMB2 (HMAC-SHA256) cuando
el servidor la exige. Se fija en 2.1 a propósito para evitar la criptografía de SMB3. Es un cliente de
red, no una herramienta de explotación. Implementado según MS-SMB2/MS-NLMP.
"""
import hashlib
import hmac
import os
import socket
import struct

from . import ntlm

# comandos
NEGOTIATE = 0x0000
SESSION_SETUP = 0x0001
LOGOFF = 0x0002
TREE_CONNECT = 0x0003
TREE_DISCONNECT = 0x0004
CREATE = 0x0005
CLOSE = 0x0006
IOCTL = 0x000B

FLAGS_SIGNED = 0x00000008
STATUS_SUCCESS = 0x00000000
STATUS_MORE_PROCESSING = 0xC0000016
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_LOGON_FAILURE = 0xC000006D
SIGNING_ENABLED = 0x01
SIGNING_REQUIRED = 0x02
FSCTL_PIPE_TRANSCEIVE = 0x0011C017
DIALECT_210 = 0x0210


class SMB2Error(Exception):
    def __init__(self, msg, status=None):
        super().__init__(msg)
        self.status = status


def _nbss(payload):
    return struct.pack(">I", len(payload) & 0xFFFFFF) + payload


class SMB2Client:
    def __init__(self, host, port=445, timeout=5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.mid = 0
        self.session_id = 0
        self.tree_id = 0
        self.signing_key = None
        self.require_signing = False

    # --- conexión / framing ---------------------------------------------------
    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *a):
        self.close()

    def _header(self, command):
        self.mid += 1
        return struct.pack("<4sHHIHHIIQIIQ16s",
                           b"\xfeSMB", 64, 1, 0, command, 1, 0, 0,
                           self.mid, 0, self.tree_id, self.session_id, b"\x00" * 16)

    def _sign(self, msg):
        m = bytearray(msg)
        m[16:20] = struct.pack("<I", struct.unpack("<I", m[16:20])[0] | FLAGS_SIGNED)
        m[48:64] = b"\x00" * 16
        sig = hmac.new(self.signing_key, bytes(m), hashlib.sha256).digest()[:16]
        m[48:64] = sig
        return bytes(m)

    def _send(self, msg):
        if self.signing_key and self.session_id:
            msg = self._sign(msg)
        self.sock.sendall(_nbss(msg))

    def _recv(self):
        hdr = self._recv_exact(4)
        length = struct.unpack(">I", hdr)[0] & 0xFFFFFF
        data = self._recv_exact(length)
        status = struct.unpack("<I", data[8:12])[0]
        return status, data

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise SMB2Error("conexión cerrada por el servidor")
            buf += chunk
        return buf

    # --- operaciones ----------------------------------------------------------
    def negotiate(self):
        # StructureSize, DialectCount, SecurityMode, Reserved, Capabilities, ClientGuid, ClientStartTime
        body = (struct.pack("<HHHHI16sQ", 36, 1, SIGNING_ENABLED, 0, 0, os.urandom(16), 0)
                + struct.pack("<H", DIALECT_210))   # un dialecto: 2.1
        self._send(self._header(NEGOTIATE) + body)
        status, resp = self._recv()
        if status != STATUS_SUCCESS:
            raise SMB2Error(f"negotiate falló: 0x{status:08X}", status)
        sec_mode = struct.unpack("<H", resp[64 + 2:64 + 4])[0]
        self.require_signing = bool(sec_mode & SIGNING_REQUIRED)

    def session_setup(self, domain, user, secret, is_hash=False, workstation="WSWS"):
        # paso 1: NTLM type1
        t1 = ntlm.make_type1()
        body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(t1), 0) + t1
        self._send(self._header(SESSION_SETUP) + body)
        status, resp = self._recv()
        self.session_id = struct.unpack("<Q", resp[40:48])[0]
        if status != STATUS_MORE_PROCESSING:
            raise SMB2Error(f"session setup (type1) inesperado: 0x{status:08X}", status)
        off, ln = struct.unpack("<HH", resp[64 + 4:64 + 8])
        type2 = resp[off:off + ln]
        server_challenge, target_info = ntlm.parse_type2(type2)

        # paso 2: NTLM type3 (firma con la clave derivada)
        nt_resp, session_key = ntlm.compute_ntlmv2(user, domain, secret, is_hash,
                                                   server_challenge, target_info)
        t3 = ntlm.make_type3(user, domain, workstation, nt_resp, session_key, ntlm.TYPE1_FLAGS)
        self.signing_key = session_key
        body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(t3), 0) + t3
        self._send(self._header(SESSION_SETUP) + body)
        status, resp = self._recv()
        if status != STATUS_SUCCESS:
            name = {STATUS_LOGON_FAILURE: "credenciales inválidas",
                    STATUS_ACCESS_DENIED: "acceso denegado"}.get(status, f"0x{status:08X}")
            raise SMB2Error(f"autenticación fallida: {name}", status)

    def tree_connect(self, share):
        path = f"\\\\{self.host}\\{share}".encode("utf-16-le")
        body = struct.pack("<HHHH", 9, 0, 64 + 8, len(path)) + path
        self._send(self._header(TREE_CONNECT) + body)
        status, resp = self._recv()
        if status != STATUS_SUCCESS:
            raise SMB2Error(f"tree connect a {share} falló: 0x{status:08X}", status)
        self.tree_id = struct.unpack("<I", resp[36:40])[0]

    def create_pipe(self, name):
        nm = name.encode("utf-16-le")
        name_off = 64 + 56
        body = struct.pack("<HBBIQQIIIIIHHII",
                           57, 0, 0, 2, 0, 0,
                           0x0012019F,       # DesiredAccess (read/write/…)
                           0,                # FileAttributes
                           7,                # ShareAccess RWD
                           1,                # CreateDisposition OPEN
                           0,                # CreateOptions
                           name_off, len(nm), 0, 0) + nm
        self._send(self._header(CREATE) + body)
        status, resp = self._recv()
        if status != STATUS_SUCCESS:
            raise SMB2Error(f"no se pudo abrir el pipe {name}: 0x{status:08X}", status)
        return resp[64 + 64:64 + 80]   # FileId (16 bytes)

    def ioctl_transceive(self, file_id, data):
        in_off = 64 + 56
        body = struct.pack("<HHI16sIIIIIIII",
                           57, 0, FSCTL_PIPE_TRANSCEIVE, file_id,
                           in_off, len(data), 0, 0, 0, 1024, 1, 0) + data
        self._send(self._header(IOCTL) + body)
        status, resp = self._recv()
        if status not in (STATUS_SUCCESS, 0x0103):   # 0x0103 = STATUS_PENDING-ish / buffer overflow tolerado abajo
            # STATUS_BUFFER_OVERFLOW (0x80000005) aún trae datos
            if status != 0x80000005:
                raise SMB2Error(f"ioctl falló: 0x{status:08X}", status)
        out_off, out_cnt = struct.unpack("<II", resp[64 + 24:64 + 32])
        return resp[out_off:out_off + out_cnt]
