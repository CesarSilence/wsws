"""Tests del motor nativo de validación de vulnerabilidades (evaluación pasiva sobre el Recon).

    python3 -m unittest tests/test_validate.py

Cubre los casos pedidos en la especificación §12: sin servicio, servicio sin datos, evidencia de posible
vulnerabilidad, evidencia suficiente, respuesta/Recon incompleto, Recon desactualizado, error y
resultado que no debe confundir inconcluso con negativo.
"""
import os
import tempfile
import unittest

os.environ.setdefault("WSWS_HOME", tempfile.mkdtemp(prefix="wsws-vtest-"))

from wsws import validate  # noqa: E402
from wsws.validate import engine as vengine  # noqa: E402
from wsws.store import Store  # noqa: E402

_N = 0


def fresh():
    global _N
    _N += 1
    return Store(f"vtest{_N}")


def mkhost(st, addr, os_="", domain="", services=(), findings=(), creds=()):
    eid = st.ev_start("fixture", "test")
    hid, _ = st.host(addr, os=os_, domain=domain, ev=eid)
    for s in services:
        port = s["port"]
        st.service(hid, port, proto=s.get("proto", "tcp"), state=s.get("state", "open"),
                   name=s.get("name", ""), product=s.get("product", ""), version=s.get("version", ""),
                   banner=s.get("banner", ""), ev=eid)
    for f in findings:
        st.finding(hid, f.get("port", 0), source=f.get("source", "nmap"), ref=f.get("ref", ""),
                   title=f.get("title", ""), severity=f.get("severity", "high"), ev=eid)
    for c in creds:
        st.cred(hid, domain=c.get("domain", ""), username=c["username"], secret=c.get("secret", "x"),
                admin=c.get("admin", 0), valid=c.get("valid", 1), ev=eid)
    st.db.commit()
    return hid


def ev(st, check, addr):
    return vengine.evaluate(st, validate.get(check), addr)


class EternalBlue(unittest.TestCase):
    def test_no_service(self):
        st = fresh(); mkhost(st, "10.0.0.1", services=[{"port": 80, "name": "http"}])
        self.assertEqual(ev(st, "eternalblue", "10.0.0.1").status, validate.NOT_APPLICABLE)

    def test_smb_no_info(self):
        st = fresh(); mkhost(st, "10.0.0.2", services=[{"port": 445, "name": "microsoft-ds"}])
        self.assertEqual(ev(st, "eternalblue", "10.0.0.2").status, validate.INCONCLUSIVE)

    def test_likely_smbv1_win7(self):
        st = fresh()
        mkhost(st, "10.0.0.3", os_="Microsoft Windows 7 SP1",
               services=[{"port": 445, "name": "microsoft-ds"}],
               findings=[{"port": 445, "ref": "smbv1-enabled", "title": "SMBv1 habilitado"}])
        r = ev(st, "eternalblue", "10.0.0.3")
        self.assertEqual(r.status, validate.LIKELY_VULNERABLE)
        self.assertTrue(r.evidence and r.reason)

    def test_vulnerable_prior_nse(self):
        st = fresh()
        mkhost(st, "10.0.0.4", os_="Windows 7",
               services=[{"port": 445, "name": "microsoft-ds"}],
               findings=[{"port": 445, "source": "nmap", "ref": "smb-vuln-ms17-010",
                          "title": "MS17-010 Remote Code Execution", "severity": "critical"}])
        self.assertEqual(ev(st, "eternalblue", "10.0.0.4").status, validate.VULNERABLE)

    def test_not_vulnerable_smbv1_off(self):
        st = fresh()
        mkhost(st, "10.0.0.5", os_="Windows Server 2019",
               services=[{"port": 445, "name": "microsoft-ds", "banner": "smb-protocols: SMBv1:False SMB2:True"}])
        self.assertEqual(ev(st, "eternalblue", "10.0.0.5").status, validate.NOT_VULNERABLE)

    def test_modern_na(self):
        st = fresh()
        mkhost(st, "10.0.0.6", os_="Microsoft Windows Server 2022",
               services=[{"port": 445, "name": "microsoft-ds"}])
        self.assertEqual(ev(st, "eternalblue", "10.0.0.6").status, validate.NOT_APPLICABLE)


class DoublePulsar(unittest.TestCase):
    def test_passive_inconclusive(self):
        st = fresh(); mkhost(st, "10.0.1.1", services=[{"port": 445, "name": "microsoft-ds"}])
        r = ev(st, "doublepulsar", "10.0.1.1")
        self.assertEqual(r.status, validate.INCONCLUSIVE)  # ausencia != negativo
        self.assertTrue(any("ausencia" in l.lower() for l in r.limitations))

    def test_indicator_likely(self):
        st = fresh()
        mkhost(st, "10.0.1.2", services=[{"port": 445}],
               findings=[{"port": 445, "ref": "smb-double-pulsar-backdoor", "title": "DoublePulsar backdoor"}])
        self.assertEqual(ev(st, "doublepulsar", "10.0.1.2").status, validate.LIKELY_VULNERABLE)


class BlueKeep(unittest.TestCase):
    def test_no_rdp(self):
        st = fresh(); mkhost(st, "10.0.2.1", services=[{"port": 445}])
        self.assertEqual(ev(st, "bluekeep", "10.0.2.1").status, validate.NOT_APPLICABLE)

    def test_affected_family_likely(self):
        st = fresh()
        mkhost(st, "10.0.2.2", os_="Windows Server 2008 R2", services=[{"port": 3389, "name": "ms-wbt-server"}])
        self.assertEqual(ev(st, "bluekeep", "10.0.2.2").status, validate.LIKELY_VULNERABLE)

    def test_modern_na(self):
        st = fresh()
        mkhost(st, "10.0.2.3", os_="Windows 10", services=[{"port": 3389, "name": "ms-wbt-server"}])
        self.assertEqual(ev(st, "bluekeep", "10.0.2.3").status, validate.NOT_APPLICABLE)

    def test_rdp_unknown_os(self):
        st = fresh(); mkhost(st, "10.0.2.4", services=[{"port": 3389, "name": "ms-wbt-server"}])
        self.assertEqual(ev(st, "bluekeep", "10.0.2.4").status, validate.INCONCLUSIVE)


class PrintNightmare(unittest.TestCase):
    def test_non_windows_na(self):
        st = fresh()
        mkhost(st, "10.0.3.1", os_="Linux 5.4", services=[{"port": 445, "name": "netbios-ssn"}])
        self.assertEqual(ev(st, "printnightmare", "10.0.3.1").status, validate.NOT_APPLICABLE)

    def test_windows_inconclusive_needs_probe(self):
        st = fresh()
        mkhost(st, "10.0.3.2", os_="Windows Server 2019", services=[{"port": 445, "name": "microsoft-ds"}])
        r = ev(st, "printnightmare", "10.0.3.2")
        self.assertEqual(r.status, validate.INCONCLUSIVE)
        self.assertTrue(any("rpc" in l.lower() for l in r.limitations))

    def test_admin_cred_caveat(self):
        st = fresh()
        mkhost(st, "10.0.3.3", os_="Windows 10", domain="corp.local",
               services=[{"port": 445, "name": "microsoft-ds"}],
               creds=[{"domain": "corp.local", "username": "adm", "admin": 1, "valid": 1}])
        r = ev(st, "printnightmare", "10.0.3.3")
        self.assertTrue(any("administrador" in l.lower() for l in r.limitations))


class EngineAndStore(unittest.TestCase):
    def test_error_host_absent(self):
        st = fresh()
        r = vengine.evaluate(st, validate.get("eternalblue"), "10.9.9.9")
        self.assertEqual(r.status, validate.ERROR)

    def test_stale_recon_limitation(self):
        st = fresh()
        hid = mkhost(st, "10.0.4.1", os_="Windows 7",
                     services=[{"port": 445}],
                     findings=[{"port": 445, "ref": "smbv1-enabled", "title": "SMBv1"}])
        st.db.execute("UPDATE services SET last_seen='2000-01-01T00:00:00Z' WHERE host_id=?", (hid,))
        st.db.commit()
        r = ev(st, "eternalblue", "10.0.4.1")
        self.assertTrue(any("desactualizado" in l.lower() for l in r.limitations))

    def test_record_persists_and_tags(self):
        st = fresh()
        mkhost(st, "10.0.4.2", os_="Windows 7",
               services=[{"port": 445}],
               findings=[{"port": 445, "source": "nmap", "ref": "smb-vuln-ms17-010",
                          "title": "MS17-010", "severity": "critical"}])
        eid = st.ev_start("check", "validate-eternalblue")
        r = ev(st, "eternalblue", "10.0.4.2")
        vengine.record(st, r, eid)
        # fila en validations
        v = st.one("SELECT * FROM validations WHERE check_id='eternalblue'")
        self.assertEqual(v["status"], validate.VULNERABLE)
        # hallazgo validado con fuente wsws-validate
        f = st.one("SELECT * FROM findings WHERE source='wsws-validate'")
        self.assertIsNotNone(f)
        self.assertEqual(f["sev"], 4)
        # etiqueta del host
        h = st.find_host("10.0.4.2")
        self.assertIn("eternalblue:vulnerable", h["tags"])

    def test_no_self_feedback_loop(self):
        # un resultado "probable" (wsws-validate) NO debe reinterpretarse luego como positivo externo
        st = fresh()
        mkhost(st, "10.0.4.9", os_="Windows Server 2008 R2", services=[{"port": 3389, "name": "ms-wbt-server"}])
        eid = st.ev_start("check", "validate-bluekeep")
        r1 = ev(st, "bluekeep", "10.0.4.9")
        self.assertEqual(r1.status, validate.LIKELY_VULNERABLE)
        vengine.record(st, r1, eid)               # escribe el hallazgo "probable" wsws-validate
        r2 = ev(st, "bluekeep", "10.0.4.9")       # segunda corrida: debe seguir siendo probable, no vulnerable
        self.assertEqual(r2.status, validate.LIKELY_VULNERABLE)

    def test_record_inconclusive_no_finding(self):
        st = fresh()
        mkhost(st, "10.0.4.3", services=[{"port": 445}])
        eid = st.ev_start("check", "validate-eternalblue")
        vengine.record(st, ev(st, "eternalblue", "10.0.4.3"), eid)
        self.assertIsNone(st.one("SELECT * FROM findings WHERE source='wsws-validate'"))
        self.assertEqual(st.one("SELECT status FROM validations")["status"], validate.INCONCLUSIVE)


class SMB1Probe(unittest.TestCase):
    def test_packets_framing(self):
        from wsws.validate.net import smb1
        for pkt in (smb1.build_negotiate(), smb1.build_session_setup(),
                    smb1.build_tree_connect("10.0.0.1", 2048), smb1.build_trans_peek(2048, 3)):
            # NBSS: byte 0 = 0x00, longitud coherente, y el SMB empieza con \xffSMB
            self.assertEqual(pkt[0], 0x00)
            import struct
            self.assertEqual(struct.unpack(">I", pkt[:4])[0], len(pkt) - 4)
            self.assertEqual(pkt[4:8], b"\xffSMB")

    def test_parse_status_and_interpret(self):
        from wsws.validate.net import smb1
        # arma un header SMB con un NT_STATUS dado y verifica el parseo
        def resp(nt):
            import struct
            return b"\xffSMB" + b"\x25" + struct.pack("<I", nt) + b"\x00" * 30
        self.assertEqual(smb1.parse_status(resp(0xC0000205)), 0xC0000205)
        self.assertEqual(smb1.interpret(0xC0000205)["status"], "vuln")
        self.assertEqual(smb1.interpret(0xC0000008)["status"], "no")
        self.assertEqual(smb1.interpret(0x00000000)["status"], "inconclusive")
        self.assertIsNone(smb1.parse_status(b"short"))


class ActiveEngine(unittest.TestCase):
    def _patch(self, result):
        from wsws.validate.net import smb1
        orig = smb1.check_ms17_010
        smb1.check_ms17_010 = lambda host, port=445, timeout=5.0: result
        self.addCleanup(lambda: setattr(smb1, "check_ms17_010", orig))

    def test_probe_vulnerable(self):
        self._patch({"status": "vuln", "detail": "patrón MS17-010", "nt": 0xC0000205})
        st = fresh(); mkhost(st, "10.1.0.1", services=[{"port": 445}])
        r = vengine.evaluate(st, validate.get("eternalblue"), "10.1.0.1", active=True)
        self.assertEqual(r.status, validate.VULNERABLE)
        self.assertEqual(r.method, "native-probe")

    def test_probe_patched(self):
        self._patch({"status": "no", "detail": "parcheado", "nt": 0xC0000008})
        st = fresh(); mkhost(st, "10.1.0.2", services=[{"port": 445}])
        r = vengine.evaluate(st, validate.get("eternalblue"), "10.1.0.2", active=True)
        self.assertEqual(r.status, validate.NOT_VULNERABLE)

    def test_probe_error_falls_back_to_passive(self):
        self._patch({"status": "error", "detail": "timeout", "nt": None})
        st = fresh()
        mkhost(st, "10.1.0.3", os_="Windows 7", services=[{"port": 445}],
               findings=[{"port": 445, "ref": "smbv1-enabled", "title": "SMBv1"}])
        r = vengine.evaluate(st, validate.get("eternalblue"), "10.1.0.3", active=True)
        # cae a pasivo (LIKELY por SMBv1+Win7) y anota el fallo de la sonda
        self.assertEqual(r.status, validate.LIKELY_VULNERABLE)
        self.assertTrue(any("sonda activa falló" in l for l in r.limitations))

    def test_passive_only_ignores_probe(self):
        self._patch({"status": "vuln", "detail": "no debería usarse", "nt": 0xC0000205})
        st = fresh(); mkhost(st, "10.1.0.4", services=[{"port": 445}])
        r = vengine.evaluate(st, validate.get("eternalblue"), "10.1.0.4", active=False)
        self.assertEqual(r.method, "passive")

    def test_has_probe(self):
        # eternalblue (SMB1), bluekeep (RDP) y printnightmare (RPC) tienen sonda; doublepulsar no (decisión)
        self.assertTrue(vengine.has_probe(validate.get("eternalblue")))
        self.assertTrue(vengine.has_probe(validate.get("bluekeep")))
        self.assertTrue(vengine.has_probe(validate.get("printnightmare")))
        self.assertFalse(vengine.has_probe(validate.get("doublepulsar")))


class NetModules(unittest.TestCase):
    def test_ntlm_vectors(self):
        from wsws.validate.net import ntlm
        self.assertEqual(ntlm.md4(b"").hex(), "31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertEqual(ntlm.md4(b"abc").hex(), "a448017aaf21d8525fc10ae87aa6729d")
        # vector MS-NLMP 4.2.4.2
        v = ntlm.ntowfv2(ntlm.nt_hash("Password"), "User", "Domain").hex()
        self.assertEqual(v, "0c868a403bfd7a93a3001ef22ef02e3f")

    def test_ntlm_type3_roundtrip(self):
        from wsws.validate.net import ntlm
        import os
        chal = os.urandom(8)
        ti = b"\x00\x00\x00\x00"
        nt, key = ntlm.compute_ntlmv2("u", "d", "pw", False, chal, ti)
        self.assertEqual(len(key), 16)
        t3 = ntlm.make_type3("u", "d", "WS", nt, key, ntlm.TYPE1_FLAGS)
        self.assertTrue(t3.startswith(b"NTLMSSP\x00"))

    def test_dcerpc_uuid_and_pdus(self):
        from wsws.validate.net import dcerpc
        b = dcerpc.uuid_to_bin("12345678-1234-abcd-ef00-0123456789ab", 1, 0)
        self.assertEqual(b.hex(), "78563412" "3412" "cdab" "ef000123456789ab" + "01000000")
        self.assertEqual(dcerpc.build_bind("12345678-1234-abcd-ef00-0123456789ab", 1)[2], dcerpc.PT_BIND)
        self.assertEqual(dcerpc.build_request(89, b"\x00" * 4)[2], dcerpc.PT_REQUEST)

    def test_dcerpc_parse(self):
        import struct
        from wsws.validate.net import dcerpc
        resp = dcerpc._header(dcerpc.PT_RESPONSE, 28, 1) + struct.pack("<IBBH", 4, 0, 0, 0) + struct.pack("<I", 0x57)
        p = dcerpc.parse(resp)
        self.assertEqual(p["ptype"], dcerpc.PT_RESPONSE)
        self.assertEqual(p["ret"], 0x57)
        fault = dcerpc._header(dcerpc.PT_FAULT, 32, 1) + b"\x00" * 8 + struct.pack("<I", 5)
        self.assertEqual(dcerpc.parse(fault)["fault"], 5)

    def test_rdp_cr(self):
        from wsws.validate.net import rdp
        cr = rdp._connection_request()
        self.assertEqual(cr[0], 3)          # TPKT version
        self.assertIn(b"\x01\x00\x08\x00", cr)   # rdpNegReq type 1, length 8

    def test_smb2_header(self):
        from wsws.validate.net.smb2 import SMB2Client
        c = SMB2Client("1.2.3.4")
        h = c._header(0)
        self.assertEqual(len(h), 64)
        self.assertEqual(h[:4], b"\xfeSMB")

    def test_pn_stub(self):
        from wsws.validate.validators.printnightmare import PrintNightmareChecker, APD_FLAGS
        import struct
        stub = PrintNightmareChecker._stub()
        self.assertEqual(len(stub), 40)
        vals = struct.unpack("<IIIIIIIIII", stub)
        self.assertEqual(vals[0], 0)            # pName NULL
        self.assertEqual(vals[1], 2)            # Level 2
        self.assertEqual(vals[-1], APD_FLAGS)   # dwFileCopyFlags


class ActivePrintNightmare(unittest.TestCase):
    class FakeSMB2:
        def __init__(self, *a, **k):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def negotiate(self): pass
        def session_setup(self, *a, **k): pass
        def tree_connect(self, *a): pass
        def create_pipe(self, *a):
            return b"\x00" * 16
        def ioctl_transceive(self, *a):
            return b"RESP"

    def setUp(self):
        from wsws.validate.net import smb2
        self._orig_client = smb2.SMB2Client
        self.addCleanup(lambda: setattr(smb2, "SMB2Client", self._orig_client))

    def _patch(self, parsed):
        from wsws.validate.net import smb2, dcerpc
        smb2.SMB2Client = self.FakeSMB2
        orig = dcerpc.parse
        dcerpc.parse = lambda pdu: parsed
        self.addCleanup(lambda: setattr(dcerpc, "parse", orig))

    def test_no_creds_inconclusive(self):
        st = fresh(); mkhost(st, "10.2.0.1", os_="Windows", services=[{"port": 445}])
        a = vengine.build_asset(st, "10.2.0.1")
        r = validate.get("printnightmare").probe(a, ctx={})
        self.assertEqual(r.status, validate.INCONCLUSIVE)

    def test_admin_cred_inconclusive(self):
        st = fresh()
        mkhost(st, "10.2.0.2", os_="Windows", services=[{"port": 445}],
               creds=[{"username": "a", "admin": 1, "valid": 1}])
        a = vengine.build_asset(st, "10.2.0.2")
        r = validate.get("printnightmare").probe(a, ctx={"creds": (".", "a", "x")})
        self.assertEqual(r.status, validate.INCONCLUSIVE)
        self.assertTrue(any("administrador" in l.lower() for l in r.limitations))

    def test_vulnerable(self):
        from wsws.validate.net import dcerpc
        self._patch({"ptype": dcerpc.PT_RESPONSE, "ret": 0x57})
        st = fresh(); mkhost(st, "10.2.0.3", os_="Windows", services=[{"port": 445}])
        a = vengine.build_asset(st, "10.2.0.3")
        r = validate.get("printnightmare").probe(a, ctx={"creds": (".", "u", "pw")})
        self.assertEqual(r.status, validate.LIKELY_VULNERABLE)

    def test_patched(self):
        from wsws.validate.net import dcerpc
        self._patch({"ptype": dcerpc.PT_RESPONSE, "ret": 0x05})
        st = fresh(); mkhost(st, "10.2.0.4", os_="Windows", services=[{"port": 445}])
        a = vengine.build_asset(st, "10.2.0.4")
        r = validate.get("printnightmare").probe(a, ctx={"creds": (".", "u", "pw")})
        self.assertEqual(r.status, validate.NOT_VULNERABLE)

    def test_logon_failure_inconclusive(self):
        from wsws.validate.net import smb2
        class Boom(self.FakeSMB2):
            def session_setup(self, *a, **k):
                raise smb2.SMB2Error("cred inválida", status=0xC000006D)
        smb2.SMB2Client = Boom   # restaurado por setUp/addCleanup
        st = fresh(); mkhost(st, "10.2.0.5", os_="Windows", services=[{"port": 445}])
        a = vengine.build_asset(st, "10.2.0.5")
        r = validate.get("printnightmare").probe(a, ctx={"creds": (".", "u", "bad")})
        self.assertEqual(r.status, validate.INCONCLUSIVE)


class ActiveBlueKeep(unittest.TestCase):
    def _patch(self, result):
        from wsws.validate.net import rdp
        orig = rdp.probe_security
        rdp.probe_security = lambda host, port=3389, timeout=5.0: result
        self.addCleanup(lambda: setattr(rdp, "probe_security", orig))

    def test_affected_no_nla_likely(self):
        self._patch({"status": "ok", "nla": False, "selected": 0, "detail": "RDP"})
        st = fresh(); mkhost(st, "10.3.0.1", os_="Windows 7", services=[{"port": 3389}])
        a = vengine.build_asset(st, "10.3.0.1")
        r = validate.get("bluekeep").probe(a)
        self.assertEqual(r.status, validate.LIKELY_VULNERABLE)
        self.assertTrue(any("BSOD" in l or "solo lectura" in l for l in r.limitations))

    def test_modern_na(self):
        self._patch({"status": "ok", "nla": True, "selected": 2, "detail": "NLA"})
        st = fresh(); mkhost(st, "10.3.0.2", os_="Windows 10", services=[{"port": 3389}])
        a = vengine.build_asset(st, "10.3.0.2")
        self.assertEqual(validate.get("bluekeep").probe(a).status, validate.NOT_APPLICABLE)

    def test_error_status(self):
        self._patch({"status": "error", "nla": None, "selected": None, "detail": "timeout"})
        st = fresh(); mkhost(st, "10.3.0.3", os_="Windows 7", services=[{"port": 3389}])
        a = vengine.build_asset(st, "10.3.0.3")
        self.assertEqual(validate.get("bluekeep").probe(a).status, validate.ERROR)


class DnsClient(unittest.TestCase):
    def test_build_query(self):
        from wsws.validate.net import dnsc
        import struct
        q = dnsc.build_query("10.1.2.3", tid=0x1234)
        self.assertEqual(q[:2], b"\x12\x34")
        self.assertEqual(struct.unpack(">H", q[4:6])[0], 1)   # qdcount
        self.assertIn(b"in-addr", q)
        self.assertIn(b"arpa", q)
        self.assertEqual(q[-4:], struct.pack(">HH", 12, 1))   # PTR / IN

    def test_parse_answer(self):
        from wsws.validate.net import dnsc
        import struct
        # respuesta DNS armada a mano: 1 pregunta + 1 answer PTR con compresión
        tid = b"\xab\xcd"
        header = tid + b"\x81\x80" + struct.pack(">HHHH", 1, 1, 0, 0)
        qname = b"\x01\x35\x07in-addr\x04arpa\x00"      # "5.in-addr.arpa" (da igual el contenido)
        question = qname + struct.pack(">HH", 12, 1)
        qname_off = len(header)
        ans_name = b"\xc0" + bytes([qname_off])          # puntero a la pregunta
        rdata = b"\x02dc\x04corp\x05local\x00"            # dc.corp.local
        answer = ans_name + struct.pack(">HHIH", 12, 1, 60, len(rdata)) + rdata
        pkt = header + question + answer
        self.assertEqual(dnsc.parse_answer(pkt), "dc.corp.local")

    def test_parse_no_answer(self):
        from wsws.validate.net import dnsc
        import struct
        pkt = b"\xab\xcd\x81\x83" + struct.pack(">HHHH", 1, 0, 0, 0) + b"\x01\x35\x00" + struct.pack(">HH", 12, 1)
        self.assertIsNone(dnsc.parse_answer(pkt))


class ReverseSetting(unittest.TestCase):
    def test_setting_roundtrip(self):
        st = fresh()
        self.assertIsNone(st.setting("reverse_dns_server"))
        st.set_setting("reverse_dns_server", "10.0.0.1")
        st.set_setting("reverse_dns_asked", "1")
        st2 = type(st)(st.name)   # reabrir el mismo workspace
        self.assertEqual(st2.setting("reverse_dns_server"), "10.0.0.1")
        self.assertEqual(st2.setting("reverse_dns_asked"), "1")


class Registry(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(validate.get("ms17").id, "eternalblue")
        self.assertEqual(validate.get("bk").id, "bluekeep")
        self.assertEqual(validate.get("pn").id, "printnightmare")
        self.assertIsNone(validate.get("nope"))

    def test_probe_extension_point_base(self):
        # la clase base define probe() como punto de extensión (INCONCLUSIVE, sin tocar la red)
        from wsws.validate.base import Asset, Validator
        r = Validator().probe(Asset(addr="10.0.5.1"))
        self.assertEqual(r.method, "native-probe")
        self.assertEqual(r.status, validate.INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
