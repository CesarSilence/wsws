"""Tests de extremo a extremo con las salidas de ejemplo de tests/fixtures.

    python3 -m unittest tests/test_wsws.py
"""
import os
import tempfile
import unittest
from pathlib import Path

FIX = Path(__file__).parent / "fixtures"
os.environ["WSWS_HOME"] = tempfile.mkdtemp(prefix="wsws-test-")

from wsws import parsers, query  # noqa: E402
from wsws.store import Store  # noqa: E402


def load(st, name):
    fmt, recs = parsers.parse((FIX / name).read_text())
    st.ingest(recs, st.ev_start(f"import {name}", fmt))
    return fmt


class WswsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.st = Store("test")
        cls.st.scope_set("include", ["10.10.10.0/24", "*.corp.local"])
        cls.fmts = [load(cls.st, f) for f in ("nmap_normal.txt", "nmap.xml", "scan.gnmap", "nxc.txt", "httpx.jsonl",
                                              "nuclei.jsonl", "masscan.txt", "naabu.txt")]

    def find(self, *terms, fn=query.find):
        return fn(self.st, query.parse_terms(terms))

    def test_formats_detected(self):
        self.assertEqual(self.fmts, ["nmap", "nmap-xml", "gnmap", "nxc", "httpx", "nuclei", "masscan", "lista"])

    def test_port_search(self):
        self.assertEqual(sorted({r["addr"] for r in self.find("445")}), ["10.10.10.40", "10.10.10.5", "10.10.10.70"])

    def test_svc_synonyms(self):
        rows = self.find("svc:smb")
        self.assertTrue(rows and {r["name"] for r in rows} <= {"microsoft-ds", "netbios-ssn", "smb", ""})
        self.assertEqual({r["addr"] for r in rows if r["port"] == 445}, {r["addr"] for r in self.find("445")})

    def test_closed_and_down_ignored(self):
        self.assertFalse(self.find("10.10.10.99"))
        self.assertFalse([r for r in self.find("10.10.10.20") if r["port"] == 443])

    def test_hostname_merges_into_ip(self):
        rows = self.st.q("SELECT addr, hostnames FROM hosts WHERE hostnames LIKE '%web01%'")
        self.assertEqual([r["addr"] for r in rows], ["10.10.10.30"])

    def test_free_text_hits_web_and_scripts(self):
        self.assertEqual({r["addr"] for r in self.find("jenkins")}, {"10.10.10.30"})
        self.assertEqual({r["port"] for r in self.find("intranet")}, {80})

    def test_negation_and_net(self):
        self.assertEqual({r["port"] for r in self.find("10.10.10.60/31", "-port:22")}, {3306, 6379})

    def test_findings(self):
        titles = {r["ref"] for r in self.find("sev:high", fn=query.findings)}
        self.assertEqual(titles, {"smb-vuln-ms17-010", "jenkins-script-console", "CVE-2020-1938"})
        self.assertEqual(len(self.find("vuln:smb", fn=query.findings)), 3)

    def test_creds_from_nxc(self):
        creds = {(r["username"], r["admin"], r["valid"]) for r in self.find(fn=query.creds)}
        self.assertEqual(creds, {("svc_backup", 1, 1), ("jperez", 0, 1), ("Administrator", 0, 0)})
        self.assertEqual({r["addr"] for r in self.find("has:admin")}, {"10.10.10.40"})

    def test_cred_domain_not_copied_to_host(self):
        self.assertEqual(self.st.find_host("10.10.10.40")["domain"], "corp.local")

    def test_scope(self):
        self.assertEqual({r["addr"] for r in self.find("scope:out")}, {"172.16.0.9"})
        self.assertTrue(self.st.in_scope("app.corp.local"))
        self.assertFalse(self.st.in_scope("10.10.0.0/16"))

    def test_parse_cred_formats(self):
        P = parsers.parse_cred
        self.assertEqual(P("corp\\jdoe:Pass1"), ("corp", "jdoe", "Pass1", ""))
        self.assertEqual(P("corp.local/jdoe:Pass1@10.0.0.5"), ("corp.local", "jdoe", "Pass1", "10.0.0.5"))
        self.assertEqual(P("jdoe@corp.local:P@ss:w0rd"), ("corp.local", "jdoe", "P@ss:w0rd", ""))
        self.assertEqual(P("corp/jdoe:P@ss"), ("corp", "jdoe", "P@ss", ""))
        self.assertEqual(P("jdoe@corp.local"), ("corp.local", "jdoe", "", ""))

    def test_manual_creds_do_not_duplicate(self):
        st = Store("creds")
        for dom, user, secret, hid in (("corp", "jdoe", "", 0), ("corp", "jdoe", "Pass1", 0),
                                       ("CORP", "JDoe", "Pass1", 0), ("corp", "jdoe", "Pass1", 7),
                                       ("corp", "jdoe", "", 0)):
            st.cred(hid, 0, dom, user, secret, source="manual")
        rows = st.q("SELECT domain, username, secret, host_id FROM creds")
        self.assertEqual([tuple(r) for r in rows], [("corp", "jdoe", "Pass1", 7)])
        # un password distinto del mismo usuario sí es otra credencial
        st.cred(0, 0, "corp", "jdoe", "Pass2", source="manual")
        self.assertEqual(st.one("SELECT COUNT(*) FROM creds")[0], 2)
        # el mismo hash como LM:NT y como NT es uno solo
        st.cred(0, 0, "", "admin", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
        st.cred(0, 0, "", "admin", "31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertEqual(st.one("SELECT COUNT(*) FROM creds WHERE username='admin'")[0], 1)

    def test_dedupe_existing_creds(self):
        st = Store("legacy")
        t = "2026-01-01T00:00:00Z"
        for user, secret in (("overload.cl/user", "password"), ("overload.cl/user", ""), ("overload.cl/USER", "password")):
            st.db.execute("INSERT INTO creds(host_id, domain, username, secret, source, first_seen, last_seen)"
                          " VALUES(0, '', ?, ?, 'manual', ?, ?)", (user, secret, t, t))
        self.assertEqual(st.dedupe_creds(), 2)
        self.assertEqual([tuple(r) for r in st.q("SELECT domain, username, secret FROM creds")],
                         [("overload.cl", "user", "password")])

    def test_domain_alias(self):
        st = Store("alias")
        st.cred(0, 0, "CORP", "jdoe", "Pass1")
        st.cred(5, 0, "corp.local", "jdoe", "Pass1", admin=1)
        st.cred(0, 0, "corp", "svc", "x")
        self.assertEqual(st.alias_add("corp", "corp.local"), 1)
        rows = st.q("SELECT domain, username, admin, host_id FROM creds ORDER BY username")
        self.assertEqual([tuple(r) for r in rows], [("corp.local", "jdoe", 1, 5), ("corp.local", "svc", 0, 0)])
        st.cred(0, 0, "CORP", "jdoe", "Pass1")  # lo nuevo con el alias también se normaliza
        self.assertEqual(st.one("SELECT COUNT(*) FROM creds")[0], 2)

    def test_cred_update_merges_on_collision(self):
        st = Store("credmod")
        a, _ = st.cred(0, 0, "corp", "jdoe", "Pass1", admin=1)
        b, _ = st.cred(0, 0, "corp", "jdoe", "Viejo")
        row, merged = st.cred_update(b, {"secret": "Pass1"})
        self.assertEqual((row["id"], merged, row["admin"]), (b, [a], 1))
        row, _ = st.cred_update(b, {"admin": 0, "username": "jperez"})
        self.assertEqual((row["username"], row["admin"]), ("jperez", 0))
        self.assertEqual(st.one("SELECT COUNT(*) FROM creds")[0], 1)

    def test_help_topics(self):
        from wsws import helptext
        from wsws.cli import help_topic
        self.assertEqual(help_topic("vulns", ["-h"]), "vulns")
        self.assertEqual(help_topic("v", ["sev:high", "--help"]), "v")
        self.assertEqual(help_topic("creds", ["add", "-h"]), "creds add")
        self.assertIsNone(help_topic("creds", ["add", "corp\\u:p"]))
        self.assertIsNone(help_topic("run", ["--", "nmap", "-h"]))  # el -h es de la herramienta
        for name in ("v", "find", "c mod", "creds del", "status", "svc"):
            self.assertIsNotNone(helptext.get(name), name)

    def test_checks_parse_and_record(self):
        from wsws import checks
        xml = """<nmaprun>
          <host><address addr="10.0.0.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="445"><state state="open"/></port></ports>
            <hostscript><script id="smb-vuln-ms17-010" output="VULNERABLE:&#10;  State: VULNERABLE&#10;  IDs: CVE:CVE-2017-0143"/></hostscript></host>
          <host><address addr="10.0.0.6" addrtype="ipv4"/><ports><port protocol="tcp" portid="445"><state state="open"/></port></ports></host>
          <host><address addr="10.0.0.7" addrtype="ipv4"/><ports><port protocol="tcp" portid="445"><state state="filtered"/></port></ports></host>
        </nmaprun>"""
        eb = {(r["check"], r["addr"]): r["status"] for r in checks.parse_eternalblue(xml)}
        self.assertEqual(eb[("eternalblue", "10.0.0.5")], "vuln")
        self.assertEqual(eb[("doublepulsar", "10.0.0.5")], "no")
        self.assertEqual(eb[("eternalblue", "10.0.0.6")], "no")
        self.assertEqual(eb[("eternalblue", "10.0.0.7")], "?")
        bk = checks.parse_rdpscan("10.0.0.8 - VULNERABLE - got appid\n10.0.0.9 - SAFE - Target appears patched\n"
                                  "10.0.0.10 - UNKNOWN - no connection - timeout\n")
        self.assertEqual([r["status"] for r in bk], ["vuln", "no", "?"])
        pn = checks.parse_printnightmare(
            "Executing: python3 printnightmare.py corp/jdoe:'****'@10.0.0.5 -check\nImpacket v0.9.23\n\n"
            "[*] Target appears to be vulnerable!\n\n"
            "Executing: python3 printnightmare.py corp/jdoe:'****'@10.0.0.6 -check\n"
            "[!] Target does not appear to be vulnerable\n"
            "Executing: python3 printnightmare.py corp/jdoe:'****'@10.0.0.7 -check\n[-] SMB SessionError: STATUS_LOGON_FAILURE\n")
        self.assertEqual([(r["addr"], r["status"]) for r in pn],
                         [("10.0.0.5", "vuln"), ("10.0.0.6", "no"), ("10.0.0.7", "?")])
        self.assertIn("LOGON_FAILURE", pn[2]["detail"])
        st = Store("checks")
        for a in ("10.0.0.5", "10.0.0.6", "10.0.0.7"):
            st.ingest([parsers.service(a, 445, name="microsoft-ds")])
        self.assertEqual(checks.targets(st, "eternalblue", [])[0], ["10.0.0.5", "10.0.0.6", "10.0.0.7"])
        checks.record(st, checks.parse_eternalblue(xml), st.ev_start("t", "check"))
        f = st.q("SELECT f.ref, f.sev, h.addr FROM findings f JOIN hosts h ON h.id=f.host_id")
        self.assertEqual([tuple(r) for r in f], [("CVE-2017-0144", 4, "10.0.0.5")])
        self.assertEqual(st.find_host("10.0.0.5")["tags"], "eternalblue:vuln,doublepulsar:no")
        self.assertEqual(st.find_host("10.0.0.7")["tags"], "")
        self.assertEqual({r["addr"] for r in self.find("tag:eternalblue:vuln", fn=lambda s, t: query.find(st, t))},
                         {"10.0.0.5"})

    def test_wrapper_targets(self):
        from wsws.runner import prepare, targets
        self.assertEqual(targets("nmap", ["-sV", "-p", "22", "--exclude", "10.0.0.9", "10.0.0.0/24", "x.corp.local"]),
                         ["10.0.0.0/24", "x.corp.local"])
        self.assertEqual(targets("nxc", ["smb", "10.0.0.5", "-u", "admin", "-p", "Pass.word1"]), ["10.0.0.5"])
        self.assertEqual(targets("nuclei", ["-u", "https://a.corp.local", "-t", "cves/"]), ["a.corp.local"])
        args, files = prepare("nmap", ["-sV", "10.0.0.1"], Path("/tmp"))
        self.assertEqual(args[-2:], ["-oX", "/tmp/nmap.xml"])


if __name__ == "__main__":
    unittest.main()
