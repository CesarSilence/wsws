"""EternalBlue (CVE-2017-0144) — evaluación pasiva sobre el Recon guardado.

Diferencia detectar SMB de confirmar la vulnerabilidad. No declara VULNERABLE por un puerto abierto ni
por una versión antigua: solo cuando el propio Recon ya trae una comprobación positiva (NSE
`smb-vuln-ms17-010` con State: VULNERABLE, que WSWS guarda como hallazgo). SMBv1 habilitado en una
familia afectada eleva a LIKELY. La confirmación activa queda como punto de extensión (probe()).
"""
import re

from .. import osfp
from ..base import (ERROR, INCONCLUSIVE, LIKELY_VULNERABLE, NOT_APPLICABLE, NOT_VULNERABLE, VULNERABLE,
                    Evidence, Validator)

SMBV1_ON = re.compile(r"smb\s*v?1[\s:=]+(true|enabled|yes|on)", re.I)
SMBV1_OFF = re.compile(r"smb\s*v?1[\s:=]+(false|disabled|no|off)", re.I)


class EternalBlueValidator(Validator):
    id = "eternalblue"
    cve = "CVE-2017-0144"
    title = "EternalBlue (MS17-010)"
    ports = (445, 139)
    aliases = ("ms17", "ms17-010", "eb")
    limitations = (
        "pasivo: confirma solo si el Recon ya corrió una comprobación MS17-010; no sondea la red",
        "un puerto SMB abierto no implica vulnerabilidad; la versión del SO es un indicio, no una prueba",
    )

    def evaluate_passive(self, asset):
        svc = asset.service_on(*self.ports)
        if not svc:
            return self.result(asset, NOT_APPLICABLE, reason="sin SMB (139/445) abierto en el Recon")

        ev = [Evidence("service", f"{svc['port']}/{svc.get('proto', 'tcp')} {svc.get('name') or 'smb'} abierto",
                       source=svc.get("source", ""), observed=svc.get("last_seen", ""))]

        # 1) ¿El Recon ya trae una comprobación MS17-010 positiva? (NSE guardado como hallazgo)
        f = asset.finding_ref("ms17-010") or asset.finding_ref("ms17_010")
        if f:
            ev.append(Evidence("finding", f.get("title") or f.get("ref"),
                               source=f.get("source", ""), observed=f.get("last_seen", "")))
            return self.result(asset, VULNERABLE, evidence=ev,
                               reason="el Recon ya contiene una comprobación MS17-010 positiva")

        osn = osfp.summary(asset, *self.ports)
        smbv1_on = bool(asset.finding_ref("smbv1")) or bool(SMBV1_ON.search(osn))
        smbv1_off = bool(SMBV1_OFF.search(osn))

        # 2) SMBv1 habilitado + familia afectada -> posible (vector presente, sin confirmar)
        if smbv1_on and (osfp.is_win7_era(osn) or osfp.is_win8_era(osn)):
            ev.append(Evidence("finding", "SMBv1 habilitado en familia Windows afectada", observed=asset.last_seen))
            return self.result(asset, LIKELY_VULNERABLE, evidence=ev,
                               reason="SMBv1 activo sobre un SO de la familia afectada; falta confirmación activa",
                               limitations=["podría estar parchado (MS17-010) aunque SMBv1 siga activo"])

        # 3) SMBv1 explícitamente deshabilitado -> vector no expuesto
        if smbv1_off and not smbv1_on:
            return self.result(asset, NOT_VULNERABLE, evidence=ev,
                               reason="SMBv1 deshabilitado: el vector de EternalBlue no está expuesto")

        # 4) SO moderno sin señales de SMBv1 -> fuera de la familia habitual (indicio, no prueba)
        if osfp.is_modern(osn) and not smbv1_on:
            return self.result(asset, NOT_APPLICABLE, evidence=ev,
                               reason="SO moderno sin SMBv1 observado; fuera de la familia afectada (por fingerprint)",
                               limitations=["basado en fingerprint de SO; un re-enum con smb-protocols lo confirmaría"])

        # 5) SMB abierto pero sin datos suficientes
        return self.result(asset, INCONCLUSIVE, evidence=ev,
                           reason="SMB abierto pero sin versión de SMB ni comprobación MS17-010 en el Recon",
                           limitations=["re-enumerar o correr la sonda activa: `wsws check ms17 <ip>`"])

    def probe(self, asset, ctx=None):
        """Sonda nativa de solo lectura: detección MS17-010 por SMB1 (PeekNamedPipe en IPC$)."""
        from ..net import smb1
        timeout = float((ctx or {}).get("timeout", 5.0))
        port = 445 if 445 in asset.ports() else (139 if 139 in asset.ports() else 445)
        r = smb1.check_ms17_010(asset.addr, port, timeout)
        nt = r.get("nt")
        ntx = f" (NT_STATUS 0x{nt:08X})" if nt is not None else ""
        ev = [Evidence("probe", f"SMB1 PeekNamedPipe en IPC$ ({asset.addr}:{port}): {r['detail']}{ntx}",
                       source="wsws-probe")]
        status = {"vuln": VULNERABLE, "no": NOT_VULNERABLE,
                  "inconclusive": INCONCLUSIVE, "error": ERROR}.get(r["status"], INCONCLUSIVE)
        reasons = {VULNERABLE: "la sonda SMB1 obtuvo el patrón de respuesta de MS17-010",
                   NOT_VULNERABLE: "la sonda SMB1 indica un sistema parcheado para MS17-010",
                   INCONCLUSIVE: "la sonda SMB1 no fue concluyente",
                   ERROR: "no se pudo completar la sonda SMB1"}
        res = self.result(asset, status, reason=reasons[status], evidence=ev, method="native-probe",
                          limitations=["detección de solo lectura; no prueba DoublePulsar ni ejecuta explotación"])
        if r["status"] == "error":
            res.error = r["detail"]
        return res
