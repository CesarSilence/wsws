"""BlueKeep (CVE-2019-0708) — evaluación pasiva sobre el Recon guardado.

No confunde RDP disponible con vulnerabilidad. Usa la familia de SO y las señales de RDP/NLA que el
Recon ya trae. NLA requerido mitiga la explotación no autenticada pero no prueba el parche, así que no
se declara seguro por eso. La comprobación de protocolo RDP (equivalente a rdpscan) queda como punto de
extensión (probe()); no se ejecuta en modo pasivo.
"""
from .. import osfp
from ..base import (ERROR, INCONCLUSIVE, LIKELY_VULNERABLE, NOT_APPLICABLE, NOT_VULNERABLE, VULNERABLE,
                    Evidence, Validator)


class BlueKeepValidator(Validator):
    id = "bluekeep"
    cve = "CVE-2019-0708"
    title = "BlueKeep (CVE-2019-0708)"
    ports = (3389,)
    aliases = ("bk", "cve-2019-0708")
    limitations = (
        "pasivo: no realiza la negociación RDP; se apoya en el fingerprint de SO y señales ya capturadas",
        "RDP accesible no implica vulnerabilidad; el fingerprint de SO es un indicio, no una prueba",
        "NLA requerido mitiga la explotación no autenticada pero no confirma que el host esté parchado",
    )

    def evaluate_passive(self, asset):
        svc = asset.service_on(*self.ports)
        if not svc:
            return self.result(asset, NOT_APPLICABLE, reason="sin RDP (3389) abierto en el Recon")

        ev = [Evidence("service", f"3389/{svc.get('proto', 'tcp')} {svc.get('name') or 'rdp'} abierto",
                       source=svc.get("source", ""), observed=svc.get("last_seen", ""))]

        # 1) ¿El Recon ya trae una comprobación BlueKeep positiva?
        f = asset.finding_ref("cve-2019-0708") or asset.finding_ref("bluekeep")
        if f:
            ev.append(Evidence("finding", f.get("title") or f.get("ref"),
                               source=f.get("source", ""), observed=f.get("last_seen", "")))
            return self.result(asset, VULNERABLE, evidence=ev,
                               reason="el Recon ya contiene una comprobación BlueKeep positiva")

        osn = osfp.summary(asset, *self.ports)
        banner = asset.banner_text(*self.ports).lower()
        nla = "nla" in banner or "credssp" in banner or "network level authentication" in banner

        # 2) SO moderno -> no afectado (por fingerprint)
        if osfp.is_modern(osn) or osfp.is_win8_era(osn):
            return self.result(asset, NOT_APPLICABLE, evidence=ev,
                               reason="SO fuera de la familia afectada por BlueKeep (por fingerprint)",
                               limitations=["basado en fingerprint de SO; BlueKeep afecta a Win7/2008 y anteriores"])

        # 3) SO de la familia afectada + RDP -> posible
        if osfp.is_win7_era(osn):
            ev.append(Evidence("os", f"SO de la familia afectada: {asset.os}", observed=asset.last_seen))
            if nla:
                ev.append(Evidence("service", "NLA/CredSSP requerido", observed=svc.get("last_seen", "")))
                return self.result(asset, LIKELY_VULNERABLE, evidence=ev,
                                   reason="familia afectada con RDP; NLA requerido reduce el riesgo no autenticado",
                                   limitations=["NLA no prueba el parche; podría explotarse con credenciales válidas"])
            return self.result(asset, LIKELY_VULNERABLE, evidence=ev,
                               reason="SO de la familia afectada con RDP expuesto; falta confirmación activa")

        # 4) RDP abierto, SO desconocido
        return self.result(asset, INCONCLUSIVE, evidence=ev,
                           reason="RDP abierto pero sin fingerprint de SO suficiente en el Recon",
                           limitations=["re-enumerar, o sonda activa: `wsws check bluekeep --bluekeep-active`"])

    def probe(self, asset, ctx=None):
        """Sonda RDP de SOLO LECTURA (negociación X.224): detecta NLA/CredSSP, sin tocar MS_T120.

        No es el check que puede tumbar el host: no interactúa con la ruta vulnerable de BlueKeep. Enriquece
        la evaluación con el dato de NLA y la combina con la familia de SO para graduar el resultado.
        """
        from ..net import rdp
        timeout = float((ctx or {}).get("timeout", 5.0))
        r = rdp.probe_security(asset.addr, 3389, timeout)
        if r["status"] == "error":
            res = self.result(asset, ERROR, method="native-probe",
                              reason=f"no se pudo negociar RDP: {r['detail']}")
            res.error = r["detail"]
            return res

        ev = [Evidence("probe", f"negociación RDP X.224: {r['detail']}", source="wsws-probe")]
        osn = osfp.summary(asset, *self.ports)
        nla = r["nla"]
        base_lim = ["sonda de solo lectura: no ejecuta el check que puede provocar BSOD; no confirma el parche"]

        if osfp.is_modern(osn) or osfp.is_win8_era(osn):
            return self.result(asset, NOT_APPLICABLE, method="native-probe", evidence=ev,
                               reason="SO fuera de la familia afectada por BlueKeep (por fingerprint)",
                               limitations=base_lim)
        if osfp.is_win7_era(osn):
            if nla:
                return self.result(asset, LIKELY_VULNERABLE, method="native-probe", evidence=ev,
                                   reason="familia afectada; NLA impuesto mitiga la explotación no autenticada",
                                   limitations=base_lim + ["explotable con credenciales válidas si no está parchado"])
            return self.result(asset, LIKELY_VULNERABLE, method="native-probe", evidence=ev,
                               reason="familia afectada con RDP sin NLA: expuesto a explotación no autenticada",
                               limitations=base_lim)
        # SO desconocido: la sonda aporta el dato de NLA, pero no alcanza para graduar
        note = "NLA impuesto" if nla else ("sin NLA" if nla is False else "NLA no determinado")
        return self.result(asset, INCONCLUSIVE, method="native-probe", evidence=ev,
                           reason=f"RDP accesible ({note}) pero sin fingerprint de SO para concluir",
                           limitations=base_lim)
