"""DoublePulsar — evaluación pasiva de indicadores (decisión: siempre pasivo).

El único indicador de red del implante se obtiene interactuando con él, lo que queda fuera del modo
pasivo por decisión del equipo. Aquí solo se reutiliza un indicador que el Recon ya haya capturado
(NSE `smb-double-pulsar-backdoor`). La ausencia de indicadores NUNCA se interpreta como ausencia del
implante: el implante vive en memoria y desaparece al reiniciar. La sonda activa queda como extensión
(probe()), lista para que un humano la habilite.
"""
from ..base import INCONCLUSIVE, LIKELY_VULNERABLE, NOT_APPLICABLE, Evidence, Validator


class DoublePulsarIndicatorValidator(Validator):
    id = "doublepulsar"
    cve = "DOUBLEPULSAR"
    title = "DoublePulsar (indicador SMB)"
    ports = (445, 139)
    aliases = ("dp", "pulsar")
    limitations = (
        "pasivo por decisión: no envía el ping Trans2 al implante; solo lee indicadores ya capturados",
        "la ausencia de indicadores NO prueba ausencia del implante (vive en memoria, se pierde al reiniciar)",
        "no cubre la variante RDP del implante ni IOC a nivel de host",
    )

    def evaluate_passive(self, asset):
        svc = asset.service_on(*self.ports)
        if not svc:
            return self.result(asset, NOT_APPLICABLE, reason="sin SMB (139/445) abierto en el Recon")

        ev = [Evidence("service", f"{svc['port']}/{svc.get('proto', 'tcp')} SMB abierto",
                       source=svc.get("source", ""), observed=svc.get("last_seen", ""))]

        f = asset.finding_ref("double-pulsar") or asset.finding_ref("doublepulsar") or asset.finding_ref("double_pulsar")
        if f:
            ev.append(Evidence("finding", f.get("title") or f.get("ref"),
                               source=f.get("source", ""), observed=f.get("last_seen", "")))
            return self.result(asset, LIKELY_VULNERABLE, evidence=ev,
                               reason="el Recon registró un indicador de DoublePulsar (indicio de compromiso)",
                               limitations=["es un indicio, no confirmación; validar fuera de banda con el blue team"])

        return self.result(asset, INCONCLUSIVE, evidence=ev,
                           reason="sin indicador de DoublePulsar en el Recon; el modo pasivo no puede descartarlo",
                           limitations=["para comprobar el implante haría falta habilitar la sonda activa (probe)"])
