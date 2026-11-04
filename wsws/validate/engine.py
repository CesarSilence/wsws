"""Motor de validación: selecciona objetivos desde el Recon, ejecuta los validadores y guarda resultados.

Flujo: Recon (Store) -> Asset normalizado -> Validator.evaluate_passive -> Result -> Store.
No contacta la red: la evaluación es pasiva sobre lo que WSWS ya enumeró. Respeta el scope (los
objetivos fuera se omiten salvo force) y registra cada corrida como evidencia.
"""
import time

from . import base, registry
from .base import Asset


def build_asset(st, addr):
    """Arma el Asset desde el Store. Es una vista del modelo existente, no una segunda base de datos."""
    h = st.find_host(addr)
    if h is None:
        return None
    hid = h["id"]
    svcs = []
    for r in st.q("SELECT * FROM services WHERE host_id=?", (hid,)):
        d = dict(r)
        svcs.append(d)
    finds = [dict(r) for r in st.q("SELECT * FROM findings WHERE host_id=?", (hid,))]
    # creds del host + creds de dominio que coincidan con el dominio del host
    dom = (h["domain"] or "").lower()
    creds = []
    for r in st.q("SELECT * FROM creds WHERE host_id=? OR (domain!='' AND LOWER(domain)=?)", (hid, dom)):
        creds.append(dict(r))
    return Asset(addr=h["addr"], hostnames=[x for x in (h["hostnames"] or "").split(",") if x],
                 os=h["os"] or "", domain=h["domain"] or "",
                 tags=[x for x in (h["tags"] or "").split(",") if x],
                 services=svcs, findings=finds, creds=creds,
                 first_seen=h["first_seen"], last_seen=h["last_seen"])


def targets(st, validator, terms, force=False):
    """IPs del workspace con algún puerto del validador abierto (más los filtros). -> (en_scope, fuera)."""
    from .. import query
    rows = query.find(st, list(terms))
    ports = set(validator.ports)
    addrs = []
    for r in rows:
        if r.get("port") in ports and r["addr"] not in addrs:
            addrs.append(r["addr"])
    out = [a for a in addrs if st.in_scope(a) is False]
    keep = [a for a in addrs if a not in out]
    return (keep + (out if force else [])), out


def has_probe(validator):
    """True si el validador implementa una sonda activa nativa propia (no la de la clase base)."""
    return type(validator).probe is not base.Validator.probe


def evaluate(st, validator, addr, active=False, ctx=None):
    """Construye el Asset y corre el validador. Modo activo = sonda nativa si existe; si no, pasivo.

    La sonda activa contacta el objetivo (detección de bajo impacto); la evaluación pasiva solo usa el
    Recon guardado. Si la sonda falla, cae a la evaluación pasiva y anota el error como limitación.
    """
    t0 = time.monotonic()
    asset = build_asset(st, addr)
    try:
        if asset is None:
            res = base.Result(check=validator.id, cve=validator.cve, addr=addr, status=base.ERROR,
                              error="el host no está en el workspace")
        elif not validator.applicable(asset):
            res = validator.result(asset, base.NOT_APPLICABLE,
                                   reason=f"el activo no expone {'/'.join(map(str, validator.ports))}")
        elif active and has_probe(validator):
            res = validator.probe(asset, ctx)
            if res.status == base.ERROR:   # sonda falló -> caer a pasivo, conservando el motivo
                passive = validator.evaluate_passive(asset)
                passive.limitations.append(f"sonda activa falló: {res.error}")
                res = passive
        else:
            res = validator.evaluate_passive(asset)
    except Exception as e:  # un validador no debe tumbar la corrida completa
        res = base.Result(check=validator.id, cve=validator.cve, addr=addr, status=base.ERROR,
                          error=f"{type(e).__name__}: {e}")
    res.duration_ms = int((time.monotonic() - t0) * 1000)
    return res


def record(st, result, eid=None):
    """Persiste el resultado: fila en `validations`, hallazgo (solo VULNERABLE/LIKELY) y etiqueta por host."""
    from .. import parsers
    h = st.find_host(result.addr)
    if h is None:
        return
    hid = h["id"]
    st.validation(hid, result.check, cve=result.cve, status=result.status, method=result.method,
                  reason=result.reason, evidence=result.evidence_text(),
                  limitations="\n".join(result.limitations), recon_age=result.recon_age, evidence_id=eid)

    v = registry.get(result.check)
    if result.status in base.FINDING:
        sev, suffix = base.FINDING[result.status]
        port = v.ports[0] if v else 0
        detail = result.reason
        if result.evidence:
            detail += "\n\nEvidencia:\n" + result.evidence_text()
        if result.limitations:
            detail += "\n\nLimitaciones:\n- " + "\n- ".join(result.limitations)
        if eid:
            detail += f"\n\nevidencia #{eid}"
        rec = parsers.finding(result.addr, port, source="wsws-validate", ref=result.cve,
                              title=f"{v.title if v else result.check} - {suffix}",
                              severity=sev, location=f"{result.addr}:{port}", detail=detail)
        st.ingest([rec], eid)

    # etiqueta <check>:<estado en minúsculas>, quitando la anterior de este check
    tag = f"{result.check}:{result.status.lower()}"
    others = [f"{result.check}:{s.lower()}" for s in base.STATES if s != result.status]
    st.tag(hid, [tag], others)


def run(st, validator, terms, force=False, eid=None):
    """Evalúa todos los objetivos de un validador y persiste. -> (resultados, fuera_de_scope)."""
    keep, out = targets(st, validator, terms, force)
    results = []
    for addr in keep:
        res = evaluate(st, validator, addr)
        record(st, res, eid)
        results.append(res)
    return results, out
