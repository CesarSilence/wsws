"""Contrato común de los validadores: estados, modelo de activo, evidencia y clase base.

El diseño sigue los patrones de WSWS (stdlib, dataclasses, sin dependencias). Un validador recibe un
`Asset` (vista normalizada del host tomada del Store, no una segunda base de datos) y devuelve un
`Result` con un estado normalizado, la evidencia que lo respalda y las limitaciones del método.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone

# --- estados normalizados -------------------------------------------------------------
VULNERABLE = "VULNERABLE"              # evidencia suficiente para confirmar la condición
LIKELY_VULNERABLE = "LIKELY_VULNERABLE"  # las evidencias apuntan, pero no confirman
NOT_VULNERABLE = "NOT_VULNERABLE"     # se descarta dentro de los límites del método
INCONCLUSIVE = "INCONCLUSIVE"         # evidencias insuficientes
NOT_APPLICABLE = "NOT_APPLICABLE"     # el activo no reúne los requisitos
ERROR = "ERROR"                       # no fue posible completar la validación

STATES = (VULNERABLE, LIKELY_VULNERABLE, NOT_VULNERABLE, INCONCLUSIVE, NOT_APPLICABLE, ERROR)
# orden de severidad para mostrar y para resumir (lo más accionable primero)
ORDER = {VULNERABLE: 0, LIKELY_VULNERABLE: 1, INCONCLUSIVE: 2, ERROR: 3, NOT_VULNERABLE: 4, NOT_APPLICABLE: 5}

# estado -> (severidad del hallazgo, sufijo). Solo estos dos estados generan hallazgo en WSWS.
FINDING = {VULNERABLE: ("critical", "validado"), LIKELY_VULNERABLE: ("high", "probable")}

TS_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _now():
    return datetime.now(timezone.utc)


def age_days(ts):
    """Antigüedad en días de una marca de tiempo del Recon (o None)."""
    try:
        d = datetime.strptime(ts, TS_FMT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
    return (_now() - d).days


# --- modelo común de datos ------------------------------------------------------------

@dataclass
class Evidence:
    """Un dato que respalda el resultado, con su procedencia (criterio 6: conclusiones con evidencia)."""
    kind: str            # service | finding | os | cred | probe
    summary: str
    source: str = ""     # herramienta/origen (nmap, nxc, wsws-check...)
    observed: str = ""   # cuándo se observó (first_seen/last_seen del Recon)

    def text(self):
        who = f" [{self.source}]" if self.source else ""
        when = f" ({self.observed})" if self.observed else ""
        return f"{self.summary}{who}{when}"


@dataclass
class Asset:
    """Vista normalizada de un host tomada del Store. Reutiliza el modelo existente, no lo duplica."""
    addr: str
    hostnames: list = field(default_factory=list)
    os: str = ""
    domain: str = ""
    tags: list = field(default_factory=list)
    services: list = field(default_factory=list)   # dicts: port, proto, name, product, version, extra, banner, state, last_seen
    findings: list = field(default_factory=list)    # dicts: ref, title, sev, detail, source, last_seen
    creds: list = field(default_factory=list)        # dicts: domain, username, admin, valid, kind
    first_seen: str = ""
    last_seen: str = ""

    # --- ayudas de consulta sobre el Recon del host -----------------------------------
    def ports(self):
        return {s["port"] for s in self.services if (s.get("state") or "open").startswith("open")}

    def has_port(self, *wanted):
        return bool(self.ports().intersection(wanted))

    def service_on(self, *wanted):
        for s in self.services:
            if s["port"] in wanted and (s.get("state") or "open").startswith("open"):
                return s
        return None

    def recon_ts(self, *ports):
        """last_seen más reciente de los servicios relevantes (para medir antigüedad del dato)."""
        ts = [s.get("last_seen") for s in self.services if s["port"] in ports and s.get("last_seen")]
        return max(ts) if ts else self.last_seen

    def finding_ref(self, substr):
        """Hallazgo de recon previo cuyo ref o título contiene substr.

        Ignora los hallazgos que generó el propio motor (`wsws-validate`): si no, un resultado "probable"
        se reinterpretaría como una comprobación externa positiva y escalaría solo a VULNERABLE.
        """
        substr = substr.lower()
        for f in self.findings:
            if (f.get("source") or "") == "wsws-validate":
                continue
            if substr in (f.get("ref") or "").lower() or substr in (f.get("title") or "").lower():
                return f
        return None

    def banner_text(self, *ports):
        parts = []
        for s in self.services:
            if not ports or s["port"] in ports:
                parts += [s.get("name") or "", s.get("product") or "", s.get("version") or "",
                          s.get("extra") or "", s.get("banner") or ""]
        return " ".join(p for p in parts if p)

    def admin_creds(self):
        """Credenciales con privilegios de administrador aplicables al host (afecta a PrintNightmare)."""
        return [c for c in self.creds if c.get("admin") and c.get("valid")]


# --- resultado ------------------------------------------------------------------------

@dataclass
class Result:
    check: str
    cve: str
    addr: str
    status: str = INCONCLUSIVE
    method: str = "passive"          # passive | native-probe
    reason: str = ""
    evidence: list = field(default_factory=list)   # [Evidence]
    limitations: list = field(default_factory=list)
    recon_age: str = ""
    error: str = ""
    duration_ms: int = 0

    def evidence_text(self):
        return "\n".join(e.text() for e in self.evidence)

    def __post_init__(self):
        if self.status not in STATES:
            raise ValueError(f"estado inválido: {self.status!r}")


# --- clase base de los validadores ----------------------------------------------------

class Validator:
    """Interfaz común. Un validador concreto define id/cve/ports y implementa applicable + evaluate_passive."""
    id = ""
    cve = ""
    title = ""
    ports = ()               # puertos que debe tener abiertos el activo
    requires_creds = False
    aliases = ()
    limitations = ()         # limitaciones generales del método (siempre se adjuntan)

    def applicable(self, asset):
        """¿El activo reúne los requisitos mínimos (p. ej. el puerto correcto abierto)?"""
        return asset.has_port(*self.ports)

    def missing(self, asset):
        """Datos de Recon que faltan para una conclusión y que podría obtener una sonda nativa."""
        return []

    def evaluate_passive(self, asset):
        """Evalúa SOLO con el Recon ya guardado. Debe devolver un Result. Lo implementa cada validador."""
        raise NotImplementedError

    def probe(self, asset, ctx=None):
        """Punto de extensión para una sonda de red nativa de bajo impacto.

        El motor no la invoca: la evaluación es pasiva por diseño. Queda declarada para que un operador
        pueda habilitar una comprobación activa en el futuro sin tocar el núcleo de WSWS.
        """
        return self.result(asset, INCONCLUSIVE, method="native-probe",
                           reason="sonda activa no habilitada (punto de extensión)",
                           limitations=["la comprobación activa requiere implementar probe() y autorización explícita"])

    # --- ayudas para construir el Result ----------------------------------------------
    def result(self, asset, status, reason="", evidence=(), limitations=(), method="passive"):
        ts = asset.recon_ts(*self.ports)
        days = age_days(ts)
        lim = list(self.limitations) + list(limitations)
        if days is not None and days >= 14:
            lim.append(f"Recon de hace {days} días ({ts}): puede estar desactualizado; conviene re-enumerar")
        return Result(check=self.id, cve=self.cve, addr=asset.addr, status=status, method=method,
                      reason=reason, evidence=list(evidence), limitations=lim,
                      recon_age=f"{days}d" if days is not None else "")
