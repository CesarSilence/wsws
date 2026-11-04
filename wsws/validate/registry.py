"""Registro de validadores. Permite sumar nuevas vulnerabilidades sin modificar el núcleo.

Los validadores incluidos se listan aquí. Además se descubren los registrados por terceros mediante los
entry points del grupo "wsws.validators" (si el entorno los expone), de modo que un paquete externo
pueda aportar un validador sin tocar WSWS.
"""
from .validators.bluekeep import BlueKeepValidator
from .validators.doublepulsar import DoublePulsarIndicatorValidator
from .validators.eternalblue import EternalBlueValidator
from .validators.printnightmare import PrintNightmareChecker

_BUILTIN = [EternalBlueValidator, DoublePulsarIndicatorValidator, BlueKeepValidator, PrintNightmareChecker]


def _discover():
    out = []
    try:
        from importlib.metadata import entry_points
    except ImportError:
        return out
    try:
        eps = entry_points(group="wsws.validators")
    except TypeError:  # Python 3.9: API sin argumento group
        eps = entry_points().get("wsws.validators", [])
    for ep in eps:
        try:
            out.append(ep.load())
        except Exception:  # un plugin roto no debe tumbar el motor
            continue
    return out


REGISTRY = {}
ALIASES = {}


def _register(cls):
    v = cls()
    REGISTRY[v.id] = v
    ALIASES[v.id] = v.id
    for a in v.aliases:
        ALIASES[a] = v.id


for _cls in _BUILTIN + _discover():
    _register(_cls)


def names():
    return list(REGISTRY)


def aliases():
    return dict(ALIASES)


def get(name):
    """Valida por nombre o alias (normaliza a minúsculas). -> Validator o None."""
    return REGISTRY.get(ALIASES.get((name or "").lower()))
