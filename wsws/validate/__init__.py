"""Motor nativo de validación de vulnerabilidades de WSWS.

Los validadores razonan sobre el Recon ya guardado en el workspace (hosts, servicios, versiones,
hallazgos y credenciales) y devuelven un resultado normalizado. No explotan ni modifican el activo
remoto. La evaluación por omisión es pasiva: usa lo que WSWS ya enumeró, sin tocar la red.

La comprobación activa (sonda de red de bajo impacto) es un punto de extensión: cada validador
declara `probe()` pero el motor solo invoca `evaluate_passive()`. Así un operador puede habilitar
una sonda nativa en el futuro sin cambiar el núcleo.
"""
from .base import (ERROR, INCONCLUSIVE, LIKELY_VULNERABLE, NOT_APPLICABLE, NOT_VULNERABLE, STATES,
                   VULNERABLE, Asset, Evidence, Result, Validator)
from .registry import REGISTRY, aliases, get, names

__all__ = ["VULNERABLE", "LIKELY_VULNERABLE", "NOT_VULNERABLE", "INCONCLUSIVE", "NOT_APPLICABLE",
           "ERROR", "STATES", "Asset", "Evidence", "Result", "Validator",
           "REGISTRY", "names", "aliases", "get"]
