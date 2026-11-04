"""Clasificación aproximada del SO Windows a partir de las cadenas que ya trae el Recon.

Las fuentes son `hosts.os` (osmatch de nmap, p. ej. "Microsoft Windows 7 SP1"), los banners de nxc
("Windows 10 Build 19041") y el texto de los servicios. Es un indicio, no una prueba: nunca basta por
sí solo para confirmar una vulnerabilidad. Devuelve etiquetas de familia para que cada validador decida.
"""
import re

# familias modernas (no afectadas por MS17-010 / BlueKeep sin parche de fábrica)
MODERN = re.compile(r"windows\s+(server\s+)?(10|11|2016|2019|2022|2025)\b", re.I)
# familias legadas típicamente afectadas por EternalBlue/BlueKeep (según cada CVE)
WIN7_ERA = re.compile(r"windows\s+(7|vista|xp|server\s+2008(\s+r2)?|server\s+2003)\b", re.I)
WIN8_ERA = re.compile(r"windows\s+(8(\.1)?|server\s+2012(\s+r2)?)\b", re.I)
IS_WINDOWS = re.compile(r"windows", re.I)

BUILD_RE = re.compile(r"build\s+(\d{4,6})", re.I)


def is_windows(text):
    return bool(IS_WINDOWS.search(text or ""))

def is_modern(text):
    return bool(MODERN.search(text or ""))

def is_win7_era(text):
    return bool(WIN7_ERA.search(text or ""))

def is_win8_era(text):
    return bool(WIN8_ERA.search(text or ""))

def build_number(text):
    m = BUILD_RE.search(text or "")
    return int(m.group(1)) if m else None


def summary(asset, *ports):
    """Texto combinado de SO + banners para clasificar (osmatch + lo que vio nxc en el puerto)."""
    return " ".join(x for x in (asset.os, asset.banner_text(*ports)) if x)
