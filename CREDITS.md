# Créditos y atribuciones

## Agradecimientos

Gracias a **SEK** por el apoyo y el contexto que hicieron posible esta herramienta.

## Implementación

wsws es original y usa solo la librería estándar de Python. Los validadores de vulnerabilidades
implementan sus comprobaciones de forma nativa (no delegan en herramientas externas). Aun así,
reconocemos el trabajo previo que sirvió de referencia técnica.

### PrintNightmare (CVE-2021-34527 / CVE-2021-1675)

La lógica de **detección** (una llamada `RpcAddPrinterDriverEx` con un contenedor de driver NULL y la
interpretación del código de error) se basa en la función `check()` de `printnightmare.py`, publicada
bajo licencia **MIT** por:

- **@ly4k** — https://github.com/ly4k
- Crédito original a **@cube0x0** y **@ollypwn**.

wsws **reimplementa** esa comprobación sobre un transporte propio (SMB2 + NTLMv2 + DCERPC en stdlib) y
**no incorpora** el código de explotación de ese proyecto: solo detecta, nunca carga un driver/DLL.

El modo "Combo File" de referencia (https://github.com/CesarSilence/PrintNightmare) es de la autoría
del equipo de wsws; wsws lo sustituye por su motor de objetivos + scope + concurrencia.

### Protocolos

Las implementaciones de SMB1, SMB2, NTLM(v2), DCERPC y RDP siguen las especificaciones públicas de
Microsoft (MS-SMB2, MS-RPRN, MS-NLMP, MS-RDPBCGR) y el RFC 1320 (MD4). Son implementaciones propias.

## Herramientas externas (opcionales, modo `--legacy`)

El modo heredado puede apoyarse en herramientas de terceros, que NO se distribuyen con wsws:

- **nmap** (NSE `smb-vuln-ms17-010`, `smb-double-pulsar-backdoor`) — https://nmap.org
- **rdpscan** — https://github.com/robertdavidgraham/rdpscan
