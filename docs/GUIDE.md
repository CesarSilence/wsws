# Guía de uso de wsws

wsws (WorkSpace With Steroids) es un workspace de pentest para la terminal: ingiere la salida de tus
herramientas, la **fusiona** en una base por workspace y te deja **buscar** y **validar** en segundos.
No depende de Metasploit. Solo usa la librería estándar de Python (3.9+) y corre en Linux y macOS.

> ⚠️ Úsalo solo sobre activos autorizados. Las validaciones activas contactan el objetivo.

Esta guía es la **referencia** de cada comando. Si prefieres ver la herramienta funcionando de principio a
fin con la salida real que produce, mira el **recorrido "de cero a validar"** del [README](../README.md).

---

## 1. Instalación

```bash
pipx install git+https://github.com/CesarSilence/wsws.git   # recomendado
# o, desde una copia local:
pipx install /ruta/a/wsws
# o sin instalar nada:
python3 -m wsws <comando>
```

No tiene dependencias. Los datos quedan en `~/.wsws/ws/<workspace>/` (`wsws.db` + `evidence/`).

---

## 2. Conceptos

- **Workspace:** un cliente/ejercicio. Cada uno es una base SQLite aislada.
- **Scope (RoE):** reglas de alcance. El modo wrapper **bloquea** objetivos fuera de scope.
- **Ingesta:** metes datos por *pipe*, *wrapper* o *archivo*; wsws detecta el formato y **fusiona** sin duplicar.
- **Búsqueda:** un lenguaje corto (`445 os:windows`) sobre hosts, servicios, web, hallazgos y credenciales.
- **Validación (`check`):** motor nativo que detecta vulnerabilidades conocidas (activo o pasivo).

---

## 3. Primeros pasos

```bash
wsws use cliente-x                          # crea y activa el workspace
wsws scope add 10.10.0.0/16 '*.cliente.cl'  # define el alcance
wsws scope exclude 10.10.0.1                # excepciones
wsws                                        # resumen del workspace
```

---

## 4. Ingesta: tres formas

| Forma | Ejemplo | Qué hace |
|---|---|---|
| **Pipe** | `herramienta \| wsws` | Detecta el formato solo. Si hay TTY, además ves la salida. |
| **Wrapper** | `wsws nmap ...`, `wsws nuclei ...`, `wsws run -- cmd` | Inyecta `-oX`/`-jle`, valida el scope **antes** de ejecutar y guarda evidencia. |
| **Archivo** | `wsws add scan.xml res.nessus` | Copia el original a `evidence/`. |

```bash
nmap -p 22 10.10.10.0/24 | wsws             # pipe, cualquier formato
wsws nmap -sV -p- 10.10.10.5                # wrapper
wsws nxc smb 10.10.10.0/24 -u u -p p        # extrae hosts, SMB signing, SMBv1, creds, Pwn3d!
wsws add resultado.nessus                    # importar archivo
```

Formatos: nmap (normal/`-oX`/`-oG`), masscan, naabu, rustscan, httpx, nuclei, nxc/netexec/crackmapexec,
Nessus `.nessus` y listas de IP/host:puerto/URL.

**La fusión no duplica:** mismo `host:puerto` → un registro con `first_seen`/`last_seen`; un host que
llegó por nombre se une a su IP cuando aparece; un scan rápido no borra la versión de uno con `-sV`.

### DNS inverso nativo (`reverse`)

`wsws reverse` resuelve el PTR de todo un rango **sin herramientas externas** (ni `ipcalc` ni `host`) y
guarda los hostnames en el workspace, fusionándolos con los hosts por IP. Respeta el scope.

**La primera vez** que lo uses en un workspace, te pregunta si tu DNS apunta al DC del dominio. Si
respondes que no, te pide la IP del DNS/DC y la **recuerda para ese workspace** (en AD, los PTR internos
los resuelve el DC, no el resolver local). Puedes cambiarla cuando quieras con `--dns`.

```bash
wsws reverse 10.10.10.0/24              # 1ª vez: pregunta por el DNS; luego resuelve y guarda
wsws reverse 10.10.10.0/24 --dns 10.10.10.1   # fija (y guarda) el DC como DNS
wsws reverse 10.10.10.0/24 --dns system       # vuelve al resolver del sistema
wsws reverse 10.0.0.0/24 -t 128         # 128 hilos
wsws 445 | wsws reverse -               # solo los hosts que ya tienen 445 abierto
wsws reverse 10.10.10.0/24 -n           # solo listar, sin guardar
```
Opciones: `--threads/-t` (def. 64), `--timeout` (def. 2s), `--dns IP|system`, `--no-save/-n`, `--force`.

Para **ver después** los hosts que vinieron del reverse (sin mezclarlos con los de nmap u otra fuente):

```bash
wsws reverse list                       # todo lo resuelto en el workspace (alias: reverse ls)
wsws reverse list 10.21.0.0/16          # filtra por red
wsws reverse list sql                   # filtra por texto en IP o hostname
wsws reverse list sql -f ip             # solo IPs, para encadenar a otra herramienta
```

---

## 5. Búsqueda

`wsws <términos>` es el atajo de `wsws find`. Los términos van con AND; para negar: `-término`.

```bash
wsws 445 os:windows                 # puerto + SO
wsws svc:smb -tag:revisado          # servicio por sinónimo, excluyendo una etiqueta
wsws sev:high new:3d                 # hallazgos high+ de los últimos 3 días
wsws show dc01                       # ficha completa de un host
```

Vistas: `find|f`, `hosts|h`, `vulns|v`, `web|w`, `creds|c`, `show <host>`.
Términos: puertos (`445`, `8000-8100`), red (`10.0.0.0/24`), `svc:`, `product:`, `os:`, `host:`,
`domain:`, `tag:`, `sev:`, `vuln:`, `title:`, `tech:`, `url:`, `has:`, `new:`, `scope:in|out`, texto libre.

Salida encadenable (`-f`), ideal para pipes:

```bash
wsws 445 -tag:revisado | nxc smb - -u user -p pass    # ip
wsws svc:http -f url | nuclei -l -                     # url
wsws creds -f user > users.txt
```

---

## 6. Validar vulnerabilidades (`wsws check`)

Motor **nativo**: valida sin herramientas de terceros. **Solo detecta, no explota.**

### Flujo típico

```bash
wsws nmap -p445,3389 10.10.10.0/24     # 1) recon: descubre los puertos
wsws check                             # 2) qué validadores hay y cuántos objetivos tiene cada uno
wsws check ms17 10.10.10.0/24          # 3) valida (sonda activa SMB1)
wsws show 10.10.10.5                   # 4) lee el detalle (sección VALIDACIONES)
wsws vulns source:wsws-validate        #    o lista los hallazgos resultantes
```

Los objetivos salen del **recon ya guardado** (hosts con el puerto abierto + tus filtros), respeta el
scope y guarda por host una fila en `validations`, más:
- `VULNERABLE` → hallazgo crítico "(validado)"; `LIKELY_VULNERABLE` → hallazgo alto "(probable)".
- etiqueta por host `<validador>:<estado>` (p. ej. `wsws tag:eternalblue:vulnerable -f ip`).

### Dos modos

- **Activo:** una sonda nativa contacta el objetivo para detectar. Por defecto donde existe.
- **Pasivo** (`--passive`): razona sobre el recon guardado (versión, SO, SMBv1, hallazgos, creds),
  sin tocar la red. Si una sonda activa falla, cae a pasivo automáticamente.

### Validadores

| Validador | CVE | Puertos | Sonda activa |
|---|---|---|---|
| `eternalblue` (`ms17`, `eb`) | CVE-2017-0144 | 445/139 | SMB1 PeekNamedPipe (solo lectura), por defecto |
| `doublepulsar` (`dp`) | — | 445/139 | ninguna (solo pasivo, por decisión) |
| `bluekeep` (`bk`) | CVE-2019-0708 | 3389 | negociación RDP/NLA (solo lectura), con `--bluekeep-active` |
| `printnightmare` (`pn`) | CVE-2021-34527 | 445 | RPC opnum 89 (contenedor NULL), necesita credenciales |

```bash
wsws check ms17 --timeout 3            # sonda SMB1, timeout por objetivo
wsws check bluekeep --bluekeep-active  # sonda RDP de solo lectura (opt-in)
wsws check pn --cred 4                 # sonda RPC con una credencial de wsws (o -d corp -u user -p 'Clave')
wsws check all -tag:revisado           # todos, con filtro
wsws check ms17 --dry-run              # muestra objetivos sin sondear
```

### Estados (nunca confunden inconcluso con negativo)

| Estado | Significado | Acción |
|---|---|---|
| `VULNERABLE` | evidencia suficiente para confirmar | accionable |
| `LIKELY_VULNERABLE` | indicios fuertes, sin confirmar | confirmar |
| `NOT_VULNERABLE` | descartado dentro del método | — |
| `INCONCLUSIVE` | faltan datos (p. ej. solo tienes el puerto, o sesión nula bloqueada) | enriquecer recon / dar creds |
| `NOT_APPLICABLE` | no aplica (no es Windows, SO moderno, puerto cerrado) | — |
| `ERROR` | no se pudo completar | revisar |

**`INCONCLUSIVE` no es "seguro".** Suele significar que falta recon o credenciales.

### Detalle de cada sonda activa (todas de detección)

- **EternalBlue:** sesión nula SMB1 → `IPC$` → PeekNamedPipe sobre un FID inexistente → lee el
  `NT_STATUS` (`STATUS_INSUFF_SERVER_RESOURCES` → vulnerable). No modifica el host.
- **BlueKeep:** negociación X.224 para ver si el host exige NLA/CredSSP. **No** ejecuta el check que
  puede provocar BSOD (no toca `MS_T120`): esa comprobación destructiva no está implementada a propósito.
- **PrintNightmare:** SMB2(2.1)+NTLMv2+DCERPC nativos; `RpcAddPrinterDriverEx` con driver **NULL** (sin
  DLL/UNC → no carga código) y lee el error. Con credenciales de **administrador** → `INCONCLUSIVE`
  (siempre pasaría): usa una cuenta **sin** privilegios para que la prueba sea válida.

> Las sondas siguen las specs de Microsoft y la cripto NTLM está validada con vectores oficiales. La
> interpretación es conservadora: respuesta rara → `INCONCLUSIVE`, nunca un falso "no vulnerable".

### Modo legacy (herramientas externas)

```bash
wsws check --legacy                    # estado de nmap/rdpscan/combo
wsws check set rdpscan=~/tools/rdpscan/rdpscan
wsws check ms17 --legacy               # usa nmap NSE en vez de la sonda nativa
```

---

## 7. Credenciales, notas, etiquetas, dominios

```bash
wsws creds add 'corp\user:Pass' --host 10.0.0.5 --admin   # no duplica; acepta impacket y UPN
wsws creds                              # lista (el ID va en la 1ª columna)
wsws creds mod 3 secret=Nueva --admin
wsws tag 10.0.0.5 dc -revisado          # +dc, quita revisado
wsws 88 | wsws tag - dc                 # etiqueta desde stdin
wsws note 10.0.0.5 "se validó manualmente"
wsws domain alias CORP corp.local       # CORP\u == corp.local\u
```

---

## 8. Evidencia y trazabilidad

```bash
wsws log                                # línea de tiempo: comando, operador, hora, exit, sha256
wsws log 12 --raw                       # salida completa de una evidencia
```

Cada corrida (recon o `check`) queda registrada. Útil para el informe y para retests (`new:`).

---

## 9. Receta de principio a fin

```bash
wsws use acme-interno
wsws scope add 10.20.0.0/16
wsws nmap -p445,3389 --script smb-protocols,smb-os-discovery 10.20.0.0/16   # recon enriquecido
wsws nxc smb <(wsws 445)                                   # SO/SMBv1/creds
wsws check all                                             # valida todo
wsws check pn --cred 2                                     # PrintNightmare con credencial no-admin
wsws vulns source:wsws-validate                            # resultados
wsws tag:eternalblue:vulnerable -f ip                      # IPs confirmadas
```

---

## 10. Dónde viven los datos (y cómo respaldarlos)

Todo queda en tu disco, sin servidor:

```
~/.wsws/
  ws/
    <workspace>/
      wsws.db          # hosts, servicios, web, hallazgos, creds, validaciones, línea de tiempo
      evidence/        # copia íntegra de cada salida/archivo ingerido, con su sha256
```

- **Respaldar o entregar un workspace:** copia la carpeta `~/.wsws/ws/<workspace>/` completa (o compártela/versiónala). Es portable.
- **Empezar de cero:** `wsws rm <workspace>` lo borra; `wsws ls` lista los que tienes.
- **Trabajar puntualmente en otro sin cambiar el activo:** `wsws -w otro ...` o `WSWS=otro wsws ...`.

---

## 11. Problemas comunes

- **`wsws: command not found` tras instalar con pipx** → asegúrate de que el directorio de pipx está en el `PATH` (`pipx ensurepath` y reabre la terminal). Alternativa sin instalar: `python3 -m wsws ...`.
- **Un objetivo se omite o aparece "fuera de scope"** → no está dentro de lo que definiste con `wsws scope add`. Revisa con `wsws scope check` o ejecuta con `wsws --force ...` (queda marcado en la evidencia).
- **`wsws check pn` da `INCONCLUSIVE` siempre** → PrintNightmare necesita una credencial **sin** privilegios (`wsws check pn --cred <ID>`). Con una cuenta de administrador la prueba "siempre pasaría" y por eso se marca inconcluso a propósito.
- **Un `check` da `INCONCLUSIVE` y no sé si es seguro** → `INCONCLUSIVE` **no** es "no vulnerable". Suele faltar recon (solo tienes el puerto) o credenciales. Enriquece el recon o pasa credenciales y vuelve a correrlo.
- **No veo la salida de la herramienta al usar pipe** → cuando la salida va a otro comando (no a la terminal), wsws solo ingiere; en una terminal interactiva además la muestra.
- **El reverse no resuelve los nombres internos** → en AD los PTR internos los resuelve el DC, no tu resolver local. Apunta el DNS al DC: `wsws reverse <rango> --dns <IP-del-DC>` (se recuerda para ese workspace).

---

## 12. Ayuda

Cada comando trae su ayuda: `wsws <comando> -h` (p. ej. `wsws check -h`, `wsws find -h`, `wsws creds add -h`).
