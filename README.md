# wsws — WorkSpace With Steroids

Workspace de pentest/red team para la terminal, **fuera de Metasploit**. Le mandas la salida de cualquier herramienta, wsws la **fusiona** en una base por cliente y después **buscas** y **validas** lo que necesitas en segundos.

> ⚠️ **Uso autorizado únicamente.** wsws es una herramienta de evaluación de seguridad. Las sondas de validación contactan sistemas remotos: úsalas **solo** sobre activos para los que tengas autorización explícita por escrito (contrato, orden de trabajo, alcance de pentest). El uso contra sistemas ajenos puede ser ilegal. La detección es de bajo impacto y no explota, pero sigue siendo tráfico no solicitado hacia el objetivo. Los autores no se responsabilizan del mal uso.

---

## Qué es y por qué

En un pentest real corres muchas herramientas (nmap, nxc, nuclei, httpx…) y terminas con decenas de archivos y salidas sueltas. Cruzar todo eso —qué hosts tienen 445, cuáles son Windows, dónde hay credenciales válidas— se vuelve el cuello de botella.

**wsws es el pegamento.** No reemplaza tus herramientas: ingiere su salida, la unifica en un solo lugar por cliente y te deja consultarla y actuar sobre ella. Pensado para:

- **No depender de Metasploit** ni de un stack pesado: es Python puro, sin dependencias, funciona offline.
- **No perder nada**: cada dato queda fusionado, fechado y con su evidencia original guardada (útil para el informe y los retests).
- **Ir rápido**: un lenguaje de búsqueda corto y salida encadenable por *pipe* hacia la siguiente herramienta.
- **Validar en el sitio**: un motor nativo detecta vulnerabilidades conocidas (MS17-010, BlueKeep, PrintNightmare…) sin herramientas de terceros.

---

## Cómo funciona

### El modelo mental

Todo gira en torno a tres pasos:

```
  METER DATOS            CONSULTAR             ACTUAR
  ───────────           ──────────           ────────
  nmap / nxc /          wsws 445 os:windows   wsws check ms17 ...
  nuclei / ...   ──▶    wsws show dc01    ──▶  wsws reverse ...
  (pipe/wrapper/add)    wsws creds             wsws ... -f ip | otra-tool
        │                    ▲                      │
        └──────▶  [ workspace = base SQLite ] ◀─────┘
                  fusión · evidencia · scope
```

1. **Metes datos** de cualquier herramienta (por *pipe*, como *wrapper* o importando archivos). wsws detecta el formato solo.
2. wsws los **fusiona** en el workspace sin duplicar y guarda el archivo original como evidencia.
3. **Consultas y actúas**: buscas, ves la ficha de un host, validas vulnerabilidades o encadenas la salida hacia otra herramienta.

### El workspace

Un **workspace** es un cliente o ejercicio. Cada uno es una **base SQLite aislada** en `~/.wsws/ws/<nombre>/`, que contiene:

- `wsws.db` — hosts, servicios, web, hallazgos, credenciales, dominios, etiquetas, notas, validaciones y la línea de tiempo.
- `evidence/` — copia íntegra de cada salida/archivo que ingirió, con su `sha256`.

No hay servidor ni configuración: los datos son tuyos, en tu disco, y puedes copiar o versionar la carpeta del workspace.

### La fusión (no duplica)

Cuando dos herramientas ven lo mismo, wsws lo **unifica** en vez de duplicarlo:

- Mismo `host:puerto` → un solo registro con `first_seen` / `last_seen`.
- Un host que llegó solo por nombre (nuclei, httpx) se une a su IP cuando esta aparece.
- Un scan rápido sin `-sV` **no** borra la versión que detectó un scan anterior con `-sV`.
- Las credenciales de dominio son una sola aunque se vean en varios hosts; `LM:NT` y `NT` cuentan como el mismo hash.

### Scope (reglas de alcance / RoE)

Defines el alcance con `wsws scope add`. El modo *wrapper* **bloquea** cualquier objetivo fuera de scope **antes** de ejecutar (puedes forzar con `--force`, que deja la marca en la evidencia). Las búsquedas y validaciones respetan el mismo límite.

### El motor de validación

`wsws check` usa un **motor nativo propio** (sockets + stdlib, sin herramientas de terceros) que **solo detecta, no explota**. Los objetivos salen del recon ya guardado, respeta el scope y cada validador es un módulo independiente: agregar una vulnerabilidad nueva no toca el núcleo (ver [Validar vulnerabilidades](#validar-vulnerabilidades-conocidas)).

### Por qué stdlib y offline

Solo usa la librería estándar de Python (3.9+). Sin dependencias que instalar, auditar o que se rompan; corre igual en una máquina de salto aislada. Los protocolos (SMB1/2, NTLMv2, DCERPC, RDP, DNS) están implementados desde cero siguiendo las especificaciones públicas.

---

## Instalación

```bash
pipx install git+https://github.com/CesarSilence/wsws.git   # recomendado
pipx install /ruta/a/wsws                                   # desde una copia local
python3 -m wsws <comando>                                   # sin instalar nada
```

Sin dependencias (Python 3.9 o superior). Funciona en Linux y macOS. Los datos quedan en `~/.wsws/ws/<workspace>/`.

---

## Recorrido: de cero a validar

Así se ve un ejercicio típico de principio a fin. La salida de abajo es real (datos de ejemplo).

**1. Crea el workspace y define el alcance.** Cada cliente/ejercicio es su propio workspace aislado.

```bash
wsws use acme-interno
wsws scope add 10.20.0.0/16
```

**2. Mete el recon.** Por *pipe*, como *wrapper* o importando lo que ya tienes; wsws detecta el formato y lo fusiona.

```bash
wsws nmap -p445,3389 --script smb-protocols,smb-os-discovery 10.20.0.0/16
nxc smb 10.20.0.0/16 -u user -p pass | wsws
wsws add escaneo-previo.xml resultado.nessus
```

`wsws` sin argumentos te da el panorama del workspace:

```
wsws · acme-interno   operador csoto
  hosts 266 · servicios 461 · web 38 · vulns 91 (crit 33, high 40, med 13, low 5) · creds 3 · evidencias 24
  scope: 10.20.0.0/16
  top puertos: 445/microsoft-ds×68  139/netbios-ssn×63  3389/ms-wbt-server×51  135/msrpc×43  22/ssh×34  ...
  últimas acciones:
    #22 11-01 18:53 wsws nmap -p445,3389 ...                      68 hosts con 445
    #24 11-04 15:27 wsws reverse 10.20.0.0/16 --dns 10.20.10.10   hosts 33 (+33 nuevos)
```

**3. Busca lo que te interesa.** Por ejemplo, los Windows con SMB expuesto:

```bash
wsws 445 os:windows
```

```
ADDR            PORT  SERVICIO      VERSIÓN     HOSTNAME              OS                            FLAGS
10.20.10.14     445   microsoft-ds  Microsoft…  dc01.corp.local       Microsoft Windows Server 20…
10.20.11.12     445   microsoft-ds  Microsoft…  srv01.corp.local      Microsoft Windows Server 20…
10.20.11.16     445   microsoft-ds  Microsoft…  srv02.corp.local      Microsoft Windows Server 20…
...
```

**4. Valida sobre esos hosts.** Los objetivos salen del recon que ya guardaste, no los escribes a mano.

```bash
wsws check                     # ¿qué puedo validar y sobre cuántos hosts?
```

```
VALIDADOR       VALIDA                           PUERTOS  OBJETIVOS  MODO
eternalblue     EternalBlue (MS17-010)           445/139  68         activo+pasivo
doublepulsar    DoublePulsar (indicador SMB)     445/139  68         pasivo
bluekeep        BlueKeep (CVE-2019-0708)         3389     51         activo+pasivo
printnightmare  PrintNightmare (CVE-2021-34527)  445      68         activo+pasivo
```

```bash
wsws check ms17                # sonda nativa MS17-010 contra los 68 hosts con 445
```

**5. Lee el resultado en la ficha del host.** `wsws show` reúne servicios, web, hallazgos y la sección VALIDACIONES con el estado, la razón y las limitaciones del método:

```bash
wsws show 10.66.66.10
```

```
10.66.66.10  dc01.lab.local, dc01   #eternalblue:vulnerable #bluekeep:likely_vulnerable #printnightmare:inconclusive
  OS: Windows Server 2008 R2 Standard 7601 · Dominio: lab.local

SERVICIOS (2)
PORT      ESTADO  SERVICIO       VERSIÓN
445/tcp   open    microsoft-ds   Windows Server 2008 R2 Standard 7601 Service Pack 1
3389/tcp  open    ms-wbt-server

HALLAZGOS (5)
SEV   PORT  HALLAZGO                             REF             UBICACIÓN
CRIT  445   EternalBlue (MS17-010) - validado    CVE-2017-0144   10.66.66.10:445
HIGH  3389  BlueKeep (CVE-2019-0708) - probable  CVE-2019-0708   10.66.66.10:3389
MED   445   SMBv1 habilitado                     smbv1-enabled   10.66.66.10:445

VALIDACIONES (4)
VALIDADOR       CVE             RESULTADO   MÉTODO   RAZÓN
eternalblue     CVE-2017-0144   VULNERABLE  active   PeekNamedPipe devolvió STATUS_INSUFF_SERVER_RESOURCES
bluekeep        CVE-2019-0708   probable    passive  SO de la familia afectada con RDP expuesto; falta confirmación activa
printnightmare  CVE-2021-34527  inconcluso  passive  SMB en Windows: candidato, pero requiere la sonda RPC (da credenciales)
  eternalblue — limitaciones: un puerto SMB abierto no implica vulnerabilidad; la versión del SO es un indicio, no una prueba
  ...
```

> **El estado nunca miente por omisión.** `inconcluso` no es "seguro": suele significar que falta recon o credenciales. Solo `VULNERABLE` se marca cuando hay evidencia suficiente.

**6. Acciona.** Saca las IPs confirmadas para el informe o para el siguiente paso, encadenando por *pipe*:

```bash
wsws tag:eternalblue:vulnerable -f ip          # lista las IPs confirmadas
wsws vulns source:wsws-validate                # todos los hallazgos del validador
wsws reverse list 10.20.0.0/16 -f ip | otra-herramienta
```

A partir de aquí, las secciones siguientes son la referencia de cada comando.

---

## Uso

### Empezar

```bash
wsws use cliente-x                          # crea y activa el workspace
wsws scope add 10.10.0.0/16 '*.cliente.cl'  # reglas de alcance (RoE)
wsws scope exclude 10.10.0.1
wsws                                        # resumen del workspace activo
```

`-w otro` o `WSWS=otro` usan otro workspace de forma puntual. `WSWS_OPERATOR` cambia el nombre del operador.

### Meter datos (ingesta)

| Forma | Ejemplo | Notas |
|---|---|---|
| **Pipe** | `herramienta \| wsws` | Detecta el formato solo. Si estás en una terminal, igual ves la salida. |
| **Wrapper** | `wsws nmap ...`, `wsws nuclei ...`, `wsws run -- cmd` | Inyecta `-oX` o `-jle` sin que lo veas, valida el scope **antes** de ejecutar y guarda la evidencia. |
| **Archivo** | `wsws add f1 f2 ...` | Copia el original a `evidence/`. |

```bash
nmap -p 22 10.10.10.0/24 | wsws             # pipe directo, cualquier formato
wsws nmap -sV -p- 10.10.10.5                # wrapper: salida normal + guardado + evidencia
wsws sudo nmap -sS 10.10.10.0/24
wsws nxc smb 10.10.10.0/24 -u u -p p        # extrae hosts, SMB signing, creds y Pwn3d!
wsws add resultado.nessus scan.xml          # importar archivos
```

Formatos soportados: nmap (normal, `-oX`, `-oG`), masscan, naabu, rustscan, httpx (JSON y texto), nuclei (JSONL y texto), nxc/netexec/crackmapexec, Nessus `.nessus` y listas de IP, host:puerto o URL.

### Buscar

`wsws <términos>` es el atajo de `wsws find`. Los términos se combinan con AND. Para negar uno, antepón `-término` o `not término`.

| Término | Significado |
|---|---|
| `445`, `22,80`, `8000-8100` | puertos |
| `10.0.0.5`, `10.0.0.0/24` | IP o red |
| `svc:smb`, `product:tomcat`, `proto:udp` | servicio. `svc:smb`, `rdp`, `winrm`, `mssql`, `dns`, `ldap`… también encuentran los nombres de nmap (`microsoft-ds`, `ms-wbt-server`…) y los puertos típicos sin nombre |
| `os:windows`, `host:dc`, `domain:corp`, `tag:dc` | host |
| `sev:high` (high o mayor), `vuln:ms17`, `source:nuclei` | hallazgos |
| `title:login`, `tech:wordpress`, `url:admin` | web |
| `has:admin`, `has:creds`, `has:vuln`, `has:web`, `has:notes` | existencia |
| `new:2h`, `new:3d`, `new:2026-10-19` | lo nuevo desde X (sirve para retests) |
| `scope:out`, `scope:in` | alcance |
| cualquier otra palabra | texto libre en banners, scripts NSE, títulos web, hallazgos y notas |

Vistas: `find|f` (servicios), `hosts|h`, `vulns|v`, `web|w`, `creds|c` y `show <host>`.

Salida: `-f <formato>`. Cada vista tiene los suyos y `wsws <vista> -h` los lista; un formato que no existe da error con la lista de disponibles.

| Vista | Formatos |
|---|---|
| `find` | `table ip hp url ports json jsonl csv` |
| `hosts` | `table ip json jsonl csv` |
| `vulns` | `table ip hp url json jsonl csv` |
| `web` | `table url ip json jsonl csv` |
| `creds` | `table cred user secret ip json jsonl csv` |

Cuando la salida va a un pipe, el formato por defecto es el más útil para encadenar:

```bash
wsws 445 -tag:revisado | nxc smb - -u user -p pass       # ip
wsws svc:http -f url | nuclei -l -                       # url
nmap -sV -p $(wsws os:linux -f ports) -iL <(wsws os:linux)
wsws creds -f user > users.txt
```

### Otras funciones

- `wsws show <host>` — ficha completa de un host (servicios, web, hallazgos, creds, notas, validaciones).
- `wsws tag <host|-> dc -revisado` — agrega o quita etiquetas. Con `-` lee los hosts desde stdin: `wsws 88 | wsws tag - dc`.
- `wsws note [host] texto` — guarda notas por host o generales.
- `wsws creds add 'corp\user:Pass' --host 10.0.0.5 --admin` — agrega una credencial a mano. También acepta `corp/user:Pass@10.0.0.5` (impacket) y `user@corp.local:Pass` (UPN). No duplica:
  - Dominio y usuario no distinguen mayúsculas.
  - Un usuario sin secreto se completa cuando llega su secreto.
  - Las credenciales de dominio son una sola aunque se vean en varios hosts.
  - `LM:NT` y `NT` cuentan como el mismo hash.
- `wsws creds mod <ID>` — modifica una credencial (el ID sale en la primera columna de `wsws creds`).
  - Sin más argumentos, pregunta campo por campo: Enter mantiene el valor y `-` lo deja vacío.
  - Directo: `wsws creds mod 3 secret=Nueva --admin host=10.0.0.9`, o `wsws creds mod 3 'corp\user:pass'`. Campos: `domain= user= secret= kind= host= valid=s/n admin=s/n source=`.
  - Si tras el cambio queda igual a otra credencial, ambas se unen bajo el ID editado.
- `wsws creds rm <ID> [<ID>...]` — borra credenciales.
- `wsws domain` — lista los dominios del workspace y sugiere alias cuando detecta un nombre NetBIOS junto a su FQDN.
  - `wsws domain alias CORP corp.local` hace que `CORP\user` y `corp.local\user` sean lo mismo. Une lo ya guardado y normaliza lo que llegue después.
  - `wsws domain rm CORP` quita el alias.
- `wsws reverse <CIDR|IP>` (alias `rdns`, `ptr`) — **DNS inverso (PTR) nativo** sobre un rango (sin ipcalc ni host): resuelve en paralelo y guarda los hostnames en el workspace, fusionándolos con los hosts por IP. Respeta el scope.
  - La **primera vez** en un workspace pregunta si tu DNS apunta al DC del dominio; si no, pides la IP del DNS/DC y la **recuerda para ese workspace** (los PTR internos de AD los resuelve el DC). Cámbiala con `--dns IP|system`.
  - `wsws reverse list` (alias `ls`) muestra los hosts que vinieron del reverse; acepta filtro por red o texto y `-f ip`.
  ```bash
  wsws reverse 10.10.10.0/24              # 1ª vez pregunta por el DNS; luego resuelve y guarda
  wsws 445 | wsws reverse -               # solo los hosts que ya tienen 445 abierto
  wsws reverse list 10.20.0.0/16 -f ip    # IPs resueltas de esa red, para encadenar
  ```
- `wsws scope [add|exclude|rm|check]` — maneja el alcance. El wrapper **bloquea** los objetivos fuera de scope; `wsws --force ...` ejecuta igual y deja la marca.
- `wsws log [id] [--raw]` — línea de tiempo: comando, operador, horas, código de salida, sha256 y archivos.

Cada comando trae su ayuda: `wsws <comando> -h` (o `help`), por ejemplo `wsws vulns -h`, `wsws creds add -h`, `wsws help scope`.

---

## Validar vulnerabilidades conocidas

`wsws check` usa un **motor nativo propio** (sin herramientas de terceros) para validar vulnerabilidades conocidas. **Solo detecta, no explota.** Tiene dos modos:

- **Activo:** una **sonda nativa** (sockets + stdlib) que contacta el objetivo para *detectar*.
- **Pasivo:** razona sobre el recon que WSWS ya guardó (servicios, versiones, SO, hallazgos previos, credenciales), sin tocar la red. Se fuerza con `--passive`. Si una sonda activa falla, cae a pasivo y lo anota en las limitaciones.

| Validador | Valida | Puertos | Sonda activa | Alias |
|---|---|---|---|---|
| `eternalblue` | EternalBlue (CVE-2017-0144) | 445/139 | SMB1 PeekNamedPipe (solo lectura), por defecto | `ms17`, `eb` |
| `doublepulsar` | DoublePulsar (indicador SMB) | 445/139 | — (solo pasivo, por decisión) | `dp`, `pulsar` |
| `bluekeep` | BlueKeep (CVE-2019-0708) | 3389 | negociación RDP/NLA (solo lectura), con `--bluekeep-active` | `bk` |
| `printnightmare` | PrintNightmare (CVE-2021-34527) | 445 | RPC `RpcAddPrinterDriverEx` (opnum 89), necesita credenciales | `pn`, `cve-2021-1675` |

Cada host recibe un **estado normalizado**, que nunca confunde inconcluso con negativo:

`VULNERABLE` · `LIKELY_VULNERABLE` · `NOT_VULNERABLE` · `INCONCLUSIVE` · `NOT_APPLICABLE` · `ERROR`

**Detalle de las sondas activas** (todas de detección, nunca explotación):

- **EternalBlue:** sesión nula SMB1 → `IPC$` → PeekNamedPipe sobre un FID inexistente; lee el `NT_STATUS` (`STATUS_INSUFF_SERVER_RESOURCES` → vulnerable). No modifica el host.
- **BlueKeep:** negociación X.224 para detectar si el host exige NLA/CredSSP y su exposición. **No** ejecuta el check que puede provocar un BSOD (no toca el canal `MS_T120`): esa comprobación destructiva no se implementa a propósito. Es opt-in con `--bluekeep-active`.
- **PrintNightmare:** stack nativo SMB2 (2.1) + NTLMv2 + DCERPC; llama a `RpcAddPrinterDriverEx` con un contenedor de driver **NULL** (sin ruta de DLL/UNC: no puede cargar código) y lee el código de error (`ERROR_INVALID_PARAMETER` → posible; `ACCESS_DENIED` → parcheado). Con credenciales de administrador el resultado es `INCONCLUSIVE` (siempre pasaría). Necesita una credencial de `wsws creds` (usa una cuenta **sin** privilegios para que la prueba sea válida).

> **Nota:** las sondas SMB1/RDP/RPC siguen MS-SMB2/MS-RPRN/MS-NLMP y la criptografía NTLM está validada contra vectores oficiales. La interpretación es conservadora: cualquier respuesta inesperada da `INCONCLUSIVE`, nunca un falso "no vulnerable".

```bash
wsws nmap -p445,3389 10.10.10.0/24             # recon: descubre hosts con esos puertos
wsws check                                     # validadores, objetivos y modo de cada uno
wsws check ms17 10.10.10.0/24                  # sonda ACTIVA MS17-010 contra esos hosts
wsws check ms17 --timeout 3                    # ajusta el timeout por objetivo
wsws check ms17 --passive                      # fuerza solo evaluación del recon
wsws check bluekeep --bluekeep-active          # sonda RDP de solo lectura (NLA), opt-in
wsws check pn --cred 4                         # sonda RPC nativa (o -d corp -u user -p 'Clave')
wsws check all -tag:revisado
wsws show 10.10.10.5                           # sección VALIDACIONES: estado, razón y limitaciones
```

Qué deja cada corrida:

- Respeta el scope: los objetivos fuera se omiten salvo `--force`.
- `VULNERABLE` crea un hallazgo crítico "(validado)" y `LIKELY_VULNERABLE` uno alto "(probable)", ambos con fuente `wsws-validate` y su evidencia (`wsws vulns source:wsws-validate`).
- A cada host le pone la etiqueta `<validador>:<estado>` (`wsws tag:eternalblue:likely_vulnerable -f ip`).
- Guarda una fila por host en `validations` con la razón y las limitaciones del método (`wsws show <host>`).
- Cada corrida queda como evidencia.
- Nuevas vulnerabilidades se agregan como módulos en `wsws/validate/validators/` (o vía el entry point `wsws.validators`) sin tocar el núcleo.

### Checkers externos (legacy)

Los checkers anteriores (nmap NSE, [rdpscan](https://github.com/robertdavidgraham/rdpscan) y el combo de [CesarSilence/PrintNightmare](https://github.com/CesarSilence/PrintNightmare)) siguen disponibles con `--legacy`:

```bash
wsws check --legacy                            # estado de las herramientas externas
wsws check set printnightmare=~/tools/PrintNightmare rdpscan=~/tools/rdpscan/rdpscan
wsws check eternalblue 10.20.30.0/24 --legacy
```

---

## Tests

```bash
python3 -m unittest discover -s tests
```

---

## Roadmap

1. **Servidor compartido**: `wsws serve` con API y Postgres para que varios operadores trabajen sobre el mismo workspace en tiempo real, y el CLI sincronice.
2. **Grafo de ataque**: relaciones credencial → host → sesión → dominio, e ingesta de BloodHound. Responde preguntas como "¿qué puedo alcanzar con estas creds?".
3. **Reporte automático**: exportar la línea de tiempo y la evidencia a la narrativa del informe de Red Team (Word).
4. **Mapeo MITRE ATT&CK** de cada acción y modo de coordinación con el blue team.
5. **Copiloto con IA**: sugiere siguientes pasos a partir del workspace y el operador decide.
6. **Snapshots y diff** entre ejercicios (retest), TUI interactiva con fzf y autocompletado de shell.

---

## Licencia y créditos

MIT (ver [`LICENSE`](LICENSE)). Gracias a **SEK**. Atribuciones y referencias en [`CREDITS.md`](CREDITS.md). Guía completa de uso en [`docs/GUIDE.md`](docs/GUIDE.md).
