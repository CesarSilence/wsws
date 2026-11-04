"""Ayuda por comando: `wsws <comando> -h`, `wsws <comando> help` o `wsws help <comando>`."""

FILTERS = """\
FILTROS (se combinan con AND; -término o `not término` niega)
  445  22,80  8000-8100        puertos
  10.0.0.5  10.0.0.0/24        IP o red
  svc:smb  product:apache      servicio / versión  (svc:smb|rdp|winrm|mssql|ldap|dns… incluye nombres de nmap)
  proto:udp  state:filtered    protocolo / estado del puerto
  os:windows  host:dc01        sistema operativo / IP o hostname
  domain:corp  tag:dc          dominio / etiqueta
  sev:high  vuln:ms17          severidad (high = high o mayor) / texto en hallazgos
  title:login  tech:iis  url:admin   web
  user:admin  source:nxc       credenciales / herramienta de origen
  has:admin|creds|vuln|web|notes     que exista algo asociado al host
  new:30m|2h|3d|1w|2026-10-19        visto por primera vez desde
  scope:in|out                       dentro / fuera del alcance
  cualquier otra palabra             texto libre (banners, NSE, títulos, hallazgos, notas)"""

OPTS = """\
OPCIONES
  -f, --format FMT   formato de salida (ver abajo)
  -n, --limit N      máximo de filas
  -j, --json         igual que -f json"""


def _fmt(rows, pipe_default):
    w = max(len(k) for k, _ in rows)
    lines = [f"  {k.ljust(w)}  {v}" for k, v in rows]
    return "FORMATOS (-f)\n" + "\n".join(lines) + f"\n  Sin -f: table en la terminal, {pipe_default} cuando la salida va a un pipe."


DATA = [("json", "todo en JSON (lista)"), ("jsonl", "un JSON por línea"), ("csv", "CSV con encabezados")]

FMT_FIND = _fmt([("table", "tabla: IP, puerto, servicio, versión, hostname, OS, flags"),
       ("ip", "solo IPs, una por línea"), ("hp", "ip:puerto"), ("url", "URLs de los servicios web"),
       ("ports", "lista de puertos separada por comas (para nmap -p)")] + DATA, "ip")
FMT_HOSTS = _fmt([("table", "tabla: IP, hostnames, OS, puertos, flags"), ("ip", "solo IPs")] + DATA, "ip")
FMT_VULNS = _fmt([("table", "tabla: severidad, IP, puerto, hallazgo, referencia, fuente"),
       ("ip", "IPs afectadas"), ("hp", "ubicación afectada (URL o ip:puerto)"), ("url", "igual que hp")] + DATA, "table")
FMT_WEB = _fmt([("table", "tabla: estado, URL, título, tecnologías, servidor"), ("url", "solo URLs"),
       ("ip", "IPs de los sitios")] + DATA, "url")
FMT_CREDS = _fmt([("table", "tabla: ID, host, usuario, secreto, tipo, estado, fuente"),
       ("cred", "dominio\\usuario:secreto"), ("user", "solo usuarios"), ("secret", "solo secretos"),
       ("ip", "IPs donde se vio la credencial")] + DATA, "cred")

HELP = {
    "find": f"""\
wsws find|f|services|svc [filtros...] [opciones]     (atajo: wsws <filtros...>)
Busca servicios (una fila por host:puerto).

{OPTS}
  -a, --all          incluye puertos cerrados/filtrados

{FMT_FIND}

{FILTERS}

EJEMPLOS
  wsws 445 os:windows
  wsws svc:smb -tag:revisado -f ip | nxc smb - -u user -p pass
  nmap -sV -p $(wsws os:linux -f ports) -iL <(wsws os:linux)
  wsws svc:http -f url | nuclei -l -""",

    "hosts": f"""\
wsws hosts|h [filtros...] [opciones]
Lista hosts (una fila por host, con sus puertos).

{OPTS}
  -a, --all          incluye puertos cerrados/filtrados

{FMT_HOSTS}

{FILTERS}

EJEMPLOS
  wsws hosts os:windows 10.20.0.0/16
  wsws hosts has:vuln -f ip > con_vulns.txt
  wsws hosts new:2h""",

    "vulns": f"""\
wsws vulns|v|findings [filtros...] [opciones]
Lista hallazgos (nmap NSE, nuclei, nxc, Nessus), de mayor a menor severidad.

{OPTS}

{FMT_VULNS}

Severidades: info, low, medium (med), high, critical (crit). sev:X significa "X o mayor".

{FILTERS}

EJEMPLOS
  wsws vulns sev:critical
  wsws vulns sev:high 10.20.0.0/16
  wsws vulns cve:2021            (cve: es igual que vuln:)
  wsws vulns source:nuclei -f csv > hallazgos.csv
  wsws vulns sev:medium -f hp""",

    "web": f"""\
wsws web|w [filtros...] [opciones]
Lista sitios web (httpx, nuclei): estado, título, tecnologías y servidor.

{OPTS}

{FMT_WEB}

{FILTERS}

EJEMPLOS
  wsws web tech:iis
  wsws web title:login -f url | nuclei -l -
  wsws web 172.16.5.0/24 -f table""",

    "creds": f"""\
wsws creds|c [filtros...] [opciones]         listar
wsws creds add <cred> [--host ip] [--admin] [--hash] [--invalid]
wsws creds mod <ID> [campo=valor...]          modificar (sin campos = interactivo)
wsws creds rm <ID> [<ID>...]                  borrar
Ayuda de cada subcomando: wsws creds add -h  ·  wsws creds mod -h  ·  wsws creds rm -h

{OPTS}

{FMT_CREDS}

{FILTERS}

EJEMPLOS
  wsws creds
  wsws creds domain:corp -f user > users.txt
  wsws creds has:admin
  wsws creds user:svc_""",

    "creds add": """\
wsws creds add <cred> [--host ip] [--admin] [--hash] [--invalid]
Agrega una credencial a mano. Si ya existe, la actualiza (no duplica).

FORMATOS DE <cred>
  corp\\usuario:Clave           dominio\\usuario (con comillas: 'corp\\usuario:Clave')
  corp/usuario:Clave@10.0.0.5  estilo impacket, con host opcional
  usuario@corp.local:Clave     UPN
  usuario:Clave                local, sin dominio
  usuario                      solo usuario (el secreto se completa después)

OPCIONES
  --host IP     asocia la credencial a un host
  --admin       marca que es administrador en ese host
  --hash        el secreto es un hash (se detecta solo si es LM:NT o NT)
  --invalid     la credencial no es válida

EJEMPLOS
  wsws creds add 'corp\\usuario:Clave' --host 10.20.11.12 --admin
  wsws creds add 'usuario@corp.local:Clave'""",

    "creds mod": """\
wsws creds mod <ID>                        interactivo: Enter mantiene, '-' deja vacío
wsws creds mod <ID> campo=valor [...]      directo
wsws creds mod <ID> 'corp\\usuario:Clave'   reemplaza dominio, usuario y secreto
El ID sale en la primera columna de `wsws creds`. Si queda igual a otra credencial, se unen.

CAMPOS
  domain=  user=  secret=  kind=  host=  valid=s/n  admin=s/n  source=

FLAGS
  --admin  --no-admin  --valid  --invalid  --hash

EJEMPLOS
  wsws creds mod 3
  wsws creds mod 3 secret=Nueva --admin host=10.0.0.9""",

    "creds rm": """\
wsws creds rm <ID> [<ID>...]
Borra credenciales. El ID sale en la primera columna de `wsws creds`.

EJEMPLO
  wsws creds rm 3 7""",

    "show": """\
wsws show|info <ip|hostname>
Ficha completa de un host: servicios, web, hallazgos, credenciales, notas y línea de tiempo.
Acepta parte del nombre; si coincide con varios hosts, los lista.

EJEMPLOS
  wsws show 10.20.10.14
  wsws show dc01""",

    "add": """\
wsws add|import [archivo...] [-q]
<herramienta> | wsws                   (sin argumentos lee desde el pipe)
Importa salidas de herramientas. El formato se detecta solo y el original se guarda como evidencia.

FORMATOS RECONOCIDOS
  nmap (normal, -oX, -oG), masscan, naabu, rustscan, httpx (JSON y texto),
  nuclei (JSONL y texto), nxc/netexec/crackmapexec, Nessus (.nessus), listas de IP / ip:puerto / URL

OPCIONES
  -q    no repetir en pantalla lo que llega por el pipe

EJEMPLOS
  wsws add scan.xml resultado.nessus nuclei.jsonl
  httpx -l hosts.txt -json | wsws""",

    "run": """\
wsws run -- <comando> [args]
wsws <nmap|masscan|naabu|rustscan|httpx|nuclei|nxc|netexec|crackmapexec> [args]
wsws sudo <herramienta> [args]
Ejecuta la herramienta: ves su salida normal y wsws guarda resultados y evidencia.
  - valida el scope antes de ejecutar (fuera de scope: se bloquea, salvo wsws --force ...)
  - nmap: agrega -oX por detrás · nuclei: agrega -jle por detrás
  - guarda log, archivos, sha256, operador, horas y código de salida (ver: wsws log)

EJEMPLOS
  wsws nmap -sV -p- 10.0.0.5
  wsws sudo nmap -sS 10.0.0.0/24
  wsws nxc smb 10.0.0.0/24 -u user -p pass
  wsws run -- ./mi_script.sh 10.0.0.5""",

    "use": """\
wsws use [nombre]
Crea (si no existe) y activa un workspace. Sin nombre muestra el activo.
Para un solo comando en otro workspace: wsws -w <nombre> ...  o  WSWS=<nombre> wsws ...""",

    "ls": """\
wsws ls
Lista los workspaces con hosts, servicios, vulns, creds y última actividad. El activo tiene *.""",

    "rm": """\
wsws rm <workspace>
Borra un workspace con toda su evidencia. Pide escribir el nombre para confirmar.""",

    "tag": """\
wsws tag <ip|hostname|-> tag1 [tag2...] [-tag_a_quitar]
Agrega o quita etiquetas. Con '-' lee los hosts desde el pipe.

EJEMPLOS
  wsws tag 10.20.10.14 dc
  wsws 88 | wsws tag - dc
  wsws tag 10.0.0.5 revisado -pendiente
  wsws tag:dc                     (buscar por etiqueta)""",

    "note": """\
wsws note|n                       lista todas las notas
wsws note <ip|hostname> texto     nota en un host
wsws note texto                   nota general

EJEMPLO
  wsws note 10.20.10.14 revisar delegación""",

    "scope": """\
wsws scope [ls]                   muestra el alcance y avisa de hosts fuera
wsws scope add <valores...>       incluye
wsws scope exclude <valores...>   excluye
wsws scope rm <valores...>        quita reglas
wsws scope check <valores...>     dice si están en scope
Valores: IP, CIDR, dominio o *.dominio. También se pueden pasar por pipe.
El wrapper bloquea objetivos fuera de scope (wsws --force ... para ejecutar igual).

EJEMPLOS
  wsws scope add 10.20.0.0/16 '*.corp.local'
  wsws scope exclude 10.20.10.1
  wsws scope:out                  (buscar hosts fuera de scope)""",

    "domain": """\
wsws domain|dom [ls]                     dominios del workspace (sugiere alias NetBIOS ↔ FQDN)
wsws domain alias <alias> <canónico>     CORP y corp.local pasan a ser lo mismo
wsws domain rm <alias>                   quita el alias

EJEMPLO
  wsws domain alias CORP corp.local""",

    "reverse": """\
wsws reverse|rdns|ptr <CIDR|IP> [...] [opciones]
wsws reverse list [filtro] [-f ip]        lista lo que YA resolvió el reverse (filtro: CIDR o texto)
Resolución DNS inversa (PTR) nativa sobre un rango, sin ipcalc ni host. Recorre las IPs usables del
CIDR, resuelve el nombre de cada una en paralelo y GUARDA los hostnames en el workspace (se fusionan
con los hosts por IP). Respeta el scope: las IPs fuera se omiten salvo --force.

La PRIMERA vez en un workspace pregunta si tu DNS apunta al DC del dominio; si no, pide la IP del
DNS/DC y la recuerda para ese workspace (en AD, los PTR internos los resuelve el DC). Cámbiala cuando
quieras con --dns.

OPCIONES
  --threads N | -t N   hilos de resolución (def. 64)
  --timeout N          timeout por consulta en segundos (def. 2)
  --dns IP|system      DNS a usar y guardar en el workspace (IP del DC, o 'system' = resolver local)
  --no-save | -n       solo muestra, no ingiere
  --force              incluye IPs fuera de scope

OBJETIVOS
  uno o más CIDR/IP, o '-' para leerlos de stdin (una IP por línea)

EJEMPLOS
  wsws reverse 10.10.10.0/24
  wsws reverse 10.0.0.0/24 192.168.1.0/24 -t 128
  wsws reverse 10.10.10.0/24 --dns 10.10.10.1   usa (y guarda) el DC como DNS
  wsws reverse 10.10.10.0/24 --dns system       vuelve al resolver del sistema
  wsws 445 | wsws reverse -            resuelve el PTR de los hosts con 445 abierto
  wsws reverse 10.10.10.0/24 -n        solo listar, sin guardar
  wsws reverse list                    todo lo resuelto en el workspace
  wsws reverse list 10.20.0.0/16       filtra por red
  wsws reverse list sql -f ip          IPs cuyo PTR contiene 'sql'""",

    "log": """\
wsws log|timeline|ev [-n N]       línea de tiempo (últimas N, por defecto 30)
wsws log <id> [--raw]             detalle de una evidencia; --raw imprime la salida completa""",

    "check": """\
wsws check                                   validadores disponibles y objetivos en el workspace
wsws check <validador>[,<validador>|all] [filtros] [opciones]
Motor NATIVO propio (sin herramientas de terceros). Dos modos:
  activo   sonda nativa (sockets+stdlib) que contacta el objetivo para DETECTAR (no explota).
  pasivo   razona sobre el recon guardado (servicios, versiones, SO, hallazgos, creds) sin tocar
           la red. Se fuerza con --passive.
Toma como objetivos los hosts con el puerto abierto (más tus filtros), respeta el scope y guarda
por host una fila en `validations` (ver wsws show <host>), además de:
  - VULNERABLE       → hallazgo crítico "(validado)", fuente wsws-validate, con evidencia
  - LIKELY_VULNERABLE→ hallazgo alto "(probable)"
  - etiqueta por host: <validador>:<estado en minúsculas>

ESTADOS
  VULNERABLE · LIKELY_VULNERABLE · NOT_VULNERABLE · INCONCLUSIVE · NOT_APPLICABLE · ERROR
  (inconcluso NO es negativo: se distinguen a propósito)

VALIDADORES
  eternalblue     EternalBlue (CVE-2017-0144)      445/139  sonda SMB1 (solo lectura)   (ms17, eb)
  doublepulsar    DoublePulsar (indicador SMB)     445/139  solo pasivo (por decisión)  (dp)
  bluekeep        BlueKeep (CVE-2019-0708)         3389     sonda RDP/NLA con --bluekeep-active (bk)
  printnightmare  PrintNightmare (CVE-2021-34527)  445      sonda RPC, necesita creds   (pn)
  all             todos

OPCIONES
  --dry-run        muestra los objetivos sin sondear
  --passive        fuerza solo evaluación del recon (no contacta la red)
  --timeout N      segundos por objetivo en la sonda activa (def. 5)
  --bluekeep-active   habilita la sonda RDP de BlueKeep (solo lectura; NO el check que puede crashear)
  --cred ID / -d -u -p   credenciales para la sonda RPC de PrintNightmare
  --force          incluye objetivos fuera de scope
  --legacy         usa los checkers externos antiguos (nmap NSE / rdpscan / combo PrintNightmare)

FILTROS
  los mismos de wsws find (wsws find -h): red, os:, tag:, host:, -tag:revisado...

EJEMPLOS
  wsws check
  wsws check ms17 10.10.10.0/24            sonda activa MS17-010 sobre los hosts del recon
  wsws check ms17 --timeout 3
  wsws check eternalblue 10.20.30.0/24 --dry-run
  wsws check bluekeep os:windows
  wsws check all -tag:revisado
  wsws vulns source:wsws-validate          resultados del motor nativo
  wsws tag:eternalblue:vulnerable -f ip    hosts vulnerables""",

    "stats": """\
wsws stats|status        (o wsws sin argumentos)
Resumen del workspace activo: conteos, scope, puertos más vistos y últimas acciones.""",
}

ALIASES = {
    "f": "find", "services": "find", "svc": "find", "h": "hosts", "v": "vulns", "findings": "vulns",
    "w": "web", "c": "creds", "info": "show", "import": "add", "n": "note", "domains": "domain",
    "dom": "domain", "chk": "check", "timeline": "log", "ev": "log", "status": "stats",
    "rdns": "reverse", "ptr": "reverse",
    "creds edit": "creds mod", "creds del": "creds rm",
}


def get(name):
    """Texto de ayuda de un comando (acepta alias y 'creds add'), o None."""
    name = " ".join(name.split()).lower()
    if name.startswith("c "):
        name = "creds " + name[2:]
    return HELP.get(ALIASES.get(name, name))
