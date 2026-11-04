"""PrintNightmare (CVE-2021-34527) — evaluación pasiva + arquitectura de la sonda nativa.

Reemplaza el checker "Combo File" de github.com/CesarSilence/PrintNightmare: aquel recorría un archivo
de objetivos y llamaba a `printnightmare.py -check` con `subprocess` + `shell=True` (delegación en
herramienta externa e inyección de comandos). Aquí la lógica vive en WSWS y la selección de objetivos,
el scope y las credenciales las aporta el motor común.

La evaluación por omisión es pasiva. La comprobación real de PrintNightmare es una llamada RPC
(MS-RPRN `RpcAddPrinterDriverEx`, opnum 89) sobre `\\PIPE\\spoolss`, que es intrusiva (operación de
escritura); por eso queda como punto de extensión (probe()) y no se ejecuta en modo pasivo.

Atribución: la lógica de detección de referencia es de `check()` en printnightmare.py (MIT, © 2021
ly4k); el modo Combo File es del autor de WSWS. Al implementar probe() debe conservarse el aviso MIT.
"""
import struct

from .. import osfp
from ..base import (ERROR, INCONCLUSIVE, LIKELY_VULNERABLE, NOT_APPLICABLE, NOT_VULNERABLE,
                    Evidence, Validator)

# MS-RPRN
RPRN_UUID = "12345678-1234-abcd-ef00-0123456789ab"
OP_ADD_PRINTER_DRIVER_EX = 89
# dwFileCopyFlags: APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY | APD_INSTALL_WARNED_DRIVER
APD_FLAGS = 0x00000004 | 0x00000010 | 0x00008000
# códigos Win32 / RPC relevantes
ERROR_ACCESS_DENIED = 0x00000005
ERROR_INVALID_PARAMETER = 0x00000057
RPC_FAULT_ACCESS_DENIED = 0x00000005


class PrintNightmareChecker(Validator):
    id = "printnightmare"
    cve = "CVE-2021-34527"
    title = "PrintNightmare (CVE-2021-34527)"
    ports = (445,)
    requires_creds = True
    aliases = ("pn", "cve-2021-34527", "cve-2021-1675")
    limitations = (
        "pasivo: la confirmación exige la llamada RPC al spooler (opnum 89), intrusiva; no se hace en pasivo",
        "la lógica de referencia prueba CVE-2021-1675 (control de acceso), no la ruta UNC de CVE-2021-34527",
        "con credenciales de administrador la prueba RPC siempre 'pasaría' (falso positivo): sería INCONCLUSIVE",
    )

    def evaluate_passive(self, asset):
        svc = asset.service_on(*self.ports)
        if not svc:
            return self.result(asset, NOT_APPLICABLE, reason="sin SMB (445) abierto en el Recon")

        osn = osfp.summary(asset, *self.ports)
        if osn and not osfp.is_windows(osn):
            return self.result(asset, NOT_APPLICABLE,
                               reason="el SO observado no es Windows; el spooler MS-RPRN no aplica")

        ev = [Evidence("service", f"445/{svc.get('proto', 'tcp')} SMB abierto",
                       source=svc.get("source", ""), observed=svc.get("last_seen", ""))]
        if osfp.is_windows(osn):
            ev.append(Evidence("os", f"SO Windows: {asset.os}", observed=asset.last_seen))

        lim = []
        if asset.admin_creds():
            lim.append("hay credenciales de administrador: una prueba RPC daría falso positivo (sería INCONCLUSIVE)")
        if not asset.creds:
            lim.append("sin credenciales guardadas para este host; la sonda RPC necesitaría una cuenta de dominio")

        return self.result(asset, INCONCLUSIVE, evidence=ev,
                           reason="SMB en Windows: candidato a PrintNightmare, pero requiere la sonda RPC (no pasiva)",
                           limitations=lim)

    def missing(self, asset):
        need = []
        osn = osfp.summary(asset, *self.ports)
        if not osfp.is_windows(osn):
            need.append("confirmación de que el host es Windows (osmatch o banner SMB)")
        if not asset.creds:
            need.append("una credencial de dominio en `wsws creds` para autenticar la sonda RPC")
        need.append("estado del servicio Spooler (solo observable con la comprobación RPC activa)")
        return need

    @staticmethod
    def _stub():
        """Stub NDR de RpcAddPrinterDriverEx con DRIVER_CONTAINER nivel 2 y todo NULL (solo detección).

        No contiene ruta de DLL ni UNC: no puede cargar código, solo provoca la validación de parámetros
        del spooler para leer su código de error. Unión no encapsulada (switch_is(Level)): el discriminante
        no se repite.
        """
        return struct.pack("<IIIIIIIIII",
                           0,            # pName: puntero unique NULL
                           2,            # DRIVER_CONTAINER.Level = 2
                           0x00020000,   # Level2: referente unique no nulo
                           0,            # DRIVER_INFO_2.cVersion
                           0, 0, 0, 0, 0,  # pName, pEnvironment, pDriverPath, pDataFile, pConfigFile = NULL
                           APD_FLAGS)    # dwFileCopyFlags

    def probe(self, asset, ctx=None):
        """Sonda RPC nativa: RpcAddPrinterDriverEx (opnum 89) con contenedor NULL. Necesita credenciales.

        Interpreta el resultado como la lógica de referencia (check() de printnightmare.py, MIT ly4k):
        ERROR_INVALID_PARAMETER -> el control de acceso dejó pasar a un no-admin (posible). ACCESS_DENIED
        -> parcheado. Con credenciales de administrador el resultado es INCONCLUSIVE (siempre pasaría).
        """
        from ..net import dcerpc
        from ..net.smb2 import SMB2Client, SMB2Error

        ctx = ctx or {}
        creds = ctx.get("creds")
        if not creds:
            return self.result(asset, INCONCLUSIVE, method="native-probe",
                               reason="la sonda RPC necesita credenciales: --cred <ID> o -d/-u/-p",
                               limitations=["sin credenciales no se puede autenticar contra el spooler"])
        domain, user, secret = creds
        is_hash = bool(ctx.get("is_hash"))
        timeout = float(ctx.get("timeout", 5.0))

        if any(c.get("admin") and c.get("valid") for c in asset.creds):
            # un admin siempre puede instalar drivers -> la prueba no distingue parcheado de vulnerable
            return self.result(asset, INCONCLUSIVE, method="native-probe",
                               reason="credenciales de administrador: la prueba RPC daría falso positivo",
                               limitations=["usar una cuenta SIN privilegios para que la comprobación sea válida"])

        ev = [Evidence("probe", f"RPC RpcAddPrinterDriverEx(NULL) en \\PIPE\\spoolss ({asset.addr})",
                       source="wsws-probe")]
        try:
            with SMB2Client(asset.addr, 445, timeout) as c:
                c.negotiate()
                c.session_setup(domain or ".", user, secret, is_hash=is_hash)
                c.tree_connect("IPC$")
                fid = c.create_pipe("spoolss")
                c.ioctl_transceive(fid, dcerpc.build_bind(RPRN_UUID, 1, 0))
                resp = c.ioctl_transceive(fid, dcerpc.build_request(OP_ADD_PRINTER_DRIVER_EX, self._stub()))
        except SMB2Error as e:
            status = INCONCLUSIVE if e.status in (0xC000006D, 0xC0000022) else ERROR
            res = self.result(asset, status, method="native-probe",
                              reason=f"no se completó la sonda RPC: {e}", evidence=ev)
            if status == ERROR:
                res.error = str(e)
            return res
        except OSError as e:
            res = self.result(asset, ERROR, method="native-probe",
                              reason=f"conexión fallida: {e}", evidence=ev)
            res.error = str(e)
            return res

        parsed = dcerpc.parse(resp)
        code = parsed.get("ret") if parsed.get("ptype") == dcerpc.PT_RESPONSE else parsed.get("fault")
        ev.append(Evidence("probe", f"respuesta DCERPC ptype={parsed.get('ptype')} code=0x{(code or 0):08X}",
                           source="wsws-probe"))
        if code == ERROR_INVALID_PARAMETER:
            return self.result(asset, LIKELY_VULNERABLE, method="native-probe", evidence=ev,
                               reason="el spooler aceptó la operación de un no-admin (patrón de CVE-2021-1675)",
                               limitations=["confirma el control de acceso (1675), no la ruta UNC de 34527"])
        if code in (ERROR_ACCESS_DENIED, RPC_FAULT_ACCESS_DENIED):
            return self.result(asset, NOT_VULNERABLE, method="native-probe", evidence=ev,
                               reason="el spooler denegó el acceso: patrón de un sistema parcheado")
        return self.result(asset, INCONCLUSIVE, method="native-probe", evidence=ev,
                           reason=f"respuesta RPC no concluyente (code=0x{(code or 0):08X})")
