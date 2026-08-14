"""
Módulo: windows_remote
Conexión WinRM a equipos Windows — análisis completo vía PowerShell
"""

import winrm
import json
import re
from datetime import datetime

# Puerto WinRM por defecto
WINRM_PORT_HTTP  = 5985
WINRM_PORT_HTTPS = 5986


def _get_session(server):
    """Crear sesión WinRM"""
    from modules.credential_manager import decrypt_server
    server = decrypt_server(server)
    protocol = "https" if server.get("use_ssl") else "http"
    port     = server.get("port", WINRM_PORT_HTTP)
    return winrm.Session(
        f"{protocol}://{server['host']}:{port}/wsman",
        auth=(server["username"], server["password"]),
        transport="ntlm",
        server_cert_validation="ignore"
    )


def _ps(session, script, timeout=15):
    """Ejecutar PowerShell y devolver stdout"""
    try:
        result = session.run_ps(script)
        out = result.std_out.decode("utf-8", errors="replace").strip()
        err = result.std_err.decode("utf-8", errors="replace").strip()
        return out or err
    except Exception as e:
        return ""


def test_connection(server):
    """Probar conexión WinRM"""
    try:
        session = _get_session(server)
        result  = _ps(session, "echo OK")
        if "OK" in result:
            return True, "Conexión WinRM exitosa"
        return False, "Conexión establecida pero sin respuesta"
    except winrm.exceptions.AuthenticationError:
        return False, "Error de autenticación — verificar usuario/contraseña"
    except Exception as e:
        return False, str(e)[:100]


def get_windows_stats(server):
    """Recopila datos completos del equipo Windows vía WinRM/PowerShell"""
    result = {
        "server_id":   server["id"],
        "server_name": server["name"],
        "host":        server["host"],
        "port":        server["port"],
        "os_type":     "windows",
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "connected":   False,
        "error":       None
    }

    try:
        session = _get_session(server)
        result["connected"] = True

        # ── GENERAL ───────────────────────────────────────────────────────────
        # Hostname y OS
        result["hostname"] = _ps(session, "$env:COMPUTERNAME")
        result["os"]       = _ps(session, "(Get-WmiObject Win32_OperatingSystem).Caption")
        result["kernel"]   = _ps(session, "(Get-WmiObject Win32_OperatingSystem).Version")
        result["ip"]       = _ps(session, "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*'} | Select-Object -First 1).IPAddress")

        # Uptime
        uptime_raw = _ps(session, """
$os = Get-WmiObject Win32_OperatingSystem
$uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)
"$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
""")
        result["uptime"] = uptime_raw or "N/A"

        # CPU
        cpu_raw = _ps(session, "(Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average")
        result["cpu_usage"] = (cpu_raw + "%") if cpu_raw else "N/A"
        result["cpu_cores"] = _ps(session, "(Get-WmiObject Win32_Processor).NumberOfLogicalProcessors")

        # Memoria
        mem_raw = _ps(session, """
$os = Get-WmiObject Win32_OperatingSystem
$total = [math]::Round($os.TotalVisibleMemorySize / 1024)
$free  = [math]::Round($os.FreePhysicalMemory / 1024)
$used  = $total - $free
"$total $used"
""")
        if mem_raw:
            parts = mem_raw.split()
            if len(parts) == 2:
                total, used = int(parts[0]), int(parts[1])
                result["mem_total"] = f"{total} MB"
                result["mem_used"]  = f"{used} MB"
                result["mem_pct"]   = round((used / total) * 100, 1) if total else 0
            else:
                result["mem_total"] = result["mem_used"] = "N/A"
                result["mem_pct"] = 0
        else:
            result["mem_total"] = result["mem_used"] = "N/A"
            result["mem_pct"] = 0

        # Disco C:
        disk_raw = _ps(session, """
$disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
$total = [math]::Round($disk.Size / 1GB, 1)
$free  = [math]::Round($disk.FreeSpace / 1GB, 1)
$used  = [math]::Round($total - $free, 1)
$pct   = [math]::Round((($total - $free) / $total) * 100)
"$($total)G $($used)G $pct"
""")
        if disk_raw:
            parts = disk_raw.split()
            if len(parts) == 3:
                result["disk_total"] = parts[0]
                result["disk_used"]  = parts[1]
                result["disk_pct"]   = int(parts[2])
            else:
                result["disk_total"] = result["disk_used"] = "N/A"
                result["disk_pct"] = 0
        else:
            result["disk_total"] = result["disk_used"] = "N/A"
            result["disk_pct"] = 0

        # Procesos
        result["procs"] = _ps(session, "(Get-Process).Count")
        result["load_1"] = result["load_5"] = result["load_15"] = "N/A"

        # Servicios críticos
        svcs_to_check = [
            "wuauserv", "WinDefend", "MpsSvc", "EventLog",
            "W32Time", "Spooler", "wuauserv", "MSSQLSERVER",
            "W3SVC", "RpcSs", "LanmanServer"
        ]
        services = []
        for svc in svcs_to_check:
            status = _ps(session, f"(Get-Service -Name '{svc}' -ErrorAction SilentlyContinue).Status")
            if status:
                services.append({
                    "name": svc,
                    "status": status.lower(),
                    "ok": "running" in status.lower()
                })
        result["services"] = services

        # Últimos eventos de seguridad
        last_logins_raw = _ps(session, """
Get-WinEvent -LogName Security -MaxEvents 5 -FilterXPath "*[System[EventID=4624]]" |
Select-Object TimeCreated, Message |
ForEach-Object { "$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm')) - Login exitoso" }
""")
        result["last_logins"] = last_logins_raw.splitlines()[:5] if last_logins_raw else []

        # ── SEGURIDAD ─────────────────────────────────────────────────────────
        security = {}

        # Windows Defender
        defender_raw = _ps(session, """
try {
  $def = Get-MpComputerStatus
  "$($def.RealTimeProtectionEnabled) $($def.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd'))"
} catch { "unavailable" }
""")
        if "unavailable" not in defender_raw and defender_raw:
            parts = defender_raw.split()
            security["defender_enabled"] = parts[0].lower() == "true"
            security["defender_updated"] = parts[1] if len(parts) > 1 else "?"
        else:
            security["defender_enabled"] = False
            security["defender_updated"] = "N/A"

        # Windows Firewall
        fw_raw = _ps(session, """
$fw = Get-NetFirewallProfile | Select-Object Name, Enabled
$fw | ForEach-Object { "$($_.Name):$($_.Enabled)" }
""")
        fw_profiles = {}
        for line in (fw_raw or "").splitlines():
            if ":" in line:
                name, enabled = line.split(":", 1)
                fw_profiles[name.strip()] = enabled.strip().lower() == "true"
        security["firewall_profiles"] = fw_profiles
        security["ufw_active"] = any(fw_profiles.values())
        security["ufw_output"] = fw_raw or "Sin datos de firewall"

        # Windows Update pendientes
        updates_raw = _ps(session, """
try {
  $wu = New-Object -ComObject Microsoft.Update.Session
  $searcher = $wu.CreateUpdateSearcher()
  $results = $searcher.Search("IsInstalled=0 and Type='Software'")
  $results.Updates.Count
} catch { "0" }
""")
        try:
            security["pending_updates"] = int(updates_raw.strip())
        except ValueError:
            security["pending_updates"] = 0

        # RDP habilitado
        rdp_raw = _ps(session, "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections")
        security["rdp_enabled"] = rdp_raw.strip() == "0"

        # UAC habilitado
        uac_raw = _ps(session, "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA")
        security["uac_enabled"] = uac_raw.strip() == "1"

        # SMBv1 (peligroso)
        smb1_raw = _ps(session, """
try {
  (Get-SmbServerConfiguration).EnableSMB1Protocol
} catch { "False" }
""")
        security["smb1_enabled"] = smb1_raw.strip().lower() == "true"

        # Chequeos de seguridad
        ssh_checks = []
        ssh_checks.append({
            "name": "Windows Defender activo",
            "ok": security["defender_enabled"],
            "rec": "Habilitar Windows Defender / antivirus"
        })
        ssh_checks.append({
            "name": "Firewall Windows activo",
            "ok": security["ufw_active"],
            "rec": "Habilitar Windows Firewall en todos los perfiles"
        })
        ssh_checks.append({
            "name": "UAC habilitado",
            "ok": security["uac_enabled"],
            "rec": "Habilitar Control de Cuentas de Usuario (UAC)"
        })
        ssh_checks.append({
            "name": "SMBv1 deshabilitado",
            "ok": not security["smb1_enabled"],
            "rec": "Deshabilitar SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
        })
        ssh_checks.append({
            "name": "RDP protegido",
            "ok": not security["rdp_enabled"],
            "rec": "Deshabilitar RDP si no es necesario o proteger con NLA"
        })
        security["ssh_checks"] = ssh_checks

        # Score
        score = 100
        if not security["defender_enabled"]:  score -= 25
        if not security["ufw_active"]:        score -= 20
        if not security["uac_enabled"]:       score -= 15
        if security["smb1_enabled"]:          score -= 20
        if security["rdp_enabled"]:           score -= 10
        if security["pending_updates"] > 5:   score -= 10
        security["score"] = max(score, 0)
        security["fail2ban_active"] = False
        security["fail2ban_status"] = "No aplica en Windows"
        security["selinux"] = "No aplica en Windows"
        security["selinux_enforcing"] = False
        security["apparmor"] = "No aplica en Windows"
        security["sysctl_checks"] = []
        security["suid_files"] = []
        security["firewalld_active"] = False
        security["iptables"] = "No aplica en Windows"
        security["ssh_config_raw"] = "WinRM/RDP — no SSH"

        result["security"]         = security
        result["ufw_active"]       = security["ufw_active"]
        result["firewalld_active"] = False
        result["ssh_root_login"]   = False
        result["fail2ban_active"]  = False
        result["security_score"]   = security["score"]
        result["pending_updates"]  = security["pending_updates"]

        # ── CROWDSEC ──────────────────────────────────────────────────────────
        cs_raw = _ps(session, "cscli version 2>$null")
        crowdsec = {
            "available": bool(cs_raw) and "not found" not in cs_raw.lower(),
            "version": cs_raw if cs_raw else "No instalado en Windows",
            "service_active": False,
            "service_status": "unknown",
            "decisions": [], "decisions_count": 0,
            "alerts": [],    "alerts_count": 0,
            "bouncers": [],  "hub_raw": "",
            "recent_logs": [],
            "install_hint": "Descargar desde https://github.com/crowdsecurity/crowdsec/releases"
        }
        result["crowdsec"]        = crowdsec
        result["crowdsec_active"] = crowdsec["service_active"]

        # ── USUARIOS ──────────────────────────────────────────────────────────
        users_data = {}

        # Usuarios locales
        users_raw = _ps(session, """
Get-LocalUser | Select-Object Name, Enabled, LastLogon |
ForEach-Object {
  $logon = if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd') } else { 'Nunca' }
  "$($_.Name)|$($_.Enabled)|$logon"
}
""")
        real_users = []
        for line in (users_raw or "").splitlines():
            parts = line.split("|")
            if len(parts) >= 3:
                real_users.append({
                    "username": parts[0],
                    "uid": "N/A",
                    "home": f"C:\\Users\\{parts[0]}",
                    "shell": "PowerShell",
                    "can_login": parts[1].lower() == "true",
                    "is_root": parts[0].lower() in ["administrator", "admin"]
                })
        users_data["real_users"] = real_users

        # Administradores locales
        admins_raw = _ps(session, "Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name")
        admin_list = [a.split("\\")[-1] for a in (admins_raw or "").splitlines() if a.strip()]
        users_data["sudo_users"] = admin_list
        users_data["uid0_users"] = admin_list
        users_data["uid0_warning"] = len(admin_list) > 2
        users_data["passwd_status"] = []
        users_data["lastlog"] = []

        # Grupos críticos
        crit_groups = []
        for grp in ["Administrators", "Remote Desktop Users", "Power Users", "Backup Operators"]:
            members_raw = _ps(session, f"(Get-LocalGroupMember -Group '{grp}' -ErrorAction SilentlyContinue).Name")
            members = [m.split("\\")[-1] for m in (members_raw or "").splitlines() if m.strip()]
            crit_groups.append({
                "name": grp,
                "gid": "N/A",
                "members": members,
                "count": len(members)
            })
        users_data["critical_groups"] = crit_groups

        user_checks = []
        user_checks.append({
            "name": "Administradores locales",
            "ok": len(admin_list) <= 2,
            "detail": f"Administradores: {', '.join(admin_list)}",
            "severity": "warn" if len(admin_list) > 2 else "ok"
        })
        users_data["security_checks"] = user_checks
        result["users"] = users_data

        # ── PUERTOS ───────────────────────────────────────────────────────────
        ports_data = {}
        DANGEROUS = {21,23,135,139,445,3389,5900,6379,9200,27017,4444,1433}
        KNOWN = {
            21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
            80:"HTTP", 110:"POP3", 135:"RPC", 139:"NetBIOS",
            143:"IMAP", 389:"LDAP", 443:"HTTPS", 445:"SMB",
            1433:"MSSQL", 3389:"RDP", 5985:"WinRM-HTTP",
            5986:"WinRM-HTTPS", 8080:"HTTP-Alt"
        }

        ports_raw = _ps(session, """
Get-NetTCPConnection -State Listen |
Select-Object LocalAddress, LocalPort |
Sort-Object LocalPort -Unique |
ForEach-Object { "$($_.LocalAddress) $($_.LocalPort)" }
""")
        listening = []
        seen = set()
        for line in (ports_raw or "").splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                port = int(parts[1])
            except ValueError:
                continue
            if port in seen:
                continue
            seen.add(port)
            addr = parts[0]
            is_public = addr in ["0.0.0.0", "::", "*", ""]
            is_dangerous = port in DANGEROUS
            service = KNOWN.get(port, "Unknown")
            if is_dangerous and is_public:
                risk = "danger"
            elif is_dangerous:
                risk = "warn"
            elif port in KNOWN:
                risk = "ok"
            else:
                risk = "info"
            listening.append({
                "port": port, "addr": addr,
                "service": service, "process": "?",
                "public": is_public, "dangerous": is_dangerous,
                "risk": risk
            })

        listening.sort(key=lambda x: x["port"])
        ports_data["listening"] = listening
        ports_data["count_total"]     = len(listening)
        ports_data["count_dangerous"] = len([p for p in listening if p["dangerous"]])
        ports_data["count_public"]    = len([p for p in listening if p["public"]])

        recommendations = []
        for p in listening:
            if p["dangerous"] and p["public"]:
                recommendations.append({
                    "port": p["port"], "service": p["service"],
                    "message": f"Puerto {p['port']} ({p['service']}) expuesto — revisar necesidad",
                    "severity": "danger"
                })
        ports_data["recommendations"] = recommendations
        ports_data["connections"] = []
        result["ports"]      = ports_data
        result["open_ports"] = [str(p["port"]) for p in listening]

    except Exception as e:
        result["connected"] = False
        result["error"]     = str(e)[:120]

    return result
