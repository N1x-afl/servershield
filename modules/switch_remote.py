"""
Módulo: switch_remote
Análisis de hardening para switches via SSH — Multi-vendor
Soporta: Cisco IOS/IOS-XE, HP/Aruba, MikroTik, Juniper
"""

import paramiko
import socket
import re
from datetime import datetime


def _get_client(server):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": server["host"],
        "port":     server["port"],
        "username": server["username"],
        "timeout":  10,
        "banner_timeout": 15,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if server["auth_type"] == "key" and server.get("key_path"):
        kwargs["key_filename"] = server["key_path"]
    else:
        kwargs["password"] = server.get("password", "")
    client.connect(**kwargs)
    return client


def _run_cmd(shell, cmd, wait=1.5):
    """Ejecutar comando en shell interactivo y devolver output"""
    import time
    shell.send(cmd + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        chunk = shell.recv(4096).decode("utf-8", errors="replace")
        output += chunk
        time.sleep(0.2)
    return output


def _clean(output):
    """Limpiar caracteres de control ANSI/VT100"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', output).strip()


def _detect_vendor(banner, version_output):
    """Detectar vendor/OS del switch"""
    combined = (banner + version_output).lower()
    if "cisco" in combined or "ios" in combined:
        return "cisco"
    if "aruba" in combined or "hp" in combined or "procurve" in combined or "comware" in combined:
        return "hp_aruba"
    if "mikrotik" in combined or "routeros" in combined:
        return "mikrotik"
    if "juniper" in combined or "junos" in combined:
        return "juniper"
    if "fortigate" in combined or "fortiswitch" in combined or "fortios" in combined or "forti" in combined:
        return "fortinet"
    return "generic"


def test_connection(server):
    try:
        client = _get_client(server)
        transport = client.get_transport()
        banner = str(transport.get_banner() or b"").lower()
        client.close()
        return True, "Conexión SSH exitosa"
    except paramiko.AuthenticationException:
        return False, "Error de autenticación"
    except socket.timeout:
        return False, "Timeout — dispositivo no responde"
    except ConnectionRefusedError:
        return False, "Conexión rechazada — verificar SSH habilitado"
    except Exception as e:
        return False, str(e)[:80]


def get_switch_stats(server):
    """Recopila datos completos del switch vía SSH"""
    result = {
        "server_id":   server["id"],
        "server_name": server["name"],
        "host":        server["host"],
        "port":        server["port"],
        "os_type":     "switch",
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "connected":   False,
        "error":       None,
        "vendor":      "unknown"
    }

    try:
        client = _get_client(server)
        result["connected"] = True

        # Obtener shell interactivo
        shell = client.invoke_shell(width=200, height=200)
        import time
        time.sleep(1.5)

        # Limpiar buffer inicial (banner/prompt)
        initial = ""
        while shell.recv_ready():
            initial += shell.recv(4096).decode("utf-8", errors="replace")
            time.sleep(0.3)

        # ── DETECCIÓN DE VENDOR ───────────────────────────────────────────────
        # Intentar comando de versión genérico
        ver_out = _clean(_run_cmd(shell, "show version", wait=2))
        if not ver_out:
            ver_out = _clean(_run_cmd(shell, "/system resource print", wait=2))  # MikroTik

        vendor = _detect_vendor(initial, ver_out)
        result["vendor"] = vendor

        # Deshabilitar paginación según vendor
        if vendor == "cisco":
            _run_cmd(shell, "terminal length 0", wait=0.5)
        elif vendor == "hp_aruba":
            _run_cmd(shell, "no page", wait=0.5)
        elif vendor == "juniper":
            _run_cmd(shell, "set cli screen-length 0", wait=0.5)

        # ── COMANDOS POR VENDOR ───────────────────────────────────────────────
        cmds = _get_commands(vendor)

        # Ejecutar todos los comandos
        outputs = {}
        for key, cmd in cmds.items():
            out = _clean(_run_cmd(shell, cmd, wait=2))
            outputs[key] = out

        client.close()

        # ── PARSEAR RESULTADOS ────────────────────────────────────────────────
        result["version_raw"]  = ver_out
        result["hostname"]     = _parse_hostname(outputs.get("hostname", ""), vendor, ver_out)
        result["os"]           = _parse_os(ver_out, vendor)
        result["kernel"]       = _parse_firmware(ver_out, vendor)
        result["uptime"]       = _parse_uptime(ver_out, vendor, outputs.get("uptime", ""))
        result["ip"]           = server["host"]
        result["cpu_usage"]    = _parse_cpu(outputs.get("cpu", ""), vendor)
        result["mem_pct"]      = _parse_mem_pct(outputs.get("memory", ""), vendor)
        result["mem_used"]     = "N/A"
        result["mem_total"]    = "N/A"
        result["disk_pct"]     = 0
        result["disk_used"]    = "N/A"
        result["disk_total"]   = "N/A"
        result["procs"]        = "N/A"
        result["load_1"]       = "N/A"
        result["load_5"]       = "N/A"
        result["load_15"]      = "N/A"
        result["cpu_cores"]    = "N/A"
        result["services"]     = []
        result["last_logins"]  = []

        # VLANs
        result["vlans"]        = _parse_vlans(outputs.get("vlans", ""), vendor)

        # Interfaces / Puertos
        result["interfaces"]   = _parse_interfaces(outputs.get("interfaces", ""), vendor)

        # Usuarios
        result["switch_users"] = _parse_users(outputs.get("users", ""), vendor)

        # Configuración de seguridad
        security = _analyze_security(outputs, vendor, ver_out)
        result["security"]         = security
        result["ufw_active"]       = security["acl_configured"]
        result["firewalld_active"] = False
        result["ssh_root_login"]   = not security["ssh_v2_only"]
        result["fail2ban_active"]  = security["login_protection"]
        result["crowdsec_active"]  = False
        result["security_score"]   = security["score"]
        result["pending_updates"]  = 0

        # Tabs de puertos — usar interfaces como "puertos"
        ports_data = _build_ports_data(result["interfaces"])
        result["ports"]      = ports_data
        result["open_ports"] = []

        # CrowdSec — no aplica en switches
        result["crowdsec"] = {
            "available": False,
            "version": "No aplica en switches",
            "service_active": False,
            "service_status": "N/A",
            "decisions": [], "decisions_count": 0,
            "alerts": [],    "alerts_count": 0,
            "bouncers": [],  "hub_raw": "",
            "recent_logs": [],
            "install_hint": "CrowdSec no es compatible con switches de red"
        }

        # Usuarios en formato compatible con template
        result["users"] = {
            "real_users": [
                {"username": u["username"], "uid": u.get("privilege", "?"),
                 "home": "N/A", "shell": "CLI",
                 "can_login": True, "is_root": u.get("privilege", "") in ["15", "admin", "superuser"]}
                for u in result["switch_users"]
            ],
            "sudo_users": [u["username"] for u in result["switch_users"]
                           if u.get("privilege", "") in ["15", "admin", "superuser"]],
            "uid0_users": [],
            "uid0_warning": False,
            "passwd_status": [],
            "lastlog": [],
            "critical_groups": [],
            "security_checks": security.get("user_checks", [])
        }

    except Exception as e:
        result["connected"] = False
        result["error"] = str(e)[:120]

    return result


# ── COMANDOS POR VENDOR ───────────────────────────────────────────────────────

def _get_commands(vendor):
    if vendor == "cisco":
        return {
            "hostname":   "show running-config | include hostname",
            "cpu":        "show processes cpu sorted | head 5",
            "memory":     "show processes memory sorted | head 3",
            "vlans":      "show vlan brief",
            "interfaces": "show interfaces status",
            "users":      "show running-config | include username",
            "uptime":     "show version | include uptime",
            "ssh":        "show running-config | include ip ssh",
            "telnet":     "show running-config | include transport input",
            "snmp":       "show running-config | include snmp-server community",
            "aaa":        "show running-config | include aaa",
            "acl":        "show ip access-lists | head 20",
            "ntp":        "show running-config | include ntp",
            "banner":     "show running-config | include banner",
            "logging":    "show running-config | include logging",
            "port_sec":   "show port-security",
            "spanning":   "show spanning-tree summary",
        }
    elif vendor == "hp_aruba":
        return {
            "hostname":   "show system | include Name",
            "cpu":        "show cpu",
            "memory":     "show memory",
            "vlans":      "show vlans",
            "interfaces": "show interfaces brief",
            "users":      "show local-user",
            "uptime":     "show system | include uptime",
            "ssh":        "show crypto host-public-key",
            "telnet":     "show telnet",
            "snmp":       "show snmp-server community",
            "aaa":        "show aaa",
            "acl":        "show access-list",
            "ntp":        "show ntp status",
            "logging":    "show logging",
            "port_sec":   "show port-security",
            "spanning":   "show spanning-tree",
        }
    elif vendor == "mikrotik":
        return {
            "hostname":   "/system identity print",
            "cpu":        "/system resource print",
            "memory":     "/system resource print",
            "vlans":      "/interface vlan print",
            "interfaces": "/interface print",
            "users":      "/user print",
            "uptime":     "/system resource print",
            "ssh":        "/ip service print",
            "telnet":     "/ip service print",
            "snmp":       "/snmp print",
            "aaa":        "/user group print",
            "acl":        "/ip firewall filter print count-only",
            "ntp":        "/system ntp client print",
            "logging":    "/system logging print",
            "port_sec":   "/interface ethernet print",
            "spanning":   "/interface bridge print",
        }
    elif vendor == "juniper":
        return {
            "hostname":   "show version | match Hostname",
            "cpu":        "show chassis routing-engine",
            "memory":     "show chassis routing-engine",
            "vlans":      "show vlans",
            "interfaces": "show interfaces terse",
            "users":      "show configuration system login",
            "uptime":     "show system uptime",
            "ssh":        "show configuration system services ssh",
            "telnet":     "show configuration system services telnet",
            "snmp":       "show configuration snmp",
            "aaa":        "show configuration system authentication-order",
            "acl":        "show firewall",
            "ntp":        "show configuration system ntp",
            "logging":    "show configuration system syslog",
            "port_sec":   "show ethernet-switching interface",
            "spanning":   "show spanning-tree bridge",
        }
    elif vendor == "fortinet":
        return {
            "hostname":   "get system status",
            "cpu":        "get system performance status",
            "memory":     "get system performance status",
            "vlans":      "show system interface",
            "interfaces": "get system interface physical",
            "users":      "show system admin",
            "uptime":     "get system status",
            "ssh":        "show system global | grep -i ssh",
            "telnet":     "show system global | grep -i telnet",
            "snmp":       "show system snmp sysinfo",
            "aaa":        "show system admin",
            "acl":        "show firewall policy | head -30",
            "ntp":        "show system ntp",
            "logging":    "show log setting",
            "port_sec":   "show system interface",
            "spanning":   "get switch stp settings",
        }
    else:  # generic
        return {
            "hostname":   "hostname",
            "cpu":        "show processes cpu",
            "memory":     "show memory",
            "vlans":      "show vlan",
            "interfaces": "show interfaces",
            "users":      "show users",
            "uptime":     "show uptime",
            "ssh":        "show ip ssh",
            "telnet":     "",
            "snmp":       "show snmp",
            "aaa":        "",
            "acl":        "show access-list",
            "ntp":        "show ntp",
            "logging":    "show log",
            "port_sec":   "",
            "spanning":   "show spanning-tree",
        }


# ── PARSERS ───────────────────────────────────────────────────────────────────

def _parse_hostname(out, vendor, ver_out):
    if vendor == "cisco":
        m = re.search(r"hostname\s+(\S+)", out)
        if m: return m.group(1)
        m = re.search(r"^(\S+)\s+uptime", ver_out, re.MULTILINE)
        if m: return m.group(1)
    elif vendor == "mikrotik":
        m = re.search(r"name:\s+(\S+)", out)
        if m: return m.group(1)
    elif vendor == "juniper":
        m = re.search(r"Hostname:\s+(\S+)", out)
        if m: return m.group(1)
    elif vendor == "fortinet":
        m = re.search(r"Hostname:\s+(\S+)", out)
        if m: return m.group(1)
        m = re.search(r"hostname\s*:\s*(\S+)", out, re.IGNORECASE)
        if m: return m.group(1)
    return out.split()[-1] if out.split() else "switch"


def _parse_os(ver_out, vendor):
    if vendor == "fortinet":
        m = re.search(r"Version:\s+(FortiGate|FortiSwitch)[\w\-]+\s+v([\d\.]+)", ver_out)
        if m: return f"{m.group(1)} v{m.group(2)}"
        m = re.search(r"(FortiGate|FortiSwitch)[\w\-]+", ver_out)
        if m: return m.group(0)
        return "Fortinet FortiOS"
    labels = {
        "cisco":    r"(Cisco IOS[\w\s\-XE]*),?\s+Version\s+([\d\.\w\(\)]+)",
        "hp_aruba": r"(HP|Aruba|ProCurve)[\w\s]+",
        "mikrotik": r"RouterOS\s+([\d\.]+)",
        "juniper":  r"JUNOS\s+([\d\w\.\-]+)",
    }
    pattern = labels.get(vendor)
    if pattern:
        m = re.search(pattern, ver_out, re.IGNORECASE)
        if m: return m.group(0)[:60]
    vendor_names = {"cisco":"Cisco IOS","hp_aruba":"HP/Aruba","mikrotik":"MikroTik RouterOS","juniper":"Juniper JunOS"}
    return vendor_names.get(vendor, "Switch OS desconocido")


def _parse_firmware(ver_out, vendor):
    if vendor == "cisco":
        m = re.search(r"Version\s+([\d\.\w\(\)]+)", ver_out)
        if m: return m.group(1)
    elif vendor == "mikrotik":
        m = re.search(r"version:\s+([\d\.]+)", ver_out)
        if m: return m.group(1)
    elif vendor == "juniper":
        m = re.search(r"JUNOS\s+([\d\w\.\-]+)", ver_out)
        if m: return m.group(1)
    elif vendor == "fortinet":
        m = re.search(r"v(\d+\.\d+\.\d+)", ver_out)
        if m: return m.group(1)
    return "N/A"


def _parse_uptime(ver_out, vendor, uptime_out):
    combined = ver_out + uptime_out
    if vendor == "cisco":
        m = re.search(r"uptime is\s+(.+?)(?:\n|$)", combined, re.IGNORECASE)
        if m: return m.group(1).strip()
    elif vendor == "mikrotik":
        m = re.search(r"uptime:\s+(\S+)", combined)
        if m: return m.group(1)
    elif vendor == "juniper":
        m = re.search(r"System booted:\s+.+?\((.+?)\)", combined)
        if m: return m.group(1)
    elif vendor == "fortinet":
        m = re.search(r"Uptime:\s+(.+?)(?:\n|$)", combined, re.IGNORECASE)
        if m: return m.group(1).strip()
    return "N/A"


def _parse_cpu(cpu_out, vendor):
    if vendor == "cisco":
        m = re.search(r"CPU utilization.*?:\s*(\d+)%", cpu_out)
        if m: return m.group(1) + "%"
    elif vendor == "mikrotik":
        m = re.search(r"cpu-load:\s+(\d+)%", cpu_out)
        if m: return m.group(1) + "%"
    elif vendor == "juniper":
        m = re.search(r"CPU utilization\s+(\d+)\s+percent", cpu_out)
        if m: return m.group(1) + "%"
    elif vendor == "fortinet":
        m = re.search(r"CPU states:\s+(\d+)%", cpu_out)
        if m: return m.group(1) + "%"
        m = re.search(r"CPU:\s+(\d+)%", cpu_out)
        if m: return m.group(1) + "%"
    return "N/A"


def _parse_mem_pct(mem_out, vendor):
    if vendor == "cisco":
        m = re.search(r"Processor Pool Total:\s+(\d+)\s+Used:\s+(\d+)", mem_out)
        if m:
            total, used = int(m.group(1)), int(m.group(2))
            return round((used / total) * 100, 1) if total else 0
    elif vendor == "mikrotik":
        free_m = re.search(r"free-memory:\s+(\d+\.\d+[MG]iB)", mem_out)
        total_m = re.search(r"total-memory:\s+(\d+\.\d+[MG]iB)", mem_out)
        if free_m and total_m:
            def to_mb(s):
                v, u = float(s[:-3]), s[-3:]
                return v * 1024 if "G" in u else v
            total = to_mb(total_m.group(1))
            free  = to_mb(free_m.group(1))
            return round(((total - free) / total) * 100, 1) if total else 0
    return 0


def _parse_vlans(vlan_out, vendor):
    vlans = []
    if vendor == "cisco":
        for line in vlan_out.splitlines():
            m = re.match(r"(\d+)\s+(\S+)\s+(active|suspended)", line)
            if m:
                vlans.append({"id": m.group(1), "name": m.group(2), "status": m.group(3)})
    elif vendor == "mikrotik":
        for line in vlan_out.splitlines():
            m = re.search(r"vlan-id=(\d+).*?name=\"?([^\"]+)\"?", line)
            if m:
                vlans.append({"id": m.group(1), "name": m.group(2), "status": "active"})
    elif vendor == "juniper":
        for line in vlan_out.splitlines():
            m = re.match(r"(\S+)\s+(\d+)\s+\S+\s+(Active|Inactive)", line)
            if m:
                vlans.append({"id": m.group(2), "name": m.group(1), "status": m.group(3).lower()})
    elif vendor == "fortinet":
        for line in vlan_out.splitlines():
            m = re.search(r'edit\s+"([^"]+)"', line)
            if m:
                vlans.append({"id": "N/A", "name": m.group(1), "status": "active"})
    else:
        for line in vlan_out.splitlines():
            m = re.search(r"(\d+)\s+(\S+)", line)
            if m and m.group(1).isdigit():
                vlans.append({"id": m.group(1), "name": m.group(2), "status": "active"})
    return vlans[:30]


def _parse_interfaces(iface_out, vendor):
    interfaces = []
    if vendor == "cisco":
        for line in iface_out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and re.match(r"[A-Za-z]", parts[0]):
                interfaces.append({
                    "name": parts[0],
                    "status": parts[1] if len(parts) > 1 else "?",
                    "duplex": parts[3] if len(parts) > 3 else "?",
                    "speed": parts[4] if len(parts) > 4 else "?",
                    "vlan": parts[6] if len(parts) > 6 else "?",
                    "up": "connected" in line.lower()
                })
    elif vendor == "mikrotik":
        for line in iface_out.splitlines():
            m = re.search(r"(\d+)\s+([RD]?)\s*(\S+)\s+ether", line)
            if m:
                interfaces.append({
                    "name": m.group(3),
                    "status": "up" if "R" in m.group(2) else "down",
                    "duplex": "auto", "speed": "auto", "vlan": "?",
                    "up": "R" in m.group(2)
                })
    elif vendor == "fortinet":
        current = None
        for line in iface_out.splitlines():
            m = re.match(r"==\s+\[(.+?)\]", line)
            if m:
                current = m.group(1).strip()
            if current and "status:" in line.lower():
                up = "up" in line.lower()
                interfaces.append({
                    "name": current, "status": "up" if up else "down",
                    "duplex": "auto", "speed": "auto", "vlan": "?", "up": up
                })
                current = None
    else:
        for line in iface_out.splitlines():
            if re.search(r"(up|down|connected|notconnect)", line, re.IGNORECASE):
                parts = line.split()
                if parts:
                    interfaces.append({
                        "name": parts[0],
                        "status": "up" if re.search(r"\bup\b|\bconnected\b", line, re.IGNORECASE) else "down",
                        "duplex": "?", "speed": "?", "vlan": "?",
                        "up": bool(re.search(r"\bup\b|\bconnected\b", line, re.IGNORECASE))
                    })
    return interfaces[:40]


def _parse_users(user_out, vendor):
    users = []
    if vendor == "cisco":
        for line in user_out.splitlines():
            m = re.search(r"username\s+(\S+)\s+privilege\s+(\d+)", line)
            if m:
                users.append({"username": m.group(1), "privilege": m.group(2),
                              "type": "local"})
    elif vendor == "mikrotik":
        for line in user_out.splitlines():
            m = re.search(r"(\d+)\s+\S+\s+(\S+)\s+(\S+)", line)
            if m:
                users.append({"username": m.group(2), "privilege": m.group(3),
                              "type": "local"})
    elif vendor == "juniper":
        for line in user_out.splitlines():
            m = re.search(r"user\s+(\S+)\s+\{", line)
            if m:
                users.append({"username": m.group(1), "privilege": "admin",
                              "type": "local"})
    elif vendor == "fortinet":
        for line in user_out.splitlines():
            m = re.search(r'edit\s+"([^"]+)"', line)
            if m:
                users.append({"username": m.group(1), "privilege": "admin",
                              "type": "local"})
    else:
        for line in user_out.splitlines():
            if line.strip():
                users.append({"username": line.split()[0], "privilege": "?",
                              "type": "local"})
    return users


def _analyze_security(outputs, vendor, ver_out):
    """Analizar configuración de seguridad del switch"""
    security = {}
    all_output = " ".join(outputs.values()).lower()

    # SSH v2
    ssh_out = outputs.get("ssh", "").lower()
    if vendor == "cisco":
        security["ssh_enabled"]  = "ssh" in ssh_out
        security["ssh_v2_only"]  = "version 2" in ssh_out
        security["ssh_timeout"]  = re.search(r"time-out\s+(\d+)", ssh_out)
    elif vendor == "mikrotik":
        security["ssh_enabled"]  = "ssh" in ssh_out and "disabled=no" in ssh_out
        security["ssh_v2_only"]  = True  # MikroTik usa SSH2 por defecto
    else:
        security["ssh_enabled"]  = "ssh" in ssh_out
        security["ssh_v2_only"]  = "v2" in ssh_out or "version 2" in ssh_out

    # Telnet — PELIGROSO
    telnet_out = outputs.get("telnet", "").lower()
    if vendor == "cisco":
        security["telnet_enabled"] = "telnet" in telnet_out and "no telnet" not in telnet_out
    elif vendor == "mikrotik":
        security["telnet_enabled"] = "telnet" in telnet_out and "disabled=no" in telnet_out
    else:
        security["telnet_enabled"] = "telnet" in telnet_out

    # SNMP
    snmp_out = outputs.get("snmp", "").lower()
    security["snmp_enabled"]   = bool(snmp_out) and len(snmp_out) > 10
    security["snmp_v1_v2"]     = "community" in snmp_out
    security["snmp_community_public"] = "public" in snmp_out or "private" in snmp_out

    # ACLs / Firewall
    acl_out = outputs.get("acl", "")
    security["acl_configured"] = len(acl_out) > 20

    # NTP
    ntp_out = outputs.get("ntp", "").lower()
    security["ntp_configured"] = len(ntp_out) > 10 and "ntp" in ntp_out

    # Logging
    log_out = outputs.get("logging", "").lower()
    security["logging_configured"] = len(log_out) > 10

    # AAA
    aaa_out = outputs.get("aaa", "").lower()
    security["aaa_configured"] = len(aaa_out) > 10

    # Banner configurado
    banner_out = outputs.get("banner", "").lower()
    security["banner_configured"] = len(banner_out) > 5

    # Port Security
    portsec_out = outputs.get("port_sec", "").lower()
    security["port_security"] = len(portsec_out) > 10 and "violation" in portsec_out

    # Spanning Tree
    stp_out = outputs.get("spanning", "").lower()
    security["stp_configured"] = len(stp_out) > 10

    # Login protection
    security["login_protection"] = security["aaa_configured"] or "login local" in all_output

    # Chequeos detallados
    checks = []
    checks.append({
        "name": "SSH v2 habilitado",
        "ok": security["ssh_v2_only"],
        "rec": "Configurar: ip ssh version 2"
    })
    checks.append({
        "name": "Telnet deshabilitado",
        "ok": not security["telnet_enabled"],
        "rec": "Deshabilitar Telnet: transport input ssh"
    })
    checks.append({
        "name": "SNMP sin comunidades default",
        "ok": not security["snmp_community_public"],
        "rec": "Cambiar comunidades 'public'/'private' por valores seguros"
    })
    checks.append({
        "name": "ACLs configuradas",
        "ok": security["acl_configured"],
        "rec": "Configurar ACLs para restringir acceso de gestión"
    })
    checks.append({
        "name": "NTP configurado",
        "ok": security["ntp_configured"],
        "rec": "Configurar servidor NTP para sincronización de logs"
    })
    checks.append({
        "name": "Logging habilitado",
        "ok": security["logging_configured"],
        "rec": "Configurar logging a servidor Syslog"
    })
    checks.append({
        "name": "AAA / Login local",
        "ok": security["login_protection"],
        "rec": "Configurar AAA o login local con contraseña"
    })
    checks.append({
        "name": "Banner de acceso",
        "ok": security["banner_configured"],
        "rec": "Configurar banner de advertencia legal"
    })
    checks.append({
        "name": "Port Security",
        "ok": security["port_security"],
        "rec": "Habilitar port-security en puertos de acceso"
    })
    checks.append({
        "name": "Spanning Tree configurado",
        "ok": security["stp_configured"],
        "rec": "Verificar configuración de STP/RSTP"
    })
    security["ssh_checks"] = checks

    # Score
    score = 100
    if not security["ssh_v2_only"]:           score -= 15
    if security["telnet_enabled"]:            score -= 25
    if security["snmp_community_public"]:     score -= 20
    if not security["acl_configured"]:        score -= 15
    if not security["login_protection"]:      score -= 15
    if not security["ntp_configured"]:        score -= 5
    if not security["logging_configured"]:    score -= 5
    security["score"] = max(score, 0)

    # Compatibilidad con template base
    security["ufw_output"]        = f"ACLs configuradas: {'Sí' if security['acl_configured'] else 'No'}\nTelnet: {'ACTIVO ⚠' if security['telnet_enabled'] else 'Deshabilitado ✓'}\nSNMP: {'Activo' if security['snmp_enabled'] else 'Deshabilitado'}"
    security["ufw_active"]        = security["acl_configured"]
    security["firewalld_active"]  = False
    security["fail2ban_active"]   = security["login_protection"]
    security["fail2ban_status"]   = "AAA/Login local: " + ("Configurado" if security["login_protection"] else "No configurado")
    security["selinux"]           = "No aplica"
    security["selinux_enforcing"] = False
    security["apparmor"]          = "No aplica"
    security["sysctl_checks"]     = []
    security["suid_files"]        = []
    security["iptables"]          = outputs.get("acl", "Sin ACLs detectadas")
    security["ssh_config_raw"]    = outputs.get("ssh", "Sin configuración SSH detectada")
    security["pending_updates"]   = 0

    # User checks
    security["user_checks"] = [
        {
            "name": "Telnet deshabilitado",
            "ok": not security["telnet_enabled"],
            "detail": "PELIGRO: Telnet transmite en texto plano" if security["telnet_enabled"] else "Telnet deshabilitado ✓",
            "severity": "danger" if security["telnet_enabled"] else "ok"
        },
        {
            "name": "SNMP seguro",
            "ok": not security["snmp_community_public"],
            "detail": "Comunidades default detectadas" if security["snmp_community_public"] else "Sin comunidades default",
            "severity": "danger" if security["snmp_community_public"] else "ok"
        }
    ]

    return security


def _build_ports_data(interfaces):
    """Convertir interfaces del switch al formato del tab Puertos"""
    listening = []
    for iface in interfaces:
        listening.append({
            "port": iface["name"],
            "addr": "switch",
            "service": "Interfaz de red",
            "process": iface.get("speed", "?") + " " + iface.get("duplex", ""),
            "public": iface["up"],
            "dangerous": False,
            "risk": "ok" if iface["up"] else "info"
        })
    return {
        "listening": listening,
        "count_total": len(listening),
        "count_dangerous": 0,
        "count_public": sum(1 for i in interfaces if i["up"]),
        "connections": [],
        "recommendations": []
    }
