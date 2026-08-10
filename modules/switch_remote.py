"""
Módulo: switch_remote
Análisis de hardening para switches via SSH — Multi-vendor
Soporta: Cisco IOS/IOS-XE, HP/Aruba, MikroTik, Juniper, Fortinet
"""

import paramiko
import socket
import re
import time
from datetime import datetime


def _get_client(server):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": server["host"],
        "port":     server["port"],
        "username": server["username"],
        "timeout":  20,
        "banner_timeout": 25,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if server["auth_type"] == "key" and server.get("key_path"):
        kwargs["key_filename"] = server["key_path"]
    else:
        kwargs["password"] = server.get("password", "")
    client.connect(**kwargs)
    return client


def _run_cmd(shell, cmd, wait=2.0):
    """Ejecutar comando en shell interactivo y devolver output"""
    shell.send(cmd + "\n")
    time.sleep(wait)
    output = ""
    deadline = time.time() + wait + 2
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", errors="replace")
            output += chunk
            time.sleep(0.3)
        else:
            time.sleep(0.2)
    return output


def _clean(output):
    """Limpiar caracteres de control ANSI/VT100"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', output).strip()


def _detect_vendor(banner, version_output):
    combined = (banner + version_output).lower()
    if "fortigate" in combined or "fortiswitch" in combined or "fortios" in combined or "forti" in combined:
        return "fortinet"
    if "cisco" in combined or "ios" in combined:
        return "cisco"
    if "aruba" in combined or "hp" in combined or "procurve" in combined or "comware" in combined:
        return "hp_aruba"
    if "mikrotik" in combined or "routeros" in combined:
        return "mikrotik"
    if "juniper" in combined or "junos" in combined:
        return "juniper"
    return "generic"


def test_connection(server):
    try:
        client = _get_client(server)
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

        shell = client.invoke_shell(width=200, height=200)
        time.sleep(2)

        # Limpiar buffer inicial
        initial = ""
        while shell.recv_ready():
            initial += shell.recv(65535).decode("utf-8", errors="replace")
            time.sleep(0.3)

        # Detectar vendor con comando de versión
        ver_out = _clean(_run_cmd(shell, "get system status", wait=2))
        if not ver_out or len(ver_out) < 20:
            ver_out = _clean(_run_cmd(shell, "show version", wait=2))
        if not ver_out or len(ver_out) < 20:
            ver_out = _clean(_run_cmd(shell, "/system resource print", wait=2))

        vendor = server.get("vendor", "auto")
        if vendor == "auto" or not vendor:
            vendor = _detect_vendor(initial, ver_out)
        result["vendor"] = vendor

        # Deshabilitar paginación
        if vendor == "cisco":
            _run_cmd(shell, "terminal length 0", wait=0.8)
        elif vendor == "hp_aruba":
            _run_cmd(shell, "no page", wait=0.8)
        elif vendor == "juniper":
            _run_cmd(shell, "set cli screen-length 0", wait=0.8)
        elif vendor == "fortinet":
            _run_cmd(shell, "config system console", wait=0.8)
            _run_cmd(shell, "set output standard", wait=0.8)
            _run_cmd(shell, "end", wait=0.8)

        # Ejecutar comandos según vendor
        cmds = _get_commands(vendor)
        outputs = {"version": ver_out}
        for key, cmd in cmds.items():
            if cmd:
                out = _clean(_run_cmd(shell, cmd, wait=2.5))
                outputs[key] = out

        client.close()

        # Parsear resultados
        result["version_raw"]  = ver_out
        result["hostname"]     = _parse_hostname(outputs.get("hostname", ""), vendor, ver_out)
        result["os"]           = _parse_os(ver_out, vendor)
        result["kernel"]       = _parse_firmware(ver_out, vendor)
        result["uptime"]       = _parse_uptime(ver_out, vendor, outputs.get("uptime", ""))
        result["ip"]           = server["host"]
        result["cpu_usage"]    = _parse_cpu(outputs.get("cpu", ""), vendor)
        # Para Fortinet usar sesiones activas como métrica de "procesos"
        # y model name como CPU cores
        if vendor == "fortinet":
            perf_out = outputs.get("cpu", "")
            m_sess = re.search(r"Average sessions:\s+(\d+)\s+sessions in 1 minute", perf_out)
            if m_sess:
                result["procs"] = f"{m_sess.group(1)} sesiones activas"
            cpu_hw = outputs.get("cpu_hw", "")
            m_cpu = re.search(r"model name\s*:\s*(.+)", cpu_hw)
            if m_cpu:
                result["cpu_cores"] = m_cpu.group(1).strip()
        result["mem_pct"]      = _parse_mem_pct(outputs.get("memory", ""), vendor)
        result["mem_used"]     = _parse_mem_used(outputs.get("memory", ""), vendor)
        result["mem_total"]    = _parse_mem_total(outputs.get("memory", ""), vendor)
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
        result["vlans"]        = _parse_vlans(outputs.get("vlans", ""), vendor)
        result["interfaces"]   = _parse_interfaces(outputs.get("interfaces", ""), vendor, outputs)
        result["switch_users"] = _parse_users(outputs.get("users", ""), vendor)

        security = _analyze_security(outputs, vendor, ver_out)
        result["security"]         = security
        result["ufw_active"]       = security["acl_configured"]
        result["firewalld_active"] = False
        result["ssh_root_login"]   = not security["ssh_v2_only"]
        result["fail2ban_active"]  = security["login_protection"]
        result["crowdsec_active"]  = False
        result["security_score"]   = security["score"]
        result["pending_updates"]  = 0

        ports_data = _build_ports_data(result["interfaces"])
        result["ports"]      = ports_data
        result["open_ports"] = []

        result["crowdsec"] = {
            "available": False,
            "version": "No aplica en switches/firewalls",
            "service_active": False,
            "service_status": "N/A",
            "decisions": [], "decisions_count": 0,
            "alerts": [],    "alerts_count": 0,
            "bouncers": [],  "hub_raw": "",
            "recent_logs": [],
            "install_hint": "CrowdSec no es compatible con este tipo de dispositivo"
        }

        result["users"] = {
            "real_users": [
                {"username": u["username"], "uid": u.get("privilege", "?"),
                 "home": "N/A", "shell": "CLI",
                 "can_login": True,
                 "is_root": u.get("privilege", "") in ["15", "admin", "super_admin", "superuser"]}
                for u in result["switch_users"]
            ],
            "sudo_users": [u["username"] for u in result["switch_users"]
                           if u.get("privilege", "") in ["15", "admin", "super_admin", "superuser"]],
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
    if vendor == "fortinet":
        return {
            "hostname":   "get system status",
            "cpu":        "get system performance status",
            "memory":     "get system performance status",
            "cpu_hw":     "get hardware cpu",
            "uptime":     "get system performance status",
            "vlans":      "show system interface",
            "interfaces": "show system interface",
            "interfaces_phy": "get system interface physical",
            "users":      "show system admin",
            "ssh":        "show system global",
            "telnet":     "show system global",
            "snmp":       "show system snmp sysinfo",
            "aaa":        "show system admin",
            "acl":        "show firewall policy",
            "ntp":        "show system ntp",
            "logging":    "show log setting",
            "port_sec":   "",
            "spanning":   "",
            "banner":     "show system global",
        }
    elif vendor == "cisco":
        return {
            "hostname":   "show running-config | include hostname",
            "cpu":        "show processes cpu sorted | head 5",
            "memory":     "show processes memory sorted | head 3",
            "uptime":     "show version | include uptime",
            "vlans":      "show vlan brief",
            "interfaces": "show interfaces status",
            "users":      "show running-config | include username",
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
            "uptime":     "show system | include uptime",
            "vlans":      "show vlans",
            "interfaces": "show interfaces brief",
            "users":      "show local-user",
            "ssh":        "show crypto host-public-key",
            "telnet":     "show telnet",
            "snmp":       "show snmp-server community",
            "aaa":        "show aaa",
            "acl":        "show access-list",
            "ntp":        "show ntp status",
            "logging":    "show logging",
            "port_sec":   "show port-security",
            "spanning":   "show spanning-tree",
            "banner":     "",
        }
    elif vendor == "mikrotik":
        return {
            "hostname":   "/system identity print",
            "cpu":        "/system resource print",
            "memory":     "/system resource print",
            "uptime":     "/system resource print",
            "vlans":      "/interface vlan print",
            "interfaces": "/interface print",
            "users":      "/user print",
            "ssh":        "/ip service print",
            "telnet":     "/ip service print",
            "snmp":       "/snmp print",
            "aaa":        "/user group print",
            "acl":        "/ip firewall filter print count-only",
            "ntp":        "/system ntp client print",
            "logging":    "/system logging print",
            "port_sec":   "/interface ethernet print",
            "spanning":   "/interface bridge print",
            "banner":     "",
        }
    elif vendor == "juniper":
        return {
            "hostname":   "show version | match Hostname",
            "cpu":        "show chassis routing-engine",
            "memory":     "show chassis routing-engine",
            "uptime":     "show system uptime",
            "vlans":      "show vlans",
            "interfaces": "show interfaces terse",
            "users":      "show configuration system login",
            "ssh":        "show configuration system services ssh",
            "telnet":     "show configuration system services telnet",
            "snmp":       "show configuration snmp",
            "aaa":        "show configuration system authentication-order",
            "acl":        "show firewall",
            "ntp":        "show configuration system ntp",
            "logging":    "show configuration system syslog",
            "port_sec":   "show ethernet-switching interface",
            "spanning":   "show spanning-tree bridge",
            "banner":     "",
        }
    else:
        return {
            "hostname":   "hostname",
            "cpu":        "show processes cpu",
            "memory":     "show memory",
            "uptime":     "show uptime",
            "vlans":      "show vlan",
            "interfaces": "show interfaces",
            "users":      "show users",
            "ssh":        "show ip ssh",
            "telnet":     "",
            "snmp":       "show snmp",
            "aaa":        "",
            "acl":        "show access-list",
            "ntp":        "show ntp",
            "logging":    "show log",
            "port_sec":   "",
            "spanning":   "show spanning-tree",
            "banner":     "",
        }


# ── PARSERS ───────────────────────────────────────────────────────────────────

def _parse_hostname(out, vendor, ver_out):
    if vendor == "fortinet":
        m = re.search(r"Hostname:\s+(\S+)", ver_out)
        if m: return m.group(1)
    elif vendor == "cisco":
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
    return out.split()[-1] if out.split() else "switch"


def _parse_os(ver_out, vendor):
    if vendor == "fortinet":
        m = re.search(r"Version:\s+(FortiGate[\w\-]+)\s+v([\d\.]+)", ver_out)
        if m: return f"{m.group(1)} v{m.group(2)}"
        m = re.search(r"Version:\s+([\w\-]+\s+v[\d\.]+)", ver_out)
        if m: return m.group(1)
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
    names = {"cisco":"Cisco IOS","hp_aruba":"HP/Aruba","mikrotik":"MikroTik RouterOS","juniper":"Juniper JunOS"}
    return names.get(vendor, "Switch OS desconocido")


def _parse_firmware(ver_out, vendor):
    if vendor == "fortinet":
        m = re.search(r"v([\d\.]+),build(\d+)", ver_out)
        if m: return f"v{m.group(1)} build{m.group(2)}"
    elif vendor == "cisco":
        m = re.search(r"Version\s+([\d\.\w\(\)]+)", ver_out)
        if m: return m.group(1)
    elif vendor == "mikrotik":
        m = re.search(r"version:\s+([\d\.]+)", ver_out)
        if m: return m.group(1)
    elif vendor == "juniper":
        m = re.search(r"JUNOS\s+([\d\w\.\-]+)", ver_out)
        if m: return m.group(1)
    return "N/A"


def _parse_uptime(ver_out, vendor, uptime_out):
    combined = ver_out + "\n" + uptime_out
    if vendor == "fortinet":
        m = re.search(r"Uptime:\s+(.+?)(?:\n|$)", combined, re.IGNORECASE)
        if m: return m.group(1).strip()
    elif vendor == "cisco":
        m = re.search(r"uptime is\s+(.+?)(?:\n|$)", combined, re.IGNORECASE)
        if m: return m.group(1).strip()
    elif vendor == "mikrotik":
        m = re.search(r"uptime:\s+(\S+)", combined)
        if m: return m.group(1)
    elif vendor == "juniper":
        m = re.search(r"System booted:.+?\((.+?)\)", combined)
        if m: return m.group(1)
    return "N/A"


def _parse_cpu(cpu_out, vendor):
    if vendor == "fortinet":
        # "CPU states: 7% user 5% system 0% nice 88% idle"
        m = re.search(r"CPU states:\s+(\d+)%\s+user", cpu_out)
        if m: return m.group(1) + "%"
        m = re.search(r"CPU0 states:\s+(\d+)%", cpu_out)
        if m: return m.group(1) + "%"
    elif vendor == "cisco":
        m = re.search(r"CPU utilization.*?:\s*(\d+)%", cpu_out)
        if m: return m.group(1) + "%"
    elif vendor == "mikrotik":
        m = re.search(r"cpu-load:\s+(\d+)%", cpu_out)
        if m: return m.group(1) + "%"
    elif vendor == "juniper":
        m = re.search(r"CPU utilization\s+(\d+)\s+percent", cpu_out)
        if m: return m.group(1) + "%"
    return "N/A"


def _parse_mem_pct(mem_out, vendor):
    if vendor == "fortinet":
        # "Memory: 1882496k total, 506056k used (26.9%)"
        m = re.search(r"Memory:.*?(\d+\.?\d*)%\)", mem_out)
        if not m:
            m = re.search(r"(\d+)k used \((\d+\.?\d*)%\)", mem_out)
        if m:
            try: return float(m.group(2) if len(m.groups()) > 1 else m.group(1))
            except: pass
        m = re.search(r"(\d+)k total,\s*(\d+)k used", mem_out)
        if m:
            total, used = int(m.group(1)), int(m.group(2))
            return round((used / total) * 100, 1) if total else 0
    elif vendor == "cisco":
        m = re.search(r"Processor Pool Total:\s+(\d+)\s+Used:\s+(\d+)", mem_out)
        if m:
            total, used = int(m.group(1)), int(m.group(2))
            return round((used / total) * 100, 1) if total else 0
    elif vendor == "mikrotik":
        free_m  = re.search(r"free-memory:\s+([\d\.]+[MG]iB)", mem_out)
        total_m = re.search(r"total-memory:\s+([\d\.]+[MG]iB)", mem_out)
        if free_m and total_m:
            def to_mb(s):
                v = float(s[:-3]); u = s[-3:]
                return v * 1024 if "G" in u else v
            total = to_mb(total_m.group(1))
            free  = to_mb(free_m.group(1))
            return round(((total - free) / total) * 100, 1) if total else 0
    return 0


def _parse_mem_used(mem_out, vendor):
    if vendor == "fortinet":
        m = re.search(r"(\d+)k used", mem_out)
        if m: return f"{int(int(m.group(1))/1024)} MB"
    return "N/A"


def _parse_mem_total(mem_out, vendor):
    if vendor == "fortinet":
        m = re.search(r"Memory:\s+(\d+)k total", mem_out)
        if m: return f"{int(int(m.group(1))/1024)} MB"
    return "N/A"


def _parse_interfaces(iface_out, vendor, outputs=None):
    if outputs is None:
        outputs = {}
    """Parser específico para cada vendor"""
    interfaces = []

    if vendor == "fortinet":
        # Formato de show system interface:
        # edit "wan1"
        #     set vdom "root"
        #     set ip 172.16.1.1 255.255.255.252
        #     set allowaccess ping https ssh
        #     set type physical
        #     set alias "P2P-MikroTik-Link"
        #     set status up / down
        current_iface = None
        current_data = {}
        skip_types = ["tunnel", "loopback", "aggregate", "redundant", "vdom-link"]

        for line in iface_out.splitlines():
            # Nueva interfaz
            m = re.match(r'\s*edit\s+"([^"]+)"', line)
            if m:
                if current_iface and current_data:
                    iface_type = current_data.get("iface_type", "physical")
                    if iface_type not in skip_types and current_data.get("ip", "0.0.0.0") != "0.0.0.0":
                        interfaces.append(current_data)
                    elif iface_type == "physical":
                        interfaces.append(current_data)
                current_iface = m.group(1)
                current_data = {
                    "name": current_iface, "status": "up",
                    "speed": "?", "duplex": "auto", "vlan": "?",
                    "ip": "", "mode": "static", "up": True,
                    "alias": "", "iface_type": "physical", "group": False
                }
                continue

            if current_data is None:
                continue

            # IP
            m = re.search(r'set ip\s+([\d\.]+)\s+([\d\.]+)', line)
            if m:
                current_data["ip"] = m.group(1)
                continue
            # Alias
            m = re.search(r'set alias\s+"([^"]+)"', line)
            if m:
                current_data["alias"] = m.group(1)
                current_data["name"] = f'{current_iface} ({m.group(1)})'
                continue
            # Mode
            m = re.search(r'set mode\s+(\w+)', line)
            if m:
                current_data["mode"] = m.group(1)
                continue
            # Type
            m = re.search(r'set type\s+(\w+)', line)
            if m:
                current_data["iface_type"] = m.group(1).lower()
                continue
            # Status explícito
            m = re.search(r'set status\s+(up|down)', line)
            if m:
                current_data["status"] = m.group(1)
                current_data["up"] = m.group(1) == "up"
                continue
            # Speed (de allowaccess inferimos que está up)
            if "set allowaccess" in line and current_data:
                current_data["up"] = True
                current_data["status"] = "up"
            # next = fin de bloque
            if re.match(r'\s*next\s*$', line):
                if current_iface and current_data:
                    iface_type = current_data.get("iface_type", "physical")
                    if iface_type == "physical":
                        interfaces.append(current_data)
                    current_iface = None
                    current_data = {}

        if current_iface and current_data:
            if current_data.get("iface_type", "physical") == "physical":
                interfaces.append(current_data)

        # Enriquecer con IPs dinámicas de get system interface physical
        # Formato: ==[wan2] / ip: 192.168.0.170 / status: up
        phy_out = iface_out  # fallback
        # El output físico se pasa como segundo parámetro via outputs
        phy_raw = outputs.get("interfaces_phy", "") if hasattr(iface_out, "__class__") else ""
        current_phy = None
        for line in phy_raw.splitlines():
            m = re.match(r"\s*==\[(\w+)\]", line)
            if m:
                current_phy = m.group(1)
                continue
            if current_phy:
                m_ip = re.search(r"ip:\s+([\d\.]+)\s+[\d\.]+", line)
                if m_ip and m_ip.group(1) != "0.0.0.0":
                    # Actualizar IP en la interfaz correspondiente
                    for iface in interfaces:
                        base_name = iface["name"].split(" (")[0]
                        if base_name == current_phy and not iface.get("ip"):
                            iface["ip"] = m_ip.group(1)
                            iface["service"] = f"Interfaz de red ({m_ip.group(1)})"
                m_st = re.search(r"status:\s+(\w+)", line)
                if m_st:
                    for iface in interfaces:
                        base_name = iface["name"].split(" (")[0]
                        if base_name == current_phy:
                            iface["status"] = m_st.group(1)
                            iface["up"] = m_st.group(1) == "up"

    elif vendor == "cisco":
        for line in iface_out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and re.match(r"[A-Za-z]", parts[0]):
                interfaces.append({
                    "name": parts[0], "status": parts[1] if len(parts) > 1 else "?",
                    "speed": parts[4] if len(parts) > 4 else "?",
                    "duplex": parts[3] if len(parts) > 3 else "?",
                    "vlan": parts[6] if len(parts) > 6 else "?",
                    "ip": "", "mode": "",
                    "up": "connected" in line.lower()
                })
    elif vendor == "mikrotik":
        for line in iface_out.splitlines():
            m = re.search(r"(\d+)\s+([RD]?)\s*(\S+)\s+ether", line)
            if m:
                interfaces.append({
                    "name": m.group(3), "status": "up" if "R" in m.group(2) else "down",
                    "duplex": "auto", "speed": "auto", "vlan": "?",
                    "ip": "", "mode": "", "up": "R" in m.group(2)
                })
    else:
        for line in iface_out.splitlines():
            if re.search(r"(up|down|connected|notconnect)", line, re.IGNORECASE):
                parts = line.split()
                if parts:
                    interfaces.append({
                        "name": parts[0],
                        "status": "up" if re.search(r"\bup\b|\bconnected\b", line, re.IGNORECASE) else "down",
                        "duplex": "?", "speed": "?", "vlan": "?",
                        "ip": "", "mode": "",
                        "up": bool(re.search(r"\bup\b|\bconnected\b", line, re.IGNORECASE))
                    })

    return interfaces[:40]


def _parse_vlans(vlan_out, vendor):
    vlans = []
    if vendor == "fortinet":
        # Parsear interfaces virtuales/VLANs de show system interface
        current = None
        for line in vlan_out.splitlines():
            m = re.search(r'edit\s+"([^"]+)"', line)
            if m: current = m.group(1)
            if current and "set type vlan" in line.lower():
                vlans.append({"id": "VLAN", "name": current, "status": "active"})
                current = None
    elif vendor == "cisco":
        for line in vlan_out.splitlines():
            m = re.match(r"(\d+)\s+(\S+)\s+(active|suspended)", line)
            if m: vlans.append({"id": m.group(1), "name": m.group(2), "status": m.group(3)})
    elif vendor == "mikrotik":
        for line in vlan_out.splitlines():
            m = re.search(r"vlan-id=(\d+).*?name=\"?([^\"]+)\"?", line)
            if m: vlans.append({"id": m.group(1), "name": m.group(2), "status": "active"})
    elif vendor == "juniper":
        for line in vlan_out.splitlines():
            m = re.match(r"(\S+)\s+(\d+)\s+\S+\s+(Active|Inactive)", line)
            if m: vlans.append({"id": m.group(2), "name": m.group(1), "status": m.group(3).lower()})
    else:
        for line in vlan_out.splitlines():
            m = re.search(r"(\d+)\s+(\S+)", line)
            if m and m.group(1).isdigit():
                vlans.append({"id": m.group(1), "name": m.group(2), "status": "active"})
    return vlans[:30]


def _parse_users(user_out, vendor):
    users = []
    if vendor == "fortinet":
        # config system admin / edit "admin" / set accprofile "super_admin"
        current_user = None
        current_profile = "admin"
        for line in user_out.splitlines():
            m = re.search(r'edit\s+"([^"]+)"', line)
            if m: current_user = m.group(1)
            m = re.search(r'set accprofile\s+"([^"]+)"', line)
            if m and current_user:
                current_profile = m.group(1)
            if "next" in line.lower() and current_user:
                users.append({"username": current_user, "privilege": current_profile, "type": "local"})
                current_user = None
                current_profile = "admin"
    elif vendor == "cisco":
        for line in user_out.splitlines():
            m = re.search(r"username\s+(\S+)\s+privilege\s+(\d+)", line)
            if m: users.append({"username": m.group(1), "privilege": m.group(2), "type": "local"})
    elif vendor == "mikrotik":
        for line in user_out.splitlines():
            m = re.search(r"(\d+)\s+\S+\s+(\S+)\s+(\S+)", line)
            if m: users.append({"username": m.group(2), "privilege": m.group(3), "type": "local"})
    elif vendor == "juniper":
        for line in user_out.splitlines():
            m = re.search(r"user\s+(\S+)\s+\{", line)
            if m: users.append({"username": m.group(1), "privilege": "admin", "type": "local"})
    else:
        for line in user_out.splitlines():
            if line.strip():
                users.append({"username": line.split()[0], "privilege": "?", "type": "local"})
    return users


def _analyze_security(outputs, vendor, ver_out):
    security = {}
    all_output = " ".join(outputs.values()).lower()

    if vendor == "fortinet":
        global_out = outputs.get("ssh", "").lower()
        # SSH
        security["ssh_enabled"]  = True  # Si llegamos aquí, SSH funciona
        security["ssh_v2_only"]  = True  # FortiOS solo soporta SSH2
        # Telnet — buscar en global
        security["telnet_enabled"] = "set admin-telnet enable" in global_out
        # SNMP
        snmp_out = outputs.get("snmp", "").lower()
        security["snmp_enabled"]          = len(snmp_out) > 20
        security["snmp_v1_v2"]            = "community" in snmp_out
        security["snmp_community_public"] = "public" in snmp_out or "private" in snmp_out
        # ACLs / Políticas
        acl_out = outputs.get("acl", "")
        security["acl_configured"] = len(acl_out) > 50
        # NTP
        ntp_out = outputs.get("ntp", "").lower()
        security["ntp_configured"] = "ntpserver" in ntp_out or "server" in ntp_out
        # Logging
        log_out = outputs.get("logging", "").lower()
        security["logging_configured"] = len(log_out) > 20
        # AAA
        security["aaa_configured"]    = True  # FortiGate siempre tiene auth local
        security["login_protection"]  = True
        # Banner
        security["banner_configured"] = "set pre-login-banner" in global_out or "set post-login-banner" in global_out
        # Port Security / STP — no aplica en FortiGate
        security["port_security"] = False
        security["stp_configured"] = False

    else:
        ssh_out    = outputs.get("ssh", "").lower()
        telnet_out = outputs.get("telnet", "").lower()
        snmp_out   = outputs.get("snmp", "").lower()
        acl_out    = outputs.get("acl", "")
        ntp_out    = outputs.get("ntp", "").lower()
        log_out    = outputs.get("logging", "").lower()
        aaa_out    = outputs.get("aaa", "").lower()

        security["ssh_enabled"]           = "ssh" in ssh_out
        security["ssh_v2_only"]           = "version 2" in ssh_out or "v2" in ssh_out
        security["telnet_enabled"]        = "telnet" in telnet_out and "no telnet" not in telnet_out
        security["snmp_enabled"]          = bool(snmp_out) and len(snmp_out) > 10
        security["snmp_v1_v2"]            = "community" in snmp_out
        security["snmp_community_public"] = "public" in snmp_out or "private" in snmp_out
        security["acl_configured"]        = len(acl_out) > 20
        security["ntp_configured"]        = len(ntp_out) > 10 and "ntp" in ntp_out
        security["logging_configured"]    = len(log_out) > 10
        security["aaa_configured"]        = len(aaa_out) > 10
        security["login_protection"]      = security["aaa_configured"] or "login local" in all_output
        security["banner_configured"]     = len(outputs.get("banner", "")) > 5
        security["port_security"]         = "violation" in outputs.get("port_sec", "").lower()
        security["stp_configured"]        = len(outputs.get("spanning", "")) > 10

    # Chequeos detallados
    checks = [
        {"name": "SSH v2 habilitado",           "ok": security["ssh_v2_only"],              "rec": "Configurar SSH versión 2 únicamente"},
        {"name": "Telnet deshabilitado",         "ok": not security["telnet_enabled"],        "rec": "Deshabilitar Telnet — protocolo sin cifrado"},
        {"name": "SNMP sin comunidades default", "ok": not security["snmp_community_public"], "rec": "Cambiar comunidades 'public'/'private'"},
        {"name": "ACLs / Políticas configuradas","ok": security["acl_configured"],            "rec": "Configurar ACLs para restringir acceso"},
        {"name": "NTP configurado",              "ok": security["ntp_configured"],            "rec": "Configurar servidor NTP"},
        {"name": "Logging habilitado",           "ok": security["logging_configured"],        "rec": "Configurar logging a servidor Syslog"},
        {"name": "AAA / Login local",            "ok": security["login_protection"],          "rec": "Configurar AAA o login local"},
        {"name": "Banner de acceso",             "ok": security["banner_configured"],         "rec": "Configurar banner de advertencia legal"},
    ]
    if vendor != "fortinet":
        checks.append({"name": "Port Security", "ok": security["port_security"], "rec": "Habilitar port-security en puertos de acceso"})
        checks.append({"name": "Spanning Tree", "ok": security["stp_configured"], "rec": "Verificar configuración de STP/RSTP"})

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

    # Compatibilidad con template
    fw_status = "Políticas: " + ("Configuradas ✓" if security["acl_configured"] else "No configuradas")
    telnet_status = "Telnet: " + ("ACTIVO ⚠" if security["telnet_enabled"] else "Deshabilitado ✓")
    snmp_status = "SNMP: " + ("Comunidades default ⚠" if security["snmp_community_public"] else "Seguro ✓")
    ntp_status = "NTP: " + ("Configurado ✓" if security["ntp_configured"] else "No configurado")

    security["ufw_output"]        = f"{fw_status}\n{telnet_status}\n{snmp_status}\n{ntp_status}"
    security["ufw_active"]        = security["acl_configured"]
    security["firewalld_active"]  = False
    security["fail2ban_active"]   = security["login_protection"]
    security["fail2ban_status"]   = "Login: " + ("Configurado ✓" if security["login_protection"] else "No configurado")
    security["selinux"]           = "No aplica"
    security["selinux_enforcing"] = False
    security["apparmor"]          = "No aplica"
    security["sysctl_checks"]     = []
    security["suid_files"]        = []
    security["iptables"]          = outputs.get("acl", "Sin políticas detectadas")[:500]
    security["ssh_config_raw"]    = outputs.get("ssh", "")[:300]
    security["pending_updates"]   = 0

    security["user_checks"] = [
        {"name": "Telnet deshabilitado", "ok": not security["telnet_enabled"],
         "detail": "PELIGRO: Telnet activo" if security["telnet_enabled"] else "Telnet deshabilitado ✓",
         "severity": "danger" if security["telnet_enabled"] else "ok"},
        {"name": "SNMP seguro", "ok": not security["snmp_community_public"],
         "detail": "Comunidades default detectadas" if security["snmp_community_public"] else "Sin comunidades default ✓",
         "severity": "danger" if security["snmp_community_public"] else "ok"},
    ]

    return security


def _build_ports_data(interfaces):
    listening = []
    for iface in interfaces:
        ip_info = f" ({iface.get('ip', '')})" if iface.get('ip') else ""
        mode_info = iface.get('mode', '')
        listening.append({
            "port":      iface["name"],
            "addr":      "switch",
            "service":   f"Interfaz de red{ip_info}",
            "process":   f"{iface.get('speed','?')} {mode_info}".strip(),
            "public":    iface["up"],
            "dangerous": False,
            "risk":      "ok" if iface["up"] else "info"
        })
    return {
        "listening":         listening,
        "count_total":       len(listening),
        "count_dangerous":   0,
        "count_public":      sum(1 for i in interfaces if i["up"]),
        "connections":       [],
        "recommendations":   []
    }
