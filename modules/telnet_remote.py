"""
Módulo: telnet_remote
Conexión Telnet a switches legacy (Cisco Catalyst 2960, etc.)
Análisis de hardening y terminal web interactiva
"""

import asyncio
import telnetlib3
import threading
import time
import re
from datetime import datetime


# ── CONEXIÓN TELNET BÁSICA (síncrona para análisis) ───────────────────────────

def _run_telnet_commands(host, port, username, password, commands, timeout=15):
    from modules.credential_manager import decrypt_password
    password = decrypt_password(password)
    """
    Conectar por Telnet, autenticar y ejecutar lista de comandos.
    Devuelve dict {comando: output}
    """
    results = {}

    async def _telnet_session():
        try:
            reader, writer = await asyncio.wait_for(
                telnetlib3.open_connection(host, port, encoding="utf-8"),
                timeout=timeout
            )

            async def read_until(patterns, max_wait=8):
                """Leer hasta encontrar alguno de los patrones"""
                buf = ""
                deadline = asyncio.get_event_loop().time() + max_wait
                while asyncio.get_event_loop().time() < deadline:
                    try:
                        chunk = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                        if chunk:
                            buf += chunk
                            for p in patterns:
                                if p in buf:
                                    return buf
                    except asyncio.TimeoutError:
                        pass
                return buf

            # Esperar prompt de usuario/contraseña
            banner = await read_until(["Username:", "username:", "Password:", "password:", ">", "#"], max_wait=10)

            # Autenticación
            if "Username:" in banner or "username:" in banner:
                writer.write(username + "\r\n")
                await read_until(["Password:", "password:"], max_wait=5)
                writer.write(password + "\r\n")
            elif "Password:" in banner or "password:" in banner:
                writer.write(password + "\r\n")

            # Esperar prompt
            prompt_buf = await read_until([">", "#"], max_wait=8)

            # Detectar si necesita enable
            if ">" in prompt_buf and "#" not in prompt_buf:
                writer.write("enable\r\n")
                en_buf = await read_until(["Password:", "#"], max_wait=5)
                if "Password:" in en_buf:
                    writer.write(password + "\r\n")
                    await read_until(["#"], max_wait=5)

            # Deshabilitar paginación
            writer.write("terminal length 0\r\n")
            await read_until(["#"], max_wait=3)

            # Ejecutar comandos
            for cmd in commands:
                if not cmd:
                    continue
                writer.write(cmd + "\r\n")
                output = await read_until(["#", ">"], max_wait=8)
                # Limpiar el comando del output
                clean = _clean_output(output, cmd)
                results[cmd] = clean

            writer.write("exit\r\n")
            writer.close()

        except asyncio.TimeoutError:
            results["__error__"] = "Timeout — el dispositivo no respondió"
        except Exception as e:
            results["__error__"] = str(e)[:100]

    # Ejecutar el coroutine en un event loop nuevo
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_telnet_session())
    finally:
        loop.close()

    return results


def _clean_output(output, cmd):
    """Limpiar output de Telnet — remover el comando y el prompt"""
    ansi = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    output = ansi.sub('', output)
    # Remover el comando del inicio
    lines = output.splitlines()
    cleaned = []
    skip_first = True
    for line in lines:
        if skip_first and cmd.strip() in line:
            skip_first = False
            continue
        # Remover líneas de prompt al final
        if re.search(r'[\w\-]+[>#]\s*$', line) and len(line) < 50:
            continue
        cleaned.append(line)
    return "\n".join(cleaned).strip()


def test_connection(server):
    """Probar conexión Telnet"""
    try:
        results = _run_telnet_commands(
            host=server["host"],
            port=server.get("port", 23),
            username=server.get("username", ""),
            password=server.get("password", ""),
            commands=["show version | include Cisco"],
            timeout=12
        )
        if "__error__" in results:
            return False, results["__error__"]
        return True, "Conexión Telnet exitosa"
    except Exception as e:
        return False, str(e)[:80]


def get_telnet_stats(server):
    """Análisis completo del switch vía Telnet"""
    result = {
        "server_id":   server["id"],
        "server_name": server["name"],
        "host":        server["host"],
        "port":        server.get("port", 23),
        "os_type":     "switch",
        "protocol":    "telnet",
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "connected":   False,
        "error":       None,
        "vendor":      "cisco"  # Telnet legacy generalmente Cisco
    }

    commands = [
        "show version",
        "show vlan brief",
        "show interfaces status",
        "show running-config | include username",
        "show running-config | include ip ssh",
        "show running-config | include transport input",
        "show running-config | include snmp-server community",
        "show running-config | include ntp",
        "show running-config | include logging",
        "show running-config | include aaa",
        "show processes cpu sorted | head 5",
        "show ip access-lists",
        "show port-security",
        "show spanning-tree summary",
    ]

    try:
        outputs = _run_telnet_commands(
            host=server["host"],
            port=server.get("port", 23),
            username=server.get("username", ""),
            password=server.get("password", ""),
            commands=commands,
            timeout=20
        )

        if "__error__" in outputs:
            result["error"] = outputs["__error__"]
            return result

        result["connected"] = True

        # Reusar parsers de switch_remote
        from modules.switch_remote import (
            _parse_hostname, _parse_os, _parse_firmware,
            _parse_uptime, _parse_cpu, _parse_mem_pct,
            _parse_vlans, _parse_interfaces, _parse_users,
            _analyze_security, _build_ports_data
        )

        ver_out = outputs.get("show version", "")
        vendor  = "cisco"
        result["vendor"] = vendor

        # Mapear outputs al formato esperado por los parsers
        mapped = {
            "hostname":   outputs.get("show version", ""),
            "cpu":        outputs.get("show processes cpu", ""),
            "memory":     outputs.get("show version", ""),
            "uptime":     outputs.get("show version", ""),
            "vlans":      outputs.get("show vlan brief", ""),
            "interfaces": outputs.get("show interfaces status", ""),
            "users":      outputs.get("show running-config | include username", ""),
            "ssh":        outputs.get("show running-config | include ip ssh", ""),
            "telnet":     outputs.get("show running-config | include transport input", ""),
            "snmp":       outputs.get("show running-config | include snmp-server community", ""),
            "ntp":        outputs.get("show running-config | include ntp", ""),
            "logging":    outputs.get("show running-config | include logging", ""),
            "aaa":        outputs.get("show running-config | include aaa", ""),
            "acl":        outputs.get("show ip access-lists", ""),
            "port_sec":   outputs.get("show port-security", ""),
            "spanning":   outputs.get("show spanning-tree summary", ""),
            "banner":     "",
        }

        result["version_raw"] = ver_out
        result["hostname"]    = _parse_hostname(mapped["hostname"], vendor, ver_out)
        result["os"]          = _parse_os(ver_out, vendor)
        result["kernel"]      = _parse_firmware(ver_out, vendor)
        result["uptime"]      = _parse_uptime(ver_out, vendor, "")
        result["ip"]          = server["host"]
        result["cpu_usage"]   = _parse_cpu(mapped["cpu"], vendor)
        result["mem_pct"]     = _parse_mem_pct(mapped["memory"], vendor)
        result["mem_used"]    = "N/A"
        result["mem_total"]   = "N/A"
        result["disk_pct"]    = 0
        result["disk_used"]   = "N/A"
        result["disk_total"]  = "N/A"
        result["procs"]       = "N/A"
        result["load_1"]      = "N/A"
        result["load_5"]      = "N/A"
        result["load_15"]     = "N/A"
        result["cpu_cores"]   = "N/A"
        result["services"]    = []
        result["last_logins"] = []
        result["vlans"]       = _parse_vlans(mapped["vlans"], vendor)
        result["interfaces"]  = _parse_interfaces(mapped["interfaces"], vendor)
        result["switch_users"]= _parse_users(mapped["users"], vendor)

        security = _analyze_security(mapped, vendor, ver_out)
        # Telnet activo por definición
        security["telnet_enabled"] = True
        security["ssh_checks"] = [c for c in security.get("ssh_checks", [])]
        # Recalcular score con telnet activo
        security["score"] = max(security.get("score", 100) - 25, 0)

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
            "version": "No aplica en switches",
            "service_active": False,
            "service_status": "N/A",
            "decisions": [], "decisions_count": 0,
            "alerts": [],    "alerts_count": 0,
            "bouncers": [],  "hub_raw": "",
            "recent_logs": [],
            "install_hint": "CrowdSec no es compatible con switches de red"
        }

        result["users"] = {
            "real_users": [
                {"username": u["username"], "uid": u.get("privilege", "?"),
                 "home": "N/A", "shell": "CLI",
                 "can_login": True,
                 "is_root": u.get("privilege", "") in ["15", "admin"]}
                for u in result["switch_users"]
            ],
            "sudo_users":    [u["username"] for u in result["switch_users"]
                              if u.get("privilege") in ["15", "admin"]],
            "uid0_users":    [],
            "uid0_warning":  False,
            "passwd_status": [],
            "lastlog":       [],
            "critical_groups": [],
            "security_checks": security.get("user_checks", [])
        }

    except Exception as e:
        result["connected"] = False
        result["error"] = str(e)[:120]

    return result


# ── TERMINAL TELNET INTERACTIVA ───────────────────────────────────────────────

_telnet_sessions = {}
_telnet_lock = threading.Lock()


def connect_telnet_terminal(sid, server, socketio):
    """Conectar terminal Telnet interactiva via WebSocket"""

    async def _session():
        try:
            reader, writer = await asyncio.wait_for(
                telnetlib3.open_connection(
                    server["host"],
                    server.get("port", 23),
                    encoding="utf-8"
                ),
                timeout=15
            )

            with _telnet_lock:
                _telnet_sessions[sid] = {
                    "reader": reader,
                    "writer": writer,
                    "active": True,
                    "loop":   asyncio.get_event_loop()
                }

            # Proceso de autenticación automática
            buf = ""
            deadline = asyncio.get_event_loop().time() + 10
            while asyncio.get_event_loop().time() < deadline:
                try:
                    chunk = await asyncio.wait_for(reader.read(512), timeout=0.5)
                    if chunk:
                        buf += chunk
                        socketio.emit("ssh_output", {"output": chunk}, to=sid)

                        if "Username:" in buf or "username:" in buf:
                            await asyncio.sleep(0.3)
                            writer.write(server["username"] + "\r\n")
                            buf = ""
                        elif "Password:" in buf or "password:" in buf:
                            await asyncio.sleep(0.3)
                            writer.write(server.get("password", "") + "\r\n")
                            buf = ""
                        elif "#" in buf or ">" in buf:
                            break
                except asyncio.TimeoutError:
                    if "#" in buf or ">" in buf:
                        break

            socketio.emit("ssh_connected", {
                "host": server["host"],
                "message": "Conexión Telnet establecida"
            }, to=sid)

            # Deshabilitar paginación
            await asyncio.sleep(0.5)
            writer.write("terminal length 0\r\n")

            # Loop de lectura
            while True:
                with _telnet_lock:
                    sess = _telnet_sessions.get(sid)
                    if not sess or not sess.get("active"):
                        break
                try:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=0.1)
                    if chunk:
                        socketio.emit("ssh_output", {"output": chunk}, to=sid)
                    elif chunk == "":
                        break
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    break

            socketio.emit("ssh_closed", {}, to=sid)

        except asyncio.TimeoutError:
            socketio.emit("ssh_error", {
                "message": "Timeout — el dispositivo no respondió en 15 segundos"
            }, to=sid)
        except Exception as e:
            socketio.emit("ssh_error", {"message": str(e)[:100]}, to=sid)

    loop = asyncio.new_event_loop()
    with _telnet_lock:
        if sid in _telnet_sessions:
            _telnet_sessions[sid]["loop"] = loop

    try:
        loop.run_until_complete(_session())
    finally:
        loop.close()
        disconnect_telnet(sid)


def send_telnet_input(sid, data):
    """Enviar input al canal Telnet"""
    with _telnet_lock:
        sess = _telnet_sessions.get(sid)
    if sess and sess.get("writer"):
        try:
            sess["writer"].write(data)
        except Exception:
            pass


def disconnect_telnet(sid):
    """Cerrar sesión Telnet"""
    with _telnet_lock:
        sess = _telnet_sessions.pop(sid, None)
    if sess:
        try:
            sess["active"] = False
            if sess.get("writer"):
                sess["writer"].close()
        except Exception:
            pass
