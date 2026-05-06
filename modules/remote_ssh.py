"""
Módulo: remote_ssh
Conexión SSH a servidores remotos y ejecución de comandos de hardening
"""

import paramiko
import json
import os
import socket
import time
from datetime import datetime

# Archivo donde se guardan los servidores registrados
SERVERS_FILE = os.path.join(os.path.dirname(__file__), "..", "servers.json")


# ── GESTIÓN DE SERVIDORES ─────────────────────────────────────────────────────

def load_servers():
    try:
        with open(SERVERS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_servers(servers):
    with open(SERVERS_FILE, "w") as f:
        json.dump(servers, f, indent=2)


def add_server(name, host, port, username, auth_type, password=None, key_path=None):
    servers = load_servers()
    # Verificar que no existe
    for s in servers:
        if s["host"] == host and s["port"] == port:
            return False, "Servidor ya registrado"
    server = {
        "id": f"{host}:{port}",
        "name": name,
        "host": host,
        "port": int(port),
        "username": username,
        "auth_type": auth_type,   # "password" o "key"
        "password": password,
        "key_path": key_path or "",
        "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_check": None,
        "status": "unknown"
    }
    servers.append(server)
    save_servers(servers)
    return True, "Servidor agregado"


def remove_server(server_id):
    servers = load_servers()
    servers = [s for s in servers if s["id"] != server_id]
    save_servers(servers)


def get_server(server_id):
    for s in load_servers():
        if s["id"] == server_id:
            return s
    return None


# ── CONEXIÓN SSH ──────────────────────────────────────────────────────────────

def _get_client(server):
    """Crear cliente SSH conectado al servidor"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": server["host"],
        "port": server["port"],
        "username": server["username"],
        "timeout": 10,
        "banner_timeout": 15,
    }
    if server["auth_type"] == "key" and server.get("key_path"):
        key_path = os.path.expanduser(server["key_path"])
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = server.get("password", "")
    client.connect(**kwargs)
    return client


def _run_remote(client, cmd, timeout=8):
    """Ejecutar comando en servidor remoto y devolver stdout"""
    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        return out or err
    except Exception:
        return ""


def test_connection(server):
    """Probar conexión SSH. Devuelve (ok: bool, mensaje: str)"""
    try:
        client = _get_client(server)
        result = _run_remote(client, "echo OK")
        client.close()
        if "OK" in result:
            return True, "Conexión exitosa"
        return False, "Conexión establecida pero sin respuesta"
    except paramiko.AuthenticationException:
        return False, "Error de autenticación — verificar usuario/contraseña/clave"
    except paramiko.SSHException as e:
        return False, f"Error SSH: {str(e)[:80]}"
    except socket.timeout:
        return False, "Timeout — servidor no responde en el tiempo límite"
    except ConnectionRefusedError:
        return False, "Conexión rechazada — verificar que SSH esté activo y el puerto sea correcto"
    except Exception as e:
        return False, f"Error: {str(e)[:80]}"


# ── ANÁLISIS REMOTO ───────────────────────────────────────────────────────────

def get_remote_stats(server):
    """Obtener estadísticas completas del servidor remoto"""
    result = {
        "server_id": server["id"],
        "server_name": server["name"],
        "host": server["host"],
        "port": server["port"],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "connected": False,
        "error": None
    }

    try:
        client = _get_client(server)
        result["connected"] = True

        # ── INFO BÁSICA ───────────────────────────────────────────────────────
        result["hostname"]  = _run_remote(client, "hostname")
        result["uptime"]    = _run_remote(client, "uptime -p")
        result["kernel"]    = _run_remote(client, "uname -r")
        result["ip"]        = _run_remote(client, "hostname -I | awk '{print $1}'")

        # OS
        os_raw = _run_remote(client, "grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"'")
        result["os"] = os_raw or _run_remote(client, "uname -s")

        # ── CPU ───────────────────────────────────────────────────────────────
        cpu = _run_remote(client, "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'")
        result["cpu_usage"] = (cpu.replace(",", ".") + "%") if cpu else "N/A"
        result["cpu_cores"] = _run_remote(client, "nproc") or "?"

        # ── MEMORIA ───────────────────────────────────────────────────────────
        mem = _run_remote(client, "free -m | awk '/^Mem:/ {print $2, $3}'")
        if mem:
            parts = mem.split()
            total, used = int(parts[0]), int(parts[1])
            result["mem_total"] = f"{total} MB"
            result["mem_used"]  = f"{used} MB"
            result["mem_pct"]   = round((used / total) * 100, 1) if total else 0
        else:
            result["mem_total"] = result["mem_used"] = "N/A"
            result["mem_pct"] = 0

        # ── DISCO ─────────────────────────────────────────────────────────────
        disk = _run_remote(client, "df -h / | awk 'NR==2 {print $2, $3, $5}'")
        if disk:
            parts = disk.split()
            result["disk_total"] = parts[0]
            result["disk_used"]  = parts[1]
            result["disk_pct"]   = int(parts[2].rstrip("%")) if parts[2].rstrip("%").isdigit() else 0
        else:
            result["disk_total"] = result["disk_used"] = "N/A"
            result["disk_pct"] = 0

        # ── CARGA ─────────────────────────────────────────────────────────────
        load = _run_remote(client, "cat /proc/loadavg")
        if load:
            p = load.split()
            result["load_1"] = p[0]
            result["load_5"] = p[1]
        else:
            result["load_1"] = result["load_5"] = "N/A"

        result["procs"] = _run_remote(client, "ps aux --no-headers | wc -l") or "?"

        # ── SEGURIDAD RÁPIDA ──────────────────────────────────────────────────
        ufw = _run_remote(client, "ufw status 2>/dev/null | head -1")
        result["ufw_active"] = "active" in ufw.lower()

        ssh_root = _run_remote(client, "grep '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null")
        result["ssh_root_login"] = "no" not in ssh_root.lower() if ssh_root else True

        fail2ban = _run_remote(client, "systemctl is-active fail2ban 2>/dev/null")
        result["fail2ban_active"] = fail2ban == "active"

        crowdsec = _run_remote(client, "systemctl is-active crowdsec 2>/dev/null")
        result["crowdsec_active"] = crowdsec == "active"

        # Puertos en escucha
        ports_raw = _run_remote(client, "ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | grep -oE '[0-9]+$' | sort -n | uniq")
        result["open_ports"] = ports_raw.splitlines() if ports_raw else []

        # Actualizaciones pendientes
        updates = _run_remote(client, "apt list --upgradable 2>/dev/null | grep -c upgradable || echo 0")
        try:
            result["pending_updates"] = int(updates) - 1  # restar header
        except ValueError:
            result["pending_updates"] = 0

        # Usuarios con sudo
        sudo_users = _run_remote(client, "grep -Po '^%?\\K[^:]+(?=.*ALL)' /etc/sudoers 2>/dev/null | head -5")
        result["sudo_users"] = sudo_users.splitlines() if sudo_users else []

        # Últimos logins
        last = _run_remote(client, "last -n 5 --time-format iso 2>/dev/null | head -5")
        result["last_logins"] = last.splitlines() if last else []

        # Servicios críticos
        svcs = ["ssh", "nginx", "apache2", "docker", "mysql", "postgresql"]
        svc_status = {}
        for svc in svcs:
            st = _run_remote(client, f"systemctl is-active {svc} 2>/dev/null")
            if st:
                svc_status[svc] = st
        result["services"] = svc_status

        # Score de seguridad rápido
        score = 100
        if not result["ufw_active"]:      score -= 20
        if result["ssh_root_login"]:      score -= 15
        if not result["fail2ban_active"]: score -= 10
        if result["pending_updates"] > 5: score -= 15
        if len(result["open_ports"]) > 10: score -= 10
        result["security_score"] = max(score, 0)

        client.close()

    except Exception as e:
        result["connected"] = False
        result["error"] = str(e)[:120]

    return result


def get_all_servers_status():
    """Obtener estado rápido de todos los servidores registrados"""
    servers = load_servers()
    results = []
    for server in servers:
        stats = get_remote_stats(server)
        # Actualizar last_check en el archivo
        all_servers = load_servers()
        for s in all_servers:
            if s["id"] == server["id"]:
                s["last_check"] = stats["timestamp"]
                s["status"] = "online" if stats["connected"] else "offline"
        save_servers(all_servers)
        results.append(stats)
    return results
