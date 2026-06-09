"""
Módulo: remote_ssh
Conexión SSH a servidores remotos — análisis completo de hardening
"""

import paramiko
import json
import os
import socket
import re
from datetime import datetime

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
    for s in servers:
        if s["host"] == host and s["port"] == int(port):
            return False, "Servidor ya registrado"
    server = {
        "id": f"{host}:{port}",
        "name": name,
        "host": host,
        "port": int(port),
        "username": username,
        "auth_type": auth_type,
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
    servers = [s for s in load_servers() if s["id"] != server_id]
    save_servers(servers)


def get_server(server_id):
    for s in load_servers():
        if s["id"] == server_id:
            return s
    return None


# ── CONEXIÓN SSH ──────────────────────────────────────────────────────────────

def _get_client(server):
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
        kwargs["key_filename"] = os.path.expanduser(server["key_path"])
    else:
        kwargs["password"] = server.get("password", "")
    client.connect(**kwargs)
    return client


def _run(client, cmd, timeout=10):
    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        return out or err
    except Exception:
        return ""


def test_connection(server):
    try:
        client = _get_client(server)
        result = _run(client, "echo OK")
        client.close()
        return ("OK" in result), ("Conexión exitosa" if "OK" in result else "Sin respuesta")
    except paramiko.AuthenticationException:
        return False, "Error de autenticación"
    except socket.timeout:
        return False, "Timeout — servidor no responde"
    except ConnectionRefusedError:
        return False, "Conexión rechazada — verificar puerto SSH"
    except Exception as e:
        return False, str(e)[:80]


# ── RECOPILACIÓN DE DATOS ─────────────────────────────────────────────────────

def get_remote_stats(server):
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

        # ── GENERAL ───────────────────────────────────────────────────────────
        result["hostname"]   = _run(client, "hostname")
        result["uptime"]     = _run(client, "uptime -p")
        result["kernel"]     = _run(client, "uname -r")
        result["ip"]         = _run(client, "hostname -I | awk '{print $1}'")
        result["cpu_cores"]  = _run(client, "nproc") or "?"
        result["procs"]      = _run(client, "ps aux --no-headers | wc -l") or "?"

        os_raw = _run(client, "grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"'")
        result["os"] = os_raw or _run(client, "uname -s")

        cpu = _run(client, "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'")
        result["cpu_usage"] = (cpu.replace(",", ".") + "%") if cpu else "N/A"

        mem = _run(client, "free -m | awk '/^Mem:/ {print $2, $3}'")
        if mem:
            parts = mem.split()
            total, used = int(parts[0]), int(parts[1])
            result["mem_total"] = f"{total} MB"
            result["mem_used"]  = f"{used} MB"
            result["mem_pct"]   = round((used / total) * 100, 1) if total else 0
        else:
            result["mem_total"] = result["mem_used"] = "N/A"
            result["mem_pct"] = 0

        disk = _run(client, "df -h / | awk 'NR==2 {print $2, $3, $5}'")
        if disk:
            parts = disk.split()
            result["disk_total"] = parts[0]
            result["disk_used"]  = parts[1]
            result["disk_pct"]   = int(parts[2].rstrip("%")) if parts[2].rstrip("%").isdigit() else 0
        else:
            result["disk_total"] = result["disk_used"] = "N/A"
            result["disk_pct"] = 0

        load = _run(client, "cat /proc/loadavg")
        if load:
            p = load.split()
            result["load_1"]  = p[0]
            result["load_5"]  = p[1]
            result["load_15"] = p[2]
        else:
            result["load_1"] = result["load_5"] = result["load_15"] = "N/A"

        svcs = ["ssh", "sshd", "nginx", "apache2", "docker", "mysql",
                "postgresql", "fail2ban", "crowdsec", "ufw"]
        svc_status = []
        for svc in svcs:
            st = _run(client, f"systemctl is-active {svc} 2>/dev/null")
            if st in ["active", "inactive", "failed"]:
                svc_status.append({"name": svc, "status": st, "ok": st == "active"})
        result["services"] = svc_status

        last = _run(client, "last -n 8 2>/dev/null | head -8")
        result["last_logins"] = last.splitlines() if last else []

        # ── SEGURIDAD ─────────────────────────────────────────────────────────
        security = {}

        # UFW
        ufw_raw = _run(client, "ufw status 2>/dev/null")
        security["ufw_active"] = "active" in ufw_raw.lower()

        # firewalld (Fedora/RHEL)
        fwd = _run(client, "sudo firewall-cmd --state 2>/dev/null")
        security["firewalld_active"] = fwd.strip() == "running"

        # Mostrar el firewall disponible
        if security["ufw_active"]:
            security["ufw_output"] = ufw_raw
        elif security["firewalld_active"]:
            security["ufw_output"] = _run(client, "sudo firewall-cmd --list-all 2>/dev/null")
        else:
            security["ufw_output"] = "Sin firewall activo detectado"

        # iptables
        ipt = _run(client, "iptables -L INPUT -n --line-numbers 2>/dev/null | head -20")
        security["iptables"] = ipt if ipt else "Sin acceso a iptables"

        # SSH config
        ssh_cfg = _run(client, "grep -E '^(Port|PermitRootLogin|PasswordAuthentication|"
                               "PubkeyAuthentication|MaxAuthTries|X11Forwarding|"
                               "PermitEmptyPasswords)' /etc/ssh/sshd_config 2>/dev/null")
        security["ssh_config_raw"] = ssh_cfg or "No se pudo leer sshd_config"

        ssh_checks = []
        cfg = ssh_cfg or ""
        ssh_checks.append({"name": "PermitRootLogin no",
                           "ok": "PermitRootLogin no" in cfg,
                           "rec": "Deshabilitar root login SSH"})
        ssh_checks.append({"name": "PasswordAuthentication no",
                           "ok": "PasswordAuthentication no" in cfg,
                           "rec": "Usar solo autenticación por clave"})
        ssh_checks.append({"name": "X11Forwarding no",
                           "ok": "X11Forwarding no" in cfg,
                           "rec": "Deshabilitar X11 Forwarding"})
        ssh_checks.append({"name": "PubkeyAuthentication yes",
                           "ok": "PubkeyAuthentication yes" in cfg,
                           "rec": "Habilitar autenticación por clave pública"})
        m = re.search(r"MaxAuthTries\s+(\d+)", cfg)
        ssh_checks.append({"name": "MaxAuthTries <= 3",
                           "ok": int(m.group(1)) <= 3 if m else False,
                           "rec": "Reducir MaxAuthTries a 3 o menos"})
        security["ssh_checks"] = ssh_checks

        # fail2ban
        f2b = _run(client, "systemctl is-active fail2ban 2>/dev/null")
        security["fail2ban_active"] = f2b == "active"
        f2b_status = _run(client, "fail2ban-client status 2>/dev/null")
        security["fail2ban_status"] = f2b_status or "fail2ban no activo"
        f2b_ssh = _run(client, "fail2ban-client status sshd 2>/dev/null || fail2ban-client status ssh 2>/dev/null")
        security["fail2ban_ssh"] = f2b_ssh or "Jail SSH no configurado"

        # SELinux / AppArmor
        selinux = _run(client, "getenforce 2>/dev/null")
        security["selinux"] = selinux or "No disponible"
        security["selinux_enforcing"] = selinux == "Enforcing"
        apparmor = _run(client, "apparmor_status 2>/dev/null | head -3")
        security["apparmor"] = apparmor or "No disponible"

        # sysctl checks
        sysctl_checks = []
        sysctl_items = [
            ("ASLR habilitado",        "kernel.randomize_va_space", "2"),
            ("SYN Cookies anti-flood", "net.ipv4.tcp_syncookies",   "1"),
            ("ICMP Redirects OFF",     "net.ipv4.conf.all.accept_redirects", "0"),
            ("Reverse Path Filtering", "net.ipv4.conf.all.rp_filter", "1"),
            ("IPv6 deshabilitado",     "net.ipv6.conf.all.disable_ipv6", "1"),
        ]
        for name, key, expected in sysctl_items:
            val = _run(client, f"sysctl {key} 2>/dev/null | awk '{{print $3}}'")
            sysctl_checks.append({"name": name, "key": key,
                                  "value": val or "N/A", "ok": val == expected,
                                  "expected": expected})
        security["sysctl_checks"] = sysctl_checks

        # Actualizaciones pendientes
        updates_apt = _run(client, "apt list --upgradable 2>/dev/null | grep -c upgradable")
        updates_dnf = _run(client, "dnf check-update 2>/dev/null | grep -c '^[a-Z]'")
        try:
            cnt = int(updates_apt) - 1
        except ValueError:
            try:
                cnt = int(updates_dnf)
            except ValueError:
                cnt = 0
        security["pending_updates"] = max(cnt, 0)

        # SUID files
        suid = _run(client, "find /usr /bin /sbin -perm /4000 2>/dev/null | head -10")
        security["suid_files"] = suid.splitlines() if suid else []

        # Score
        score = 100
        if not security["ufw_active"] and not security["firewalld_active"]: score -= 20
        if any(not c["ok"] for c in ssh_checks if "PermitRootLogin" in c["name"]): score -= 15
        if not security["fail2ban_active"]: score -= 10
        if security["pending_updates"] > 5: score -= 15
        if not any(c["ok"] for c in sysctl_checks if "ASLR" in c["name"]): score -= 10
        security["score"] = max(score, 0)

        result["security"]         = security
        result["ufw_active"]       = security["ufw_active"]
        result["firewalld_active"] = security["firewalld_active"]
        result["ssh_root_login"]   = not any(c["ok"] for c in ssh_checks if "PermitRootLogin" in c["name"])
        result["fail2ban_active"]  = security["fail2ban_active"]
        result["security_score"]   = security["score"]
        result["pending_updates"]  = security["pending_updates"]

        # ── CROWDSEC ──────────────────────────────────────────────────────────
        crowdsec = {}
        cs_ver = _run(client, "cscli version 2>&1 | head -1")
        crowdsec["available"] = bool(cs_ver) and "not found" not in cs_ver.lower()
        crowdsec["version"]   = cs_ver if crowdsec["available"] else "No instalado"

        cs_svc = _run(client, "systemctl is-active crowdsec 2>/dev/null")
        crowdsec["service_active"] = cs_svc == "active"
        crowdsec["service_status"] = cs_svc or "unknown"

        if crowdsec["available"]:
            dec_raw = _run(client, "cscli decisions list -o json 2>/dev/null")
            decisions = []
            try:
                if dec_raw and dec_raw.strip() not in ["null", "", "[]"]:
                    for d in (json.loads(dec_raw) or [])[:10]:
                        decisions.append({
                            "ip": d.get("value", "?"),
                            "reason": d.get("reason", "?"),
                            "action": d.get("type", "ban"),
                            "duration": d.get("duration", "?"),
                            "scenario": d.get("scenario", "?")
                        })
            except (json.JSONDecodeError, TypeError):
                pass
            crowdsec["decisions"] = decisions
            crowdsec["decisions_count"] = len(decisions)

            alert_raw = _run(client, "cscli alerts list -o json 2>/dev/null")
            alerts = []
            try:
                if alert_raw and alert_raw.strip() not in ["null", "", "[]"]:
                    for a in (json.loads(alert_raw) or [])[:8]:
                        alerts.append({
                            "scenario": a.get("scenario", "?"),
                            "ip": a.get("sourceRange", "?"),
                            "created_at": (a.get("createdAt", "?"))[:19]
                        })
            except (json.JSONDecodeError, TypeError):
                pass
            crowdsec["alerts"] = alerts
            crowdsec["alerts_count"] = len(alerts)

            bc_raw = _run(client, "cscli bouncers list -o json 2>/dev/null")
            bouncers = []
            try:
                if bc_raw and bc_raw.strip() not in ["null", "", "[]"]:
                    for b in (json.loads(bc_raw) or []):
                        bouncers.append({
                            "name": b.get("name", "?"),
                            "type": b.get("type", "?"),
                            "active": b.get("last_pull") is not None
                        })
            except (json.JSONDecodeError, TypeError):
                pass
            crowdsec["bouncers"] = bouncers

            hub_raw = _run(client, "cscli hub list 2>/dev/null | head -20")
            crowdsec["hub_raw"] = hub_raw or "Sin datos del hub"

            logs = _run(client, "journalctl -u crowdsec -n 8 --no-pager 2>/dev/null")
            crowdsec["recent_logs"] = logs.splitlines()[-8:] if logs else []
        else:
            crowdsec["decisions"] = []
            crowdsec["decisions_count"] = 0
            crowdsec["alerts"] = []
            crowdsec["alerts_count"] = 0
            crowdsec["bouncers"] = []
            crowdsec["hub_raw"] = ""
            crowdsec["recent_logs"] = []
            crowdsec["install_hint"] = (
                "# Debian/Ubuntu:\ncurl -s https://packagecloud.io/install/repositories/"
                "crowdsec/crowdsec/script.deb.sh | sudo bash\nsudo apt install crowdsec -y\n\n"
                "# Fedora/RHEL:\ncurl -L https://github.com/crowdsecurity/crowdsec/releases/"
                "latest/download/crowdsec-release.tgz -o crowdsec-release.tgz\n"
                "tar xzvf crowdsec-release.tgz && cd crowdsec-v*/\nsudo ./wizard.sh --unattended"
            )

        result["crowdsec"] = crowdsec
        result["crowdsec_active"] = crowdsec["service_active"]

        # ── USUARIOS ──────────────────────────────────────────────────────────
        users_data = {}

        passwd_raw = _run(client, "awk -F: '$3>=1000 || $3==0 {print $1,$3,$6,$7}' /etc/passwd 2>/dev/null")
        real_users = []
        for line in passwd_raw.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                shell = parts[3]
                real_users.append({
                    "username": parts[0],
                    "uid": parts[1],
                    "home": parts[2],
                    "shell": shell,
                    "can_login": shell not in ["/usr/sbin/nologin", "/bin/false", "/sbin/nologin"],
                    "is_root": parts[1] == "0"
                })
        users_data["real_users"] = real_users

        uid0 = _run(client, "awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null")
        users_data["uid0_users"] = uid0.splitlines() if uid0 else ["root"]
        users_data["uid0_warning"] = len(users_data["uid0_users"]) > 1

        sudo_raw = _run(client, "grep -Po '^%?\\K[^:]+(?=.*ALL)' /etc/sudoers 2>/dev/null")
        sudo_grp = _run(client, "getent group sudo wheel admin 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n'")
        sudo_list = list(set((sudo_raw + "\n" + sudo_grp).splitlines()))
        users_data["sudo_users"] = [u for u in sudo_list if u.strip()]

        passwd_status = []
        pw_raw = _run(client, "passwd -S -a 2>/dev/null | head -20")
        if pw_raw:
            for line in pw_raw.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    passwd_status.append({
                        "user": parts[0],
                        "status": parts[1],
                        "locked": parts[1] in ["L", "LK"],
                        "no_password": parts[1] == "NP",
                        "has_password": parts[1] in ["P", "PS"]
                    })
        users_data["passwd_status"] = passwd_status

        crit_groups = []
        for grp_name in ["docker", "sudo", "wheel", "shadow", "disk", "adm"]:
            grp_raw = _run(client, f"getent group {grp_name} 2>/dev/null")
            if grp_raw:
                parts = grp_raw.split(":")
                members = parts[3].split(",") if len(parts) > 3 and parts[3] else []
                crit_groups.append({
                    "name": grp_name,
                    "gid": parts[2] if len(parts) > 2 else "?",
                    "members": [m for m in members if m],
                    "count": len([m for m in members if m])
                })
        users_data["critical_groups"] = crit_groups

        lastlog = _run(client, "lastlog 2>/dev/null | awk 'NR>1 && $2!=\"**\" {print}' | head -10")
        users_data["lastlog"] = lastlog.splitlines() if lastlog else []

        user_checks = []
        empty_pw = [p for p in passwd_status if p.get("no_password") and
                    p.get("user") not in ["sync", "halt", "shutdown"]]
        user_checks.append({
            "name": "Usuarios sin contraseña",
            "ok": len(empty_pw) == 0,
            "detail": f"{len(empty_pw)} usuario(s) sin contraseña" if empty_pw else "Ninguno",
            "severity": "danger" if empty_pw else "ok"
        })
        user_checks.append({
            "name": "UID 0 único",
            "ok": len(users_data["uid0_users"]) <= 1,
            "detail": f"Usuarios con UID 0: {', '.join(users_data['uid0_users'])}",
            "severity": "danger" if len(users_data["uid0_users"]) > 1 else "ok"
        })
        docker_members = next((g["members"] for g in crit_groups if g["name"] == "docker"), [])
        user_checks.append({
            "name": "Grupo docker (escalación)",
            "ok": len(docker_members) == 0,
            "detail": f"Miembros: {', '.join(docker_members)}" if docker_members else "Sin miembros",
            "severity": "warn" if docker_members else "ok"
        })
        users_data["security_checks"] = user_checks
        result["users"] = users_data

        # ── PUERTOS ───────────────────────────────────────────────────────────
        ports_data = {}
        DANGEROUS = {21,23,135,139,445,3389,5900,6379,9200,27017,4444,1433,2049}
        KNOWN = {
            20:"FTP-Data", 21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP",
            53:"DNS", 80:"HTTP", 110:"POP3", 139:"NetBIOS", 143:"IMAP",
            161:"SNMP", 389:"LDAP", 443:"HTTPS", 445:"SMB", 465:"SMTPS",
            587:"SMTP-Sub", 631:"CUPS", 993:"IMAPS", 995:"POP3S",
            1433:"MSSQL", 2049:"NFS", 3000:"Dev-HTTP", 3306:"MySQL",
            3389:"RDP", 4444:"Metasploit", 5000:"Dev-HTTP", 5432:"PostgreSQL",
            5900:"VNC", 6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt",
            9200:"Elasticsearch", 27017:"MongoDB"
        }

        ss_raw = _run(client, "ss -tlnup 2>/dev/null")
        if not ss_raw:
            ss_raw = _run(client, "netstat -tlnup 2>/dev/null")

        listening = []
        seen_ports = set()
        for line in ss_raw.splitlines():
            if "LISTEN" not in line:
                continue
            port_match = re.search(r":(\d+)\s", line)
            if not port_match:
                continue
            port = int(port_match.group(1))
            if port in seen_ports:
                continue
            seen_ports.add(port)

            addr_match = re.search(r"(\S+):(\d+)\s+\S+:(\*|\d+)", line)
            addr = addr_match.group(1) if addr_match else "?"
            is_public = addr in ["0.0.0.0", "::", "*", ""]

            proc_match = re.search(r'"([^"]+)"', line)
            process = proc_match.group(1) if proc_match else "?"

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
                "port": port,
                "addr": addr,
                "service": service,
                "process": process,
                "public": is_public,
                "dangerous": is_dangerous,
                "risk": risk
            })

        listening.sort(key=lambda x: x["port"])
        ports_data["listening"] = listening
        ports_data["count_total"] = len(listening)
        ports_data["count_dangerous"] = len([p for p in listening if p["dangerous"]])
        ports_data["count_public"] = len([p for p in listening if p["public"]])

        conns_raw = _run(client, "ss -tnp state established 2>/dev/null | head -15")
        connections = []
        for line in conns_raw.splitlines():
            if re.search(r"\d+\.\d+\.\d+\.\d+:\d+", line):
                parts = line.split()
                if len(parts) >= 4:
                    connections.append({
                        "local": parts[3],
                        "remote": parts[4] if len(parts) > 4 else "?"
                    })
        ports_data["connections"] = connections[:12]

        recommendations = []
        for p in listening:
            if p["dangerous"] and p["public"]:
                recommendations.append({
                    "port": p["port"],
                    "service": p["service"],
                    "message": f"Puerto {p['port']} ({p['service']}) expuesto públicamente — CERRAR o restringir",
                    "severity": "danger"
                })
        ports_data["recommendations"] = recommendations
        result["ports"] = ports_data
        result["open_ports"] = [str(p["port"]) for p in listening]
        result["security_score"] = security["score"]

        client.close()

    except Exception as e:
        result["connected"] = False
        result["error"] = str(e)[:120]

    return result


def get_all_servers_status():
    servers = load_servers()
    results = []
    for server in servers:
        stats = get_remote_stats(server)
        all_servers = load_servers()
        for s in all_servers:
            if s["id"] == server["id"]:
                s["last_check"] = stats["timestamp"]
                s["status"] = "online" if stats["connected"] else "offline"
        save_servers(all_servers)
        results.append(stats)
    return results
