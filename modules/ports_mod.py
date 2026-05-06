"""
Módulo: ports_mod
Análisis de puertos — abiertos, en escucha, peligrosos, firewall
"""

import subprocess
import re
from datetime import datetime


def _run(cmd, shell=True):
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=15)
        return r.stdout.strip()
    except Exception:
        return ""


# Puertos conocidos y su descripción
KNOWN_PORTS = {
    20: ("FTP-Data", "warn"), 21: ("FTP", "danger"), 22: ("SSH", "ok"),
    23: ("Telnet", "danger"), 25: ("SMTP", "warn"), 53: ("DNS", "warn"),
    80: ("HTTP", "ok"), 110: ("POP3", "warn"), 111: ("RPCBind", "danger"),
    135: ("MS-RPC", "danger"), 139: ("NetBIOS", "danger"), 143: ("IMAP", "warn"),
    161: ("SNMP", "danger"), 389: ("LDAP", "warn"), 443: ("HTTPS", "ok"),
    445: ("SMB", "danger"), 465: ("SMTPS", "warn"), 514: ("Syslog", "warn"),
    587: ("SMTP-Sub", "warn"), 631: ("CUPS", "warn"), 993: ("IMAPS", "ok"),
    995: ("POP3S", "ok"), 1433: ("MSSQL", "danger"), 1521: ("Oracle", "danger"),
    2049: ("NFS", "danger"), 2181: ("ZooKeeper", "warn"), 3000: ("Dev-HTTP", "warn"),
    3306: ("MySQL", "warn"), 3389: ("RDP", "danger"), 4444: ("Metasploit", "danger"),
    4567: ("App-Server", "warn"), 5000: ("Dev-HTTP", "warn"), 5432: ("PostgreSQL", "warn"),
    5900: ("VNC", "danger"), 6379: ("Redis", "danger"), 6443: ("K8s-API", "warn"),
    6666: ("IRC/Trojan", "danger"), 8080: ("HTTP-Alt", "warn"), 8443: ("HTTPS-Alt", "warn"),
    8888: ("Jupyter", "warn"), 9000: ("PHP-FPM/Portainer", "warn"),
    9090: ("Prometheus", "warn"), 9200: ("Elasticsearch", "danger"),
    9300: ("Elasticsearch-Cluster", "danger"), 27017: ("MongoDB", "danger"),
}

DANGEROUS_PORTS = {p for p, (_, risk) in KNOWN_PORTS.items() if risk == "danger"}


def get_ports_info():
    data = {}

    # ── PUERTOS EN ESCUCHA (ss) ──────────────────────────────────────────────
    ss_out = _run("ss -tlnup 2>/dev/null")
    if not ss_out:
        ss_out = _run("netstat -tlnup 2>/dev/null")

    listening = []
    for line in ss_out.splitlines():
        # Parsear líneas de ss/netstat
        if "LISTEN" not in line and "listen" not in line.lower():
            continue
        # ss format: State Recv-Q Send-Q LocalAddr:Port PeerAddr:Port Process
        parts = line.split()
        if not parts:
            continue

        local = ""
        process = ""

        # ss moderno
        if parts[0] in ["LISTEN", "tcp", "udp"]:
            for i, p in enumerate(parts):
                if ":" in p and not p.startswith("0.0.0.0:*"):
                    local = p
                    break
            # Proceso al final
            for p in reversed(parts):
                if "pid=" in p or '"' in p:
                    process = p
                    break

        # Extraer puerto
        port_match = re.search(r":(\d+)$", local) or re.search(r"[:\*](\d+)", local)
        if not port_match:
            # Intentar con netstat format
            for p in parts:
                m = re.search(r":(\d+)$", p)
                if m:
                    port_match = m
                    local = p
                    break

        if not port_match:
            continue

        port = int(port_match.group(1))
        addr = local.rsplit(":", 1)[0] if ":" in local else local

        # Proceso
        if not process:
            for p in parts:
                if "pid=" in p or '"' in p or "users:" in p:
                    process = p[:40]
                    break

        # Info del puerto
        service, risk = KNOWN_PORTS.get(port, ("Unknown", "info"))
        is_dangerous = port in DANGEROUS_PORTS
        is_public = addr in ["0.0.0.0", "::", "*", ""]

        listening.append({
            "port": port,
            "addr": addr,
            "protocol": "tcp",
            "service": service,
            "risk": risk,
            "dangerous": is_dangerous,
            "public": is_public,
            "process": _clean_process(process)
        })

    # Deduplicar por puerto
    seen = set()
    unique_listening = []
    for l in listening:
        if l["port"] not in seen:
            seen.add(l["port"])
            unique_listening.append(l)

    unique_listening.sort(key=lambda x: x["port"])
    data["listening"] = unique_listening
    data["count_listening"] = len(unique_listening)
    data["count_dangerous"] = len([l for l in unique_listening if l["dangerous"]])
    data["count_public"] = len([l for l in unique_listening if l["public"]])

    # ── CONEXIONES ESTABLECIDAS ──────────────────────────────────────────────
    conns_raw = _run("ss -tnp state established 2>/dev/null | head -20")
    if not conns_raw:
        conns_raw = _run("netstat -tnp 2>/dev/null | grep ESTABLISHED | head -20")

    connections = []
    for line in conns_raw.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        # Extraer src/dst
        for i in range(len(parts)):
            if re.match(r"\d+\.\d+\.\d+\.\d+:\d+", parts[i]):
                if i + 1 < len(parts) and re.match(r"\d+\.\d+\.\d+\.\d+:\d+", parts[i+1]):
                    connections.append({
                        "local": parts[i],
                        "remote": parts[i+1],
                        "process": parts[-1] if len(parts) > i+2 else "?"
                    })
                    break
    data["connections"] = connections[:15]

    # ── UFW STATUS ───────────────────────────────────────────────────────────
    ufw_raw = _run("ufw status verbose 2>/dev/null")
    data["ufw_rules"] = ufw_raw.splitlines() if ufw_raw else ["UFW no disponible"]

    # ── IPTABLES ─────────────────────────────────────────────────────────────
    ipt_raw = _run("iptables -L INPUT -n --line-numbers 2>/dev/null | head -25")
    data["iptables_input"] = ipt_raw.splitlines() if ipt_raw else ["Sin acceso a iptables"]

    # ── RECOMENDACIONES ──────────────────────────────────────────────────────
    recommendations = []
    for port_info in unique_listening:
        if port_info["dangerous"] and port_info["public"]:
            recommendations.append({
                "port": port_info["port"],
                "service": port_info["service"],
                "message": f"Puerto {port_info['port']} ({port_info['service']}) expuesto públicamente — CERRAR o restringir con firewall",
                "severity": "danger"
            })
        elif port_info["dangerous"]:
            recommendations.append({
                "port": port_info["port"],
                "service": port_info["service"],
                "message": f"Puerto {port_info['port']} ({port_info['service']}) abierto localmente — verificar necesidad",
                "severity": "warn"
            })

    # Telnet
    if any(l["port"] == 23 for l in unique_listening):
        recommendations.insert(0, {
            "port": 23, "service": "Telnet",
            "message": "Telnet activo — protocolo sin cifrado, DESHABILITAR inmediatamente",
            "severity": "danger"
        })

    data["recommendations"] = recommendations
    data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return data


def _clean_process(proc_str):
    """Extraer nombre de proceso limpio"""
    if not proc_str:
        return "desconocido"
    # users:(("nginx",pid=1234,fd=6))
    m = re.search(r'"([^"]+)"', proc_str)
    if m:
        return m.group(1)
    # pid=1234
    m = re.search(r"pid=(\d+)", proc_str)
    if m:
        return f"pid:{m.group(1)}"
    return proc_str[:30]
