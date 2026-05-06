"""
Módulo: system_info
Estado del servidor — CPU, memoria, disco, red, uptime, procesos
"""

import subprocess
import platform
import os
import re
from datetime import datetime


def _run(cmd, shell=True):
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=8)
        return r.stdout.strip()
    except Exception:
        return ""


def get_quick_stats():
    stats = {}

    # Hostname
    stats["hostname"] = _run("hostname") or platform.node()

    # OS
    try:
        with open("/etc/os-release") as f:
            lines = {k: v.strip('"') for k, v in
                     (l.strip().split("=", 1) for l in f if "=" in l)}
        stats["os"] = lines.get("PRETTY_NAME", platform.system())
    except Exception:
        stats["os"] = platform.system()

    # Uptime
    uptime_raw = _run("uptime -p")
    stats["uptime"] = uptime_raw if uptime_raw else "N/A"

    # CPU usage
    cpu = _run("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'")
    if not cpu:
        cpu = _run("grep -c ^processor /proc/cpuinfo")
        stats["cpu_usage"] = "N/A"
        stats["cpu_cores"] = cpu or "?"
    else:
        stats["cpu_usage"] = cpu.replace(",", ".") + "%"
        stats["cpu_cores"] = _run("nproc") or "?"

    # Memoria
    mem = _run("free -m | awk '/^Mem:/ {print $2\" \"$3\" \"$4}'")
    if mem:
        parts = mem.split()
        total, used, free = int(parts[0]), int(parts[1]), int(parts[2])
        pct = round((used / total) * 100, 1) if total else 0
        stats["mem_total"] = f"{total} MB"
        stats["mem_used"] = f"{used} MB"
        stats["mem_pct"] = pct
    else:
        stats["mem_total"] = "N/A"
        stats["mem_used"] = "N/A"
        stats["mem_pct"] = 0

    # Disco
    disk = _run("df -h / | awk 'NR==2 {print $2\" \"$3\" \"$5}'")
    if disk:
        parts = disk.split()
        stats["disk_total"] = parts[0]
        stats["disk_used"] = parts[1]
        stats["disk_pct"] = parts[2].rstrip("%")
    else:
        stats["disk_total"] = "N/A"
        stats["disk_used"] = "N/A"
        stats["disk_pct"] = 0

    # Kernel
    stats["kernel"] = _run("uname -r") or platform.release()

    # IP principal
    ip = _run("hostname -I | awk '{print $1}'")
    stats["ip"] = ip or "127.0.0.1"

    # Timestamp
    stats["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Procesos activos
    stats["procs"] = _run("ps aux --no-headers | wc -l") or "?"

    return stats


def get_full_status():
    data = get_quick_stats()

    # Top 5 procesos por CPU
    top_cpu = _run("ps aux --sort=-%cpu | awk 'NR>1 && NR<=6 {print $1, $2, $3, $4, $11}'")
    procs = []
    for line in top_cpu.splitlines():
        parts = line.split(None, 4)
        if len(parts) == 5:
            procs.append({
                "user": parts[0], "pid": parts[1],
                "cpu": parts[2], "mem": parts[3], "cmd": parts[4][:40]
            })
    data["top_procs"] = procs

    # Interfaces de red
    ifaces = _run("ip -o -4 addr show | awk '{print $2, $4}'")
    net = []
    for line in ifaces.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            net.append({"iface": parts[0], "ip": parts[1]})
    data["net_ifaces"] = net

    # Últimos logins
    last = _run("last -n 5 --time-format iso | head -5")
    data["last_logins"] = last.splitlines() if last else ["Sin información"]

    # Servicios críticos
    services = ["ssh", "sshd", "nginx", "apache2", "mysql", "postgresql",
                "docker", "fail2ban", "ufw", "crowdsec"]
    svc_status = []
    for svc in services:
        out = _run(f"systemctl is-active {svc} 2>/dev/null")
        if out:
            svc_status.append({"name": svc, "status": out,
                               "ok": out == "active"})
    data["services"] = svc_status

    # Carga del sistema
    load = _run("cat /proc/loadavg")
    if load:
        parts = load.split()
        data["load_1"] = parts[0]
        data["load_5"] = parts[1]
        data["load_15"] = parts[2]
    else:
        data["load_1"] = data["load_5"] = data["load_15"] = "N/A"

    return data
