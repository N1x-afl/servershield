"""
Módulo: security_check
Análisis de seguridad — firewall, SSH, fail2ban, SELinux/AppArmor, auditoría
"""

import subprocess
import os


def _run(cmd, shell=True):
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=8)
        return r.stdout.strip()
    except Exception:
        return ""


def _check(cmd):
    """Retorna True si el comando tiene salida no vacía"""
    return bool(_run(cmd))


def get_security_status():
    data = {}

    # ── FIREWALL ────────────────────────────────────────────────────────────
    ufw_status = _run("ufw status 2>/dev/null")
    iptables_rules = _run("iptables -L -n --line-numbers 2>/dev/null | head -30")
    nft_rules = _run("nft list ruleset 2>/dev/null | head -20")

    data["firewall"] = {
        "ufw_active": "active" in ufw_status.lower(),
        "ufw_output": ufw_status if ufw_status else "UFW no encontrado",
        "iptables": iptables_rules if iptables_rules else "Sin reglas iptables",
        "nftables": nft_rules if nft_rules else "Sin reglas nftables"
    }

    # ── SSH ─────────────────────────────────────────────────────────────────
    ssh_cfg = _run("grep -E '^(Port|PermitRootLogin|PasswordAuthentication|"
                   "PubkeyAuthentication|MaxAuthTries|Protocol|AllowUsers|"
                   "PermitEmptyPasswords|X11Forwarding|ClientAliveInterval)' "
                   "/etc/ssh/sshd_config 2>/dev/null")

    ssh_checks = []
    cfg_text = ssh_cfg or ""

    checks_ssh = [
        ("PermitRootLogin no",     "PermitRootLogin no"     in cfg_text, "PermitRootLogin debe ser 'no'"),
        ("PasswordAuthentication", "PasswordAuthentication no" in cfg_text, "Deshabilitar autenticación por contraseña"),
        ("PubkeyAuthentication",   "PubkeyAuthentication yes" in cfg_text, "Habilitar autenticación por clave pública"),
        ("X11Forwarding no",       "X11Forwarding no"       in cfg_text, "Deshabilitar X11 Forwarding"),
        ("MaxAuthTries ≤ 3",       _check_max_auth(cfg_text),             "MaxAuthTries debe ser ≤ 3"),
        ("Puerto no-default",      "Port 22" not in cfg_text and "Port" in cfg_text, "Cambiar puerto por defecto (22)"),
    ]

    for name, status, recommendation in checks_ssh:
        ssh_checks.append({"name": name, "ok": status, "rec": recommendation})

    data["ssh"] = {
        "config_raw": cfg_text if cfg_text else "No se pudo leer /etc/ssh/sshd_config",
        "checks": ssh_checks,
        "service_active": _run("systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null") == "active"
    }

    # ── FAIL2BAN ────────────────────────────────────────────────────────────
    f2b_active = _run("systemctl is-active fail2ban 2>/dev/null") == "active"
    f2b_jails = _run("fail2ban-client status 2>/dev/null")
    f2b_ssh = _run("fail2ban-client status sshd 2>/dev/null || fail2ban-client status ssh 2>/dev/null")
    data["fail2ban"] = {
        "active": f2b_active,
        "jails": f2b_jails if f2b_jails else "fail2ban no activo o sin jails",
        "ssh_jail": f2b_ssh if f2b_ssh else "Jail SSH no configurado"
    }

    # ── SELinux / AppArmor ──────────────────────────────────────────────────
    selinux = _run("getenforce 2>/dev/null")
    apparmor = _run("apparmor_status 2>/dev/null | head -5")
    data["mac"] = {
        "selinux": selinux if selinux else "No disponible",
        "apparmor": apparmor if apparmor else "No disponible",
        "selinux_enforcing": selinux == "Enforcing",
        "apparmor_active": "active" in (apparmor or "").lower() or bool(apparmor)
    }

    # ── ACTUALIZACIONES PENDIENTES ───────────────────────────────────────────
    apt_updates = _run("apt list --upgradable 2>/dev/null | grep -c upgradable")
    yum_updates = _run("yum check-update 2>/dev/null | wc -l")
    data["updates"] = {
        "apt_pending": apt_updates if apt_updates and apt_updates != "1" else "0",
        "yum_pending": yum_updates if yum_updates else "0"
    }

    # ── AUDITD ──────────────────────────────────────────────────────────────
    auditd_active = _run("systemctl is-active auditd 2>/dev/null") == "active"
    audit_rules = _run("auditctl -l 2>/dev/null | head -10")
    data["auditd"] = {
        "active": auditd_active,
        "rules": audit_rules if audit_rules else "Sin reglas o auditd no activo"
    }

    # ── SUID/SGID peligrosos ─────────────────────────────────────────────────
    suid_files = _run("find /usr /bin /sbin -perm /4000 2>/dev/null | head -15")
    data["suid"] = suid_files.splitlines() if suid_files else []

    # ── CHEQUEOS GENERALES ───────────────────────────────────────────────────
    general_checks = []

    # IPv6 deshabilitado
    ipv6 = _run("sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null")
    general_checks.append({
        "name": "IPv6 deshabilitado",
        "ok": "= 1" in ipv6,
        "value": ipv6 or "N/A",
        "rec": "Deshabilitar IPv6 si no se usa: net.ipv6.conf.all.disable_ipv6=1"
    })

    # ASLR habilitado
    aslr = _run("cat /proc/sys/kernel/randomize_va_space 2>/dev/null")
    general_checks.append({
        "name": "ASLR habilitado",
        "ok": aslr == "2",
        "value": aslr or "N/A",
        "rec": "kernel.randomize_va_space=2 en /etc/sysctl.conf"
    })

    # Rp_filter
    rpfilter = _run("sysctl net.ipv4.conf.all.rp_filter 2>/dev/null")
    general_checks.append({
        "name": "Reverse Path Filtering",
        "ok": "= 1" in rpfilter or "= 2" in rpfilter,
        "value": rpfilter or "N/A",
        "rec": "net.ipv4.conf.all.rp_filter=1"
    })

    # SYN flood protection
    syn = _run("sysctl net.ipv4.tcp_syncookies 2>/dev/null")
    general_checks.append({
        "name": "SYN Cookies (anti-flood)",
        "ok": "= 1" in syn,
        "value": syn or "N/A",
        "rec": "net.ipv4.tcp_syncookies=1"
    })

    # ICMP redirect
    icmp = _run("sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null")
    general_checks.append({
        "name": "ICMP Redirects deshabilitados",
        "ok": "= 0" in icmp,
        "value": icmp or "N/A",
        "rec": "net.ipv4.conf.all.accept_redirects=0"
    })

    data["general_checks"] = general_checks

    # Resumen score
    total = len(general_checks) + len(ssh_checks)
    ok_count = sum(1 for c in general_checks if c["ok"]) + sum(1 for c in ssh_checks if c["ok"])
    data["score"] = round((ok_count / total) * 100) if total else 0
    data["score_ok"] = ok_count
    data["score_total"] = total

    return data


def _check_max_auth(cfg_text):
    import re
    m = re.search(r"MaxAuthTries\s+(\d+)", cfg_text)
    if m:
        return int(m.group(1)) <= 3
    return False
