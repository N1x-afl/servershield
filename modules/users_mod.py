"""
Módulo: users_mod
Gestión de usuarios — root, sudo, permisos, contraseñas, grupos de seguridad
"""

import subprocess
import pwd
import grp
import os
import re
from datetime import datetime


def _run(cmd, shell=True):
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=8)
        return r.stdout.strip()
    except Exception:
        return ""


def get_users_info():
    data = {}

    # ── USUARIOS DEL SISTEMA ─────────────────────────────────────────────────
    all_users = []
    try:
        for pw in pwd.getpwall():
            uid = pw.pw_uid
            # Usuarios reales (uid >= 1000) o root (0)
            is_real = uid == 0 or uid >= 1000
            shell_ok = pw.pw_shell not in ["/usr/sbin/nologin", "/bin/false",
                                            "/sbin/nologin", "/bin/sync"]
            all_users.append({
                "username": pw.pw_name,
                "uid": uid,
                "gid": pw.pw_gid,
                "home": pw.pw_dir,
                "shell": pw.pw_shell,
                "is_real": is_real,
                "can_login": shell_ok,
                "is_root": uid == 0
            })
    except Exception as e:
        data["users_error"] = str(e)

    data["all_users"] = all_users
    data["real_users"] = [u for u in all_users if u["is_real"]]
    data["root_users"] = [u for u in all_users if u["uid"] == 0]

    # ── USUARIOS CON SUDO ─────────────────────────────────────────────────────
    sudo_users = []

    # Del grupo sudo/wheel
    for grp_name in ["sudo", "wheel", "admin"]:
        try:
            g = grp.getgrnam(grp_name)
            for member in g.gr_mem:
                if member not in sudo_users:
                    sudo_users.append(member)
        except KeyError:
            pass

    # Del archivo sudoers
    sudoers_raw = _run("grep -v '^#' /etc/sudoers 2>/dev/null | grep -v '^$'")
    sudoers_lines = []
    if sudoers_raw:
        for line in sudoers_raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("Defaults"):
                sudoers_lines.append(line)
                # Extraer usuarios con NOPASSWD
                if "NOPASSWD" in line:
                    m = re.match(r"^(\w+)\s+", line)
                    if m:
                        user = m.group(1)
                        if user not in ["root"] and not user.startswith("%"):
                            if user not in sudo_users:
                                sudo_users.append(user)

    data["sudo_users"] = sudo_users
    data["sudoers_rules"] = sudoers_lines[:20]

    # Archivos en /etc/sudoers.d/
    sudoers_d = _run("ls /etc/sudoers.d/ 2>/dev/null")
    data["sudoers_d_files"] = sudoers_d.splitlines() if sudoers_d else []

    # ── ESTADO DE CONTRASEÑAS ─────────────────────────────────────────────────
    passwd_status = []
    shadow_raw = _run("cat /etc/shadow 2>/dev/null | awk -F: '{print $1, $2, $5, $6, $7}'")
    if not shadow_raw:
        # Sin permisos para leer shadow
        passwd_status_raw = _run("passwd -S -a 2>/dev/null | head -20")
        if passwd_status_raw:
            for line in passwd_status_raw.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    passwd_status.append({
                        "user": parts[0],
                        "status": parts[1],
                        "locked": parts[1] in ["L", "LK"],
                        "no_password": parts[1] == "NP",
                        "has_password": parts[1] in ["P", "PS"]
                    })
        data["shadow_access"] = False
    else:
        data["shadow_access"] = True
        for line in shadow_raw.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                user = parts[0]
                pw_hash = parts[1]
                locked = pw_hash.startswith("!") or pw_hash.startswith("*")
                no_pw = pw_hash in ["", "!!", "*"]
                passwd_status.append({
                    "user": user,
                    "locked": locked,
                    "no_password": no_pw,
                    "has_password": not locked and not no_pw,
                    "status": "BLOQUEADO" if locked else ("SIN CLAVE" if no_pw else "ACTIVO")
                })

    data["passwd_status"] = passwd_status

    # ── ÚLTIMOS ACCESOS ──────────────────────────────────────────────────────
    lastlog = _run("lastlog 2>/dev/null | awk 'NR>1 && $2!=\"**\" {print}' | head -15")
    data["lastlog"] = lastlog.splitlines() if lastlog else []

    last_logins = _run("last -n 10 2>/dev/null")
    data["last_logins"] = last_logins.splitlines()[:10] if last_logins else []

    # ── USUARIOS CON UID 0 (otros root) ──────────────────────────────────────
    uid0_extra = _run("awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null")
    uid0_list = uid0_extra.splitlines() if uid0_extra else ["root"]
    data["uid0_users"] = uid0_list
    data["uid0_warning"] = len(uid0_list) > 1

    # ── GRUPOS DE SEGURIDAD CRÍTICOS ─────────────────────────────────────────
    critical_groups = ["docker", "sudo", "wheel", "shadow", "disk", "adm"]
    groups_info = []
    for grp_name in critical_groups:
        try:
            g = grp.getgrnam(grp_name)
            groups_info.append({
                "name": grp_name,
                "gid": g.gr_gid,
                "members": g.gr_mem,
                "count": len(g.gr_mem)
            })
        except KeyError:
            groups_info.append({
                "name": grp_name,
                "gid": "N/A",
                "members": [],
                "count": 0
            })
    data["critical_groups"] = groups_info

    # ── CHEQUEOS DE SEGURIDAD DE USUARIOS ────────────────────────────────────
    checks = []

    # ¿Root tiene login directo habilitado?
    root_pw = _run("grep '^root:' /etc/shadow 2>/dev/null | cut -d: -f2")
    root_locked = root_pw.startswith("!") or root_pw.startswith("*") if root_pw else False
    checks.append({
        "name": "Root bloqueado (login directo)",
        "ok": root_locked,
        "detail": "Cuenta root bloqueada para acceso directo" if root_locked else "Root tiene login directo habilitado — RIESGO",
        "severity": "ok" if root_locked else "danger"
    })

    # ¿Usuarios sin contraseña?
    empty_pw = [p for p in passwd_status if p.get("no_password") and p.get("user") not in ["sync", "halt", "shutdown"]]
    checks.append({
        "name": "Usuarios sin contraseña",
        "ok": len(empty_pw) == 0,
        "detail": f"{len(empty_pw)} usuario(s) sin contraseña: {', '.join([p['user'] for p in empty_pw[:5]])}" if empty_pw else "Sin usuarios sin contraseña",
        "severity": "danger" if empty_pw else "ok"
    })

    # Más de 1 usuario con UID 0
    checks.append({
        "name": "UID 0 único (solo root)",
        "ok": len(uid0_list) <= 1,
        "detail": f"ALERTA: Usuarios con UID 0: {', '.join(uid0_list)}" if len(uid0_list) > 1 else "Solo root tiene UID 0",
        "severity": "danger" if len(uid0_list) > 1 else "ok"
    })

    # Docker group risk
    docker_members = next((g["members"] for g in groups_info if g["name"] == "docker"), [])
    checks.append({
        "name": "Grupo docker (escalación)",
        "ok": len(docker_members) == 0,
        "detail": f"Usuarios en grupo docker: {', '.join(docker_members)}" if docker_members else "Nadie en grupo docker",
        "severity": "warn" if docker_members else "ok"
    })

    data["security_checks"] = checks
    data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return data
