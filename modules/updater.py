"""
Módulo: updater
Verificación y aplicación de actualizaciones desde GitHub
"""

import subprocess
import os
import json
from datetime import datetime

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(cmd, cwd=None):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=30, cwd=cwd or APP_DIR)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e), 1


def get_current_version():
    """Obtener versión/commit actual"""
    out, _, _ = _run("git describe --tags --always 2>/dev/null || git rev-parse --short HEAD")
    return out or "desconocida"


def get_current_commit():
    out, _, _ = _run("git rev-parse HEAD")
    return out[:8] if out else "?"


def check_for_updates():
    """
    Verificar si hay actualizaciones en el repositorio remoto.
    Devuelve dict con info del estado.
    """
    result = {
        "current_version": get_current_version(),
        "current_commit":  get_current_commit(),
        "has_updates":     False,
        "remote_version":  None,
        "remote_commit":   None,
        "commits_behind":  0,
        "changelog":       [],
        "error":           None,
        "last_checked":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "git_available":   False,
        "repo_url":        None
    }

    # Verificar que git está disponible
    out, _, rc = _run("git --version")
    if rc != 0:
        result["error"] = "Git no está instalado"
        return result
    result["git_available"] = True

    # Verificar que es un repo git
    _, _, rc = _run("git rev-parse --is-inside-work-tree")
    if rc != 0:
        result["error"] = "La app no está en un repositorio git"
        return result

    # Obtener URL del repo
    url, _, _ = _run("git remote get-url origin 2>/dev/null")
    result["repo_url"] = url or "N/A"

    # Fetch sin modificar archivos locales
    _, err, rc = _run("git fetch origin main 2>&1")
    if rc != 0:
        result["error"] = f"No se pudo conectar al repositorio: {err[:80]}"
        return result

    # Comparar commits
    local, _, _  = _run("git rev-parse HEAD")
    remote, _, _ = _run("git rev-parse origin/main")

    result["current_commit"] = local[:8]  if local  else "?"
    result["remote_commit"]  = remote[:8] if remote else "?"

    if local and remote and local != remote:
        result["has_updates"] = True

        # Cuántos commits hay por delante
        count_raw, _, _ = _run(f"git rev-list HEAD..origin/main --count")
        try:
            result["commits_behind"] = int(count_raw)
        except ValueError:
            result["commits_behind"] = 0

        # Últimos cambios (changelog)
        log_raw, _, _ = _run(
            "git log HEAD..origin/main --oneline --no-merges | head -10"
        )
        result["changelog"] = log_raw.splitlines() if log_raw else []

        # Versión remota (último tag)
        remote_ver, _, _ = _run("git describe --tags origin/main 2>/dev/null")
        result["remote_version"] = remote_ver or result["remote_commit"]
    else:
        result["remote_version"] = result["current_version"]

    return result


def apply_update():
    """
    Aplicar actualización con git pull.
    Devuelve (ok: bool, mensaje: str, detalles: str)
    """
    # Verificar que hay actualizaciones
    status = check_for_updates()
    if status.get("error"):
        return False, status["error"], ""

    if not status["has_updates"]:
        return False, "No hay actualizaciones disponibles", ""

    # Hacer backup del commit actual
    current, _, _ = _run("git rev-parse HEAD")

    # Aplicar git pull
    out, err, rc = _run("git pull origin main")

    if rc != 0:
        return False, f"Error al actualizar: {err[:100]}", out

    # Verificar si requirements.txt cambió
    changed, _, _ = _run(f"git diff {current} HEAD --name-only")
    needs_pip = "requirements.txt" in changed

    details = out
    if needs_pip:
        # Actualizar dependencias automáticamente
        pip_out, pip_err, pip_rc = _run("venv/bin/pip install -r requirements.txt -q")
        if pip_rc == 0:
            details += "\n✓ Dependencias actualizadas"
        else:
            details += f"\n⚠ Error actualizando dependencias: {pip_err[:80]}"

    return True, "Actualización aplicada correctamente — reiniciá la app para cargar los cambios", details
