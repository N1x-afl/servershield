"""
Módulo: crowdsec_mod
Integración con CrowdSec — estado, decisiones, alertas, bouncers
"""

import subprocess
import json
from datetime import datetime


def _run(cmd, shell=True):
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=10)
        # cscli escribe en stderr — combinar ambas salidas
        output = r.stdout.strip() or r.stderr.strip()
        return output, r.returncode
    except Exception:
        return "", 1


def get_crowdsec_status():
    data = {}

    cscli_ver, rc = _run("cscli version 2>&1")
    data["available"] = rc == 0 and bool(cscli_ver)
    data["version"] = cscli_ver.splitlines()[0] if cscli_ver else "CrowdSec no instalado"

    if not data["available"]:
        data["install_hint"] = (
            "curl -s https://packagecloud.io/install/repositories/"
            "crowdsec/crowdsec/script.deb.sh | sudo bash\n"
            "sudo apt-get install crowdsec"
        )
        data["service_active"] = False
        data["bouncers"] = []
        data["decisions"] = []
        data["alerts"] = []
        data["metrics"] = {}
        data["hub_status"] = []
        data["recent_logs"] = []
        data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return data

    svc_status, _ = _run("systemctl is-active crowdsec 2>/dev/null")
    data["service_active"] = svc_status == "active"
    data["service_status"] = svc_status or "unknown"

    decisions_raw, _ = _run("cscli decisions list -o json 2>/dev/null")
    decisions = []
    try:
        if decisions_raw and decisions_raw.strip() not in ["null", "", "[]"]:
            decs = json.loads(decisions_raw) or []
            for d in decs[:15]:
                decisions.append({
                    "id": d.get("id", "?"),
                    "ip": d.get("value", "?"),
                    "reason": d.get("reason", "?"),
                    "action": d.get("type", "ban"),
                    "duration": d.get("duration", "?"),
                    "origin": d.get("origin", "?"),
                    "scenario": d.get("scenario", "?")
                })
    except (json.JSONDecodeError, TypeError):
        pass

    data["decisions"] = decisions
    data["decisions_count"] = len(decisions)

    alerts_raw, _ = _run("cscli alerts list -o json 2>/dev/null")
    alerts = []
    try:
        if alerts_raw and alerts_raw.strip() not in ["null", "", "[]"]:
            als = json.loads(alerts_raw) or []
            for a in als[:10]:
                alerts.append({
                    "id": a.get("id", "?"),
                    "scenario": a.get("scenario", "?"),
                    "ip": a.get("sourceRange", a.get("source", {}).get("ip", "?")),
                    "count": a.get("decisionsCount", 0),
                    "created_at": (a.get("createdAt", "?"))[:19]
                })
    except (json.JSONDecodeError, TypeError):
        pass

    data["alerts"] = alerts
    data["alerts_count"] = len(alerts)

    bouncers_raw, _ = _run("cscli bouncers list -o json 2>/dev/null")
    bouncers = []
    try:
        if bouncers_raw and bouncers_raw.strip() not in ["null", "", "[]"]:
            bcs = json.loads(bouncers_raw) or []
            for b in bcs:
                bouncers.append({
                    "name": b.get("name", "?"),
                    "ip": b.get("ip_address", "?"),
                    "type": b.get("type", "?"),
                    "active": b.get("last_pull", None) is not None,
                    "last_pull": (b.get("last_pull", "?") or "?")[:19]
                })
    except (json.JSONDecodeError, TypeError):
        pass

    data["bouncers"] = bouncers

    metrics_raw, _ = _run("cscli metrics 2>/dev/null | head -40")
    data["metrics_raw"] = metrics_raw if metrics_raw else "Sin métricas disponibles"

    hub_raw, _ = _run("cscli hub list -o json 2>/dev/null")
    hub = []
    try:
        if hub_raw and hub_raw.strip() not in ["null", "", "{}"]:
            h = json.loads(hub_raw) or {}
            for category, items in h.items():
                if isinstance(items, list):
                    for item in items[:5]:
                        hub.append({
                            "type": category,
                            "name": item.get("name", "?"),
                            "status": item.get("status", "?"),
                            "version": item.get("local_version", "?")
                        })
    except (json.JSONDecodeError, TypeError):
        pass

    data["hub_status"] = hub

    log_raw, _ = _run("journalctl -u crowdsec -n 10 --no-pager 2>/dev/null")
    data["recent_logs"] = log_raw.splitlines()[-10:] if log_raw else []

    data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return data
