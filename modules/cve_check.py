"""
Módulo: cve_check
Consulta de CVEs — paquetes vulnerables, kernel, software instalado
"""

import subprocess
import re
import json
import urllib.request
import urllib.error
from datetime import datetime


def _run(cmd, shell=True):
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=15)
        return r.stdout.strip()
    except Exception:
        return ""


def get_cve_info():
    data = {}

    # ── INFORMACIÓN DEL SISTEMA ─────────────────────────────────────────────
    kernel = _run("uname -r")
    os_info = _run("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
    data["kernel"] = kernel or "N/A"
    data["os"] = os_info or "N/A"

    # ── PAQUETES CON ACTUALIZACIONES DE SEGURIDAD (Debian/Ubuntu) ──────────
    sec_updates = []
    apt_sec = _run("apt-get -s upgrade 2>/dev/null | grep '^Inst' | head -20")
    if apt_sec:
        for line in apt_sec.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                sec_updates.append({
                    "package": parts[1],
                    "version": parts[2].strip("[]()") if len(parts) > 2 else "?",
                    "source": "apt"
                })

    # Debian security specifically
    apt_sec2 = _run("apt list --upgradable 2>/dev/null | grep -i security | head -15")
    for line in apt_sec2.splitlines():
        m = re.match(r"^([\w\-\.]+)/(\S+)\s+(\S+)", line)
        if m and m.group(1) not in [s["package"] for s in sec_updates]:
            sec_updates.append({
                "package": m.group(1),
                "version": m.group(3),
                "source": "security"
            })

    data["security_updates"] = sec_updates[:20]
    data["updates_count"] = len(sec_updates)

    # ── PAQUETES INSTALADOS CRÍTICOS ────────────────────────────────────────
    critical_packages = []
    pkgs_to_check = [
        "openssl", "openssh-server", "openssh-client", "bash", "linux-kernel",
        "sudo", "curl", "wget", "python3", "nginx", "apache2",
        "docker.io", "docker-ce", "postgresql", "mysql-server"
    ]

    for pkg in pkgs_to_check:
        ver = _run(f"dpkg -l {pkg} 2>/dev/null | grep '^ii' | awk '{{print $3}}'")
        if not ver:
            ver = _run(f"rpm -q {pkg} 2>/dev/null")
        if ver and ver != pkg:
            critical_packages.append({"name": pkg, "version": ver})

    data["critical_packages"] = critical_packages

    # ── CVEs desde NVD API (sin key, limitado) ───────────────────────────────
    data["nvd_cves"] = []
    data["nvd_error"] = None

    try:
        # Query CVEs recientes relacionados con kernel Linux
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch=linux+kernel&resultsPerPage=5&noRejected"
        )
        req = urllib.request.Request(url, headers={"User-Agent": "ServerShield/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = json.loads(resp.read().decode())
            vulns = raw.get("vulnerabilities", [])
            for v in vulns[:5]:
                cve_data = v.get("cve", {})
                cve_id = cve_data.get("id", "?")
                desc = ""
                for d in cve_data.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")[:200]
                        break
                metrics = cve_data.get("metrics", {})
                score = "N/A"
                severity = "N/A"
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    m_list = metrics.get(key, [])
                    if m_list:
                        cvss = m_list[0].get("cvssData", {})
                        score = str(cvss.get("baseScore", "N/A"))
                        severity = cvss.get("baseSeverity", m_list[0].get("baseSeverity", "N/A"))
                        break
                published = cve_data.get("published", "?")[:10]
                data["nvd_cves"].append({
                    "id": cve_id,
                    "description": desc,
                    "score": score,
                    "severity": severity,
                    "published": published
                })
    except urllib.error.URLError:
        data["nvd_error"] = "Sin conexión a internet o NVD API no disponible"
    except Exception as e:
        data["nvd_error"] = f"Error consultando NVD: {str(e)[:80]}"

    # ── ANÁLISIS LOCAL CON LYNIS (si está instalado) ────────────────────────
    lynis_ver = _run("lynis --version 2>/dev/null | head -1")
    data["lynis_available"] = bool(lynis_ver)
    data["lynis_version"] = lynis_ver or "No instalado"

    last_lynis = _run("cat /var/log/lynis.log 2>/dev/null | grep 'Hardening index' | tail -1")
    data["lynis_last_score"] = last_lynis if last_lynis else "Sin escaneo previo"

    # ── RESUMEN ─────────────────────────────────────────────────────────────
    data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data["risk_level"] = _calculate_risk(data)

    return data


def _calculate_risk(data):
    score = 100
    score -= min(data.get("updates_count", 0) * 5, 40)
    for cve in data.get("nvd_cves", []):
        try:
            s = float(cve.get("score", 0) or 0)
            if s >= 9.0:
                score -= 15
            elif s >= 7.0:
                score -= 8
            elif s >= 4.0:
                score -= 3
        except ValueError:
            pass
    score = max(score, 0)
    if score >= 80:
        return ("BAJO", "ok")
    elif score >= 50:
        return ("MEDIO", "warn")
    else:
        return ("ALTO", "danger")
