#!/usr/bin/env python3
"""ServerShield — Hardening Toolkit con soporte multi-servidor"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from functools import wraps
from matrix_mode import parse_args, run_matrix_intro
from modules import system_info, security_check, cve_check, crowdsec_mod, ports_mod, users_mod
from modules.remote_ssh import (
    load_servers, add_server, remove_server, get_server,
    get_remote_stats, get_all_servers_status, test_connection
)

app = Flask(__name__)
app.secret_key = "s3rv3rsh13ld_s3cr3t_k3y_2024"
USERS = {"admin": "Adm1n@Shield2024", "auditor": "Aud1t@2024"}

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if USERS.get(username) == password:
            session["user"] = username
            session["role"] = "admin" if username == "admin" else "auditor"
            return redirect(url_for("dashboard"))
        error = "Credenciales inválidas. Acceso denegado."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── LOCAL ─────────────────────────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=session["user"],
                           role=session["role"], stats=system_info.get_quick_stats(), active="dashboard")

@app.route("/status")
@login_required
def status():
    return render_template("status.html", user=session["user"], role=session["role"],
                           data=system_info.get_full_status(), active="status")

@app.route("/cve")
@login_required
def cve():
    return render_template("cve.html", user=session["user"], role=session["role"],
                           data=cve_check.get_cve_info(), active="cve")

@app.route("/crowdsec")
@login_required
def crowdsec():
    return render_template("crowdsec.html", user=session["user"], role=session["role"],
                           data=crowdsec_mod.get_crowdsec_status(), active="crowdsec")

@app.route("/security")
@login_required
def security():
    return render_template("security.html", user=session["user"], role=session["role"],
                           data=security_check.get_security_status(), active="security")

@app.route("/users")
@login_required
def users():
    return render_template("users.html", user=session["user"], role=session["role"],
                           data=users_mod.get_users_info(), active="users")

@app.route("/ports")
@login_required
def ports():
    return render_template("ports.html", user=session["user"], role=session["role"],
                           data=ports_mod.get_ports_info(), active="ports")

# ── MULTI-SERVIDOR ────────────────────────────────────────────────────────────
@app.route("/servers")
@login_required
def servers():
    all_servers = load_servers()
    stats = get_all_servers_status() if all_servers else []
    return render_template("servers.html", user=session["user"], role=session["role"],
                           servers=all_servers, stats=stats, active="servers")

@app.route("/remote/<path:server_id>")
@login_required
def server_detail(server_id):
    server = get_server(server_id)
    if not server:
        return redirect(url_for("servers"))
    data = get_remote_stats(server)
    return render_template("server_detail.html", user=session["user"], role=session["role"],
                           data=data, active="servers")

@app.route("/remote/add", methods=["POST"])
@login_required
def remote_add():
    d = request.get_json()
    ok, msg = add_server(
        name=d.get("name", ""),
        host=d.get("host", ""),
        port=int(d.get("port", 22)),
        username=d.get("username", ""),
        auth_type=d.get("auth_type", "password"),
        password=d.get("password", ""),
        key_path=d.get("key_path", "")
    )
    if not ok:
        return jsonify({"ok": False, "message": msg})
    # Probar conexión
    server = get_server(f"{d['host']}:{d.get('port', 22)}")
    if server:
        conn_ok, conn_msg = test_connection(server)
        return jsonify({"ok": True, "message": f"Servidor agregado — {conn_msg}"})
    return jsonify({"ok": True, "message": msg})

@app.route("/remote/remove/<path:server_id>", methods=["POST"])
@login_required
def remote_remove(server_id):
    remove_server(server_id)
    return jsonify({"ok": True})

@app.route("/remote/refresh/<path:server_id>")
@login_required
def remote_refresh(server_id):
    server = get_server(server_id)
    if server:
        get_remote_stats(server)
    return jsonify({"ok": True})

# ── API ───────────────────────────────────────────────────────────────────────
@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(system_info.get_quick_stats())

@app.route("/api/servers")
@login_required
def api_servers():
    return jsonify(get_all_servers_status())

# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    args = parse_args()
    if args.matrix_mode:
        run_matrix_intro(duration=args.matrix_duration)
    print("\n" + "="*60)
    print("  ⬡  ServerShield — Hardening Tool iniciando...")
    print(f"  URL: http://0.0.0.0:{args.port}")
    if args.matrix_mode:
        print("  Modo: MATRIX MODE ACTIVATED 🟢")
    print("="*60 + "\n")
    app.run(host=args.host, port=args.port, debug=False)
