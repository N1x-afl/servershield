#!/usr/bin/env python3
"""ServerShield — Hardening Toolkit"""

from flask import (Flask, render_template, request, redirect,
                   url_for, session, jsonify)
from functools import wraps
from matrix_mode import parse_args, run_matrix_intro
from modules import system_info, security_check, cve_check, crowdsec_mod, ports_mod, users_mod
from modules.remote_ssh import (
    load_servers, add_server, remove_server, get_server,
    get_remote_stats, test_connection
)
from modules.config_manager import (
    initialize_config, verify_user, change_password,
    admin_change_password, add_user, remove_user,
    get_users, get_app_config, update_app_config
)
from remote_cache import fetch_all_parallel, get_cached, set_cache, invalidate, get_cache_age

app = Flask(__name__)
app.secret_key = "s3rv3rsh13ld_s3cr3t_k3y_2024"

# Inicializar config con usuarios por defecto si no existe
initialize_config({
    "admin":   ("Adm1n@Shield2024", "admin"),
    "auditor": ("Aud1t@2024",       "auditor")
})


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            return redirect(url_for("dashboard"))
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
        role = verify_user(username, password)
        if role:
            session["user"] = username
            session["role"] = role
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
                           role=session["role"],
                           stats=system_info.get_quick_stats(),
                           active="dashboard")


@app.route("/status")
@login_required
def status():
    return render_template("status.html", user=session["user"],
                           role=session["role"],
                           data=system_info.get_full_status(), active="status")


@app.route("/cve")
@login_required
def cve():
    return render_template("cve.html", user=session["user"],
                           role=session["role"],
                           data=cve_check.get_cve_info(), active="cve")


@app.route("/crowdsec")
@login_required
def crowdsec():
    return render_template("crowdsec.html", user=session["user"],
                           role=session["role"],
                           data=crowdsec_mod.get_crowdsec_status(), active="crowdsec")


@app.route("/security")
@login_required
def security():
    return render_template("security.html", user=session["user"],
                           role=session["role"],
                           data=security_check.get_security_status(), active="security")


@app.route("/users")
@login_required
def users():
    return render_template("users.html", user=session["user"],
                           role=session["role"],
                           data=users_mod.get_users_info(), active="users")


@app.route("/ports")
@login_required
def ports():
    return render_template("ports.html", user=session["user"],
                           role=session["role"],
                           data=ports_mod.get_ports_info(), active="ports")


# ── MULTI-SERVIDOR ────────────────────────────────────────────────────────────
@app.route("/servers")
@login_required
def servers():
    all_servers = load_servers()
    stats = fetch_all_parallel(all_servers, get_remote_stats) if all_servers else []
    cache_ages = {s["id"]: get_cache_age(s["id"]) for s in all_servers}
    return render_template("servers.html", user=session["user"],
                           role=session["role"],
                           servers=all_servers, stats=stats,
                           cache_ages=cache_ages, active="servers")


@app.route("/remote/<path:server_id>")
@login_required
def server_detail(server_id):
    server = get_server(server_id)
    if not server:
        return redirect(url_for("servers"))
    data = get_remote_stats(server)
    set_cache(server_id, data)
    return render_template("server_detail.html", user=session["user"],
                           role=session["role"], data=data, active="servers")


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
    server = get_server(f"{d['host']}:{d.get('port', 22)}")
    if server:
        conn_ok, conn_msg = test_connection(server)
        return jsonify({"ok": True, "message": f"Servidor agregado — {conn_msg}"})
    return jsonify({"ok": True, "message": msg})


@app.route("/remote/remove/<path:server_id>", methods=["POST"])
@login_required
def remote_remove(server_id):
    remove_server(server_id)
    invalidate(server_id)
    return jsonify({"ok": True})


@app.route("/remote/refresh/<path:server_id>")
@login_required
def remote_refresh(server_id):
    server = get_server(server_id)
    if server:
        invalidate(server_id)
        data = get_remote_stats(server)
        set_cache(server_id, data)
    return jsonify({"ok": True})


# ── CONFIGURACIÓN ─────────────────────────────────────────────────────────────
@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html",
                           user=session["user"], role=session["role"],
                           active="settings", active_tab="password",
                           users_list=get_users() if session["role"] == "admin" else [],
                           app_config=get_app_config(),
                           flash_msg=None, flash_type=None)


@app.route("/settings/password", methods=["POST"])
@login_required
def settings_password():
    current = request.form.get("current_password", "")
    new_pw  = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    flash_msg, flash_type = None, None

    if new_pw != confirm:
        flash_msg, flash_type = "Las contraseñas no coinciden", "error"
    else:
        ok, msg = change_password(session["user"], current, new_pw)
        flash_msg = msg
        flash_type = "ok" if ok else "error"

    return render_template("settings.html",
                           user=session["user"], role=session["role"],
                           active="settings", active_tab="password",
                           users_list=get_users() if session["role"] == "admin" else [],
                           app_config=get_app_config(),
                           flash_msg=flash_msg, flash_type=flash_type)


@app.route("/settings/users/add", methods=["POST"])
@admin_required
def settings_users_add():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm_password", "")
    role     = request.form.get("role", "auditor")

    if password != confirm:
        flash_msg, flash_type = "Las contraseñas no coinciden", "error"
    else:
        ok, msg = add_user(username, password, role)
        flash_msg, flash_type = msg, "ok" if ok else "error"

    return render_template("settings.html",
                           user=session["user"], role=session["role"],
                           active="settings", active_tab="users",
                           users_list=get_users(),
                           app_config=get_app_config(),
                           flash_msg=flash_msg, flash_type=flash_type)


@app.route("/settings/users/delete", methods=["POST"])
@admin_required
def settings_users_delete():
    username = request.form.get("username", "")
    ok, msg = remove_user(username, session["user"])
    flash_type = "ok" if ok else "error"
    return render_template("settings.html",
                           user=session["user"], role=session["role"],
                           active="settings", active_tab="users",
                           users_list=get_users(),
                           app_config=get_app_config(),
                           flash_msg=msg, flash_type=flash_type)


@app.route("/settings/users/admin-password", methods=["POST"])
@admin_required
def settings_admin_password():
    target   = request.form.get("target_username", "")
    new_pw   = request.form.get("new_password", "")
    confirm  = request.form.get("confirm_password", "")

    if new_pw != confirm:
        flash_msg, flash_type = "Las contraseñas no coinciden", "error"
    else:
        ok, msg = admin_change_password(target, new_pw)
        flash_msg, flash_type = msg, "ok" if ok else "error"

    return render_template("settings.html",
                           user=session["user"], role=session["role"],
                           active="settings", active_tab="users",
                           users_list=get_users(),
                           app_config=get_app_config(),
                           flash_msg=flash_msg, flash_type=flash_type)


@app.route("/settings/app", methods=["POST"])
@admin_required
def settings_app():
    ok, msg = update_app_config(
        port=request.form.get("port"),
        app_name=request.form.get("app_name"),
        session_timeout=request.form.get("session_timeout")
    )
    flash_type = "ok" if ok else "error"
    return render_template("settings.html",
                           user=session["user"], role=session["role"],
                           active="settings", active_tab="app",
                           users_list=get_users(),
                           app_config=get_app_config(),
                           flash_msg=msg, flash_type=flash_type)


# ── API ───────────────────────────────────────────────────────────────────────
@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(system_info.get_quick_stats())


@app.route("/api/servers")
@login_required
def api_servers():
    return jsonify(fetch_all_parallel(load_servers(), get_remote_stats))


# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    args = parse_args()
    if args.matrix_mode:
        run_matrix_intro(duration=args.matrix_duration)

    cfg = get_app_config()
    port = args.port if args.port != 5000 else cfg.get("port", 5000)

    print("\n" + "="*60)
    print("  ⬡  ServerShield — Hardening Tool iniciando...")
    print(f"  URL: http://0.0.0.0:{port}")
    if args.matrix_mode:
        print("  Modo: MATRIX MODE ACTIVATED 🟢")
    print("="*60 + "\n")

    app.run(host=args.host, port=port, debug=False)
