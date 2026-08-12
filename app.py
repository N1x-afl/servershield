#!/usr/bin/env python3
"""ServerShield — Hardening Toolkit con Terminal Web SSH"""

from flask import (Flask, render_template, request, redirect,
                   url_for, session, jsonify)
from flask_socketio import SocketIO, emit, disconnect
from functools import wraps
import threading

from matrix_mode import parse_args, run_matrix_intro
from modules import system_info, security_check, cve_check, crowdsec_mod, ports_mod, users_mod
from modules.remote_ssh import (
    load_servers, add_server, remove_server, get_server,
    get_remote_stats, test_connection
)
from modules.windows_remote import get_windows_stats, test_connection as win_test_connection
from modules.switch_remote  import get_switch_stats,   test_connection as switch_test_connection
from modules.config_manager import (
    initialize_config, verify_user, change_password,
    admin_change_password, add_user, remove_user,
    get_users, get_app_config, update_app_config
)
from modules.updater      import check_for_updates, apply_update
from modules.terminal_ssh import connect_ssh, send_input, resize_terminal, disconnect_ssh
from modules.telnet_remote import (
    get_telnet_stats, test_connection as telnet_test_connection,
    connect_telnet_terminal, send_telnet_input, disconnect_telnet
)
from remote_cache import fetch_all_parallel, get_cached, set_cache, invalidate, get_cache_age

app = Flask(__name__)
app.secret_key = "s3rv3rsh13ld_s3cr3t_k3y_2024"
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

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



def _decode_id(sid):
    return sid.replace("COLON", ":")

def _fetch_server(server):
    os_type  = server.get("os_type", "linux")
    protocol = server.get("protocol", "ssh")
    if os_type == "windows":
        return get_windows_stats(server)
    elif os_type == "switch":
        if protocol == "telnet":
            return get_telnet_stats(server)
        return get_switch_stats(server)
    return get_remote_stats(server)


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
                           stats=system_info.get_quick_stats(), active="dashboard")

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


# ── SERVIDORES REMOTOS ────────────────────────────────────────────────────────
@app.route("/servers")
@login_required
def servers():
    all_servers = [s for s in load_servers() if s.get("os_type") != "switch"]
    stats = fetch_all_parallel(all_servers, _fetch_server) if all_servers else []
    cache_ages = {s["id"]: get_cache_age(s["id"]) for s in all_servers}
    return render_template("servers.html", user=session["user"], role=session["role"],
                           servers=all_servers, stats=stats,
                           cache_ages=cache_ages, active="servers")

@app.route("/remote/<path:server_id>")
@login_required
def server_detail(server_id):
    server = get_server(server_id)
    if not server:
        return redirect(url_for("servers"))
    data = _fetch_server(server)
    set_cache(server_id, data)
    return render_template("server_detail.html", user=session["user"],
                           role=session["role"], data=data, active="servers")

@app.route("/remote/add", methods=["POST"])
@login_required
def remote_add():
    d = request.get_json()
    os_type = d.get("os_type", "linux")
    ok, msg = add_server(
        name=d.get("name", ""),
        host=d.get("host", ""),
        port=int(d.get("port", 22 if os_type == "linux" else 5985)),
        username=d.get("username", ""),
        auth_type=d.get("auth_type", "password"),
        password=d.get("password", ""),
        key_path=d.get("key_path", "")
    )
    if not ok:
        return jsonify({"ok": False, "message": msg})
    servers_list = load_servers()
    for s in servers_list:
        if s["host"] == d.get("host") and s["port"] == int(d.get("port", 22)):
            s["os_type"] = os_type
            s["use_ssl"] = d.get("use_ssl", False)
    from modules.remote_ssh import save_servers
    save_servers(servers_list)
    server = get_server(f"{d['host']}:{d.get('port', 22)}")
    if server:
        if os_type == "windows":
            conn_ok, conn_msg = win_test_connection(server)
        else:
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
        data = _fetch_server(server)
        set_cache(server_id, data)
    return jsonify({"ok": True})


# ── SWITCHES ──────────────────────────────────────────────────────────────────
@app.route("/switches")
@login_required
def switches():
    """Carga lazy — solo pasa la lista, el JS carga cada dispositivo"""
    all_switches = [s for s in load_servers() if s.get("os_type") == "switch"]
    return render_template("switches.html", user=session["user"], role=session["role"],
                           switches=all_switches, stats=[], active="switches")

@app.route("/switch/<path:server_id>")
@login_required
def switch_detail(server_id):
    server = get_server(server_id)
    if not server:
        return redirect(url_for("switches"))
    data = _fetch_server(server)
    set_cache(server_id, data)
    return render_template("server_detail.html", user=session["user"],
                           role=session["role"], data=data, active="switches")

@app.route("/switch/add", methods=["POST"])
@login_required
def switch_add():
    d = request.get_json()
    ok, msg = add_server(
        name=d.get("name", ""),
        host=d.get("host", ""),
        port=int(d.get("port", 22)),
        username=d.get("username", ""),
        auth_type="password",
        password=d.get("password", ""),
        key_path=""
    )
    if not ok:
        return jsonify({"ok": False, "message": msg})
    servers_list = load_servers()
    for s in servers_list:
        if s["host"] == d.get("host") and s["port"] == int(d.get("port", 22)):
            s["os_type"]  = "switch"
            s["vendor"]   = d.get("vendor", "auto")
            s["protocol"] = d.get("protocol", "ssh")
    from modules.remote_ssh import save_servers
    save_servers(servers_list)
    server = get_server(f"{d['host']}:{d.get('port', 22)}")
    if server:
        if d.get("protocol") == "telnet":
            conn_ok, conn_msg = telnet_test_connection(server)
        else:
            conn_ok, conn_msg = switch_test_connection(server)
        return jsonify({"ok": True, "message": f"Switch agregado — {conn_msg}"})
    return jsonify({"ok": True, "message": msg})

@app.route("/switch/remove/<path:server_id>", methods=["POST"])
@login_required
def switch_remove(server_id):
    remove_server(server_id)
    invalidate(server_id)
    return jsonify({"ok": True})

@app.route("/switch/refresh/<path:server_id>")
@login_required
def switch_refresh(server_id):
    server = get_server(server_id)
    if server:
        invalidate(server_id)
        data = _fetch_server(server)
        set_cache(server_id, data)
    return jsonify({"ok": True})


# ── TERMINAL WEB SSH ──────────────────────────────────────────────────────────
@app.route("/terminal/<path:server_id>")
@login_required
def terminal(server_id):
    if session.get("role") != "admin":
        return redirect(url_for("dashboard"))
    server = get_server(server_id)
    if not server:
        return redirect(url_for("servers"))
    if server.get("os_type") == "windows":
        return redirect(url_for("server_detail", server_id=server_id))
    return render_template("terminal.html", server=server)


# ── SOCKETIO — TERMINAL ───────────────────────────────────────────────────────
@socketio.on("ssh_connect")
def on_ssh_connect(data):
    """Cliente solicita conexión SSH"""
    # Verificar sesión de Flask
    if not session.get("user") or session.get("role") != "admin":
        emit("ssh_error", {"message": "Acceso denegado"})
        return

    server_id = data.get("server_id")
    rows = data.get("rows", 24)
    cols = data.get("cols", 80)

    server = get_server(server_id)
    if not server:
        emit("ssh_error", {"message": "Servidor no encontrado"})
        return

    # Conectar en thread separado — SSH o Telnet según protocolo
    protocol = server.get("protocol", "ssh")
    if protocol == "telnet":
        t = threading.Thread(
            target=connect_telnet_terminal,
            args=(request.sid, server, socketio),
            daemon=True
        )
    else:
        t = threading.Thread(
            target=connect_ssh,
            args=(request.sid, server, socketio, rows, cols),
            daemon=True
        )
    t.start()


@socketio.on("ssh_input")
def on_ssh_input(data):
    """Input del usuario → canal SSH o Telnet"""
    if not session.get("user") or session.get("role") != "admin":
        return
    server_id = data.get("server_id", "")
    server = get_server(server_id) if server_id else None
    if server and server.get("protocol") == "telnet":
        send_telnet_input(request.sid, data.get("input", ""))
    else:
        send_input(request.sid, data.get("input", ""))


@socketio.on("resize")
def on_resize(data):
    """Redimensionar terminal"""
    resize_terminal(request.sid, data.get("rows", 24), data.get("cols", 80))


@socketio.on("disconnect")
def on_disconnect():
    """Limpiar sesión SSH o Telnet al desconectar"""
    disconnect_ssh(request.sid)
    disconnect_telnet(request.sid)


# ── ACTUALIZACIONES ───────────────────────────────────────────────────────────
@app.route("/updates")
@admin_required
def updates():
    status = check_for_updates()
    return render_template("updates.html", user=session["user"], role=session["role"],
                           active="updates", status=status,
                           update_result=False, update_ok=None,
                           update_msg=None, update_details=None)

@app.route("/updates/apply", methods=["POST"])
@admin_required
def updates_apply():
    ok, msg, details = apply_update()
    status = check_for_updates()
    return render_template("updates.html", user=session["user"], role=session["role"],
                           active="updates", status=status,
                           update_result=True, update_ok=ok,
                           update_msg=msg, update_details=details)


# ── CONFIGURACIÓN ─────────────────────────────────────────────────────────────
@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html", user=session["user"], role=session["role"],
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
    if new_pw != confirm:
        flash_msg, flash_type = "Las contraseñas no coinciden", "error"
    else:
        ok, msg = change_password(session["user"], current, new_pw)
        flash_msg, flash_type = msg, "ok" if ok else "error"
    return render_template("settings.html", user=session["user"], role=session["role"],
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
    return render_template("settings.html", user=session["user"], role=session["role"],
                           active="settings", active_tab="users",
                           users_list=get_users(), app_config=get_app_config(),
                           flash_msg=flash_msg, flash_type=flash_type)

@app.route("/settings/users/delete", methods=["POST"])
@admin_required
def settings_users_delete():
    username = request.form.get("username", "")
    ok, msg = remove_user(username, session["user"])
    return render_template("settings.html", user=session["user"], role=session["role"],
                           active="settings", active_tab="users",
                           users_list=get_users(), app_config=get_app_config(),
                           flash_msg=msg, flash_type="ok" if ok else "error")

@app.route("/settings/users/admin-password", methods=["POST"])
@admin_required
def settings_admin_password():
    target  = request.form.get("target_username", "")
    new_pw  = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")
    if new_pw != confirm:
        flash_msg, flash_type = "Las contraseñas no coinciden", "error"
    else:
        ok, msg = admin_change_password(target, new_pw)
        flash_msg, flash_type = msg, "ok" if ok else "error"
    return render_template("settings.html", user=session["user"], role=session["role"],
                           active="settings", active_tab="users",
                           users_list=get_users(), app_config=get_app_config(),
                           flash_msg=flash_msg, flash_type=flash_type)

@app.route("/settings/app", methods=["POST"])
@admin_required
def settings_app():
    ok, msg = update_app_config(
        port=request.form.get("port"),
        app_name=request.form.get("app_name"),
        session_timeout=request.form.get("session_timeout")
    )
    return render_template("settings.html", user=session["user"], role=session["role"],
                           active="settings", active_tab="app",
                           users_list=get_users(), app_config=get_app_config(),
                           flash_msg=msg, flash_type="ok" if ok else "error")


@app.route("/settings/font", methods=["POST"])
@login_required
def settings_font():
    """Guardar fuente elegida por el usuario"""
    d = request.get_json()
    font = d.get("font", "share_orbitron")
    try:
        from modules.config_manager import load_config, save_config
        config = load_config()
        if config:
            if "user_fonts" not in config:
                config["user_fonts"] = {}
            config["user_fonts"][session["user"]] = font
            save_config(config)
    except Exception:
        pass
    return jsonify({"ok": True})

@app.route("/settings/theme", methods=["POST"])
@login_required
def settings_theme():
    """Guardar tema elegido por el usuario"""
    d = request.get_json()
    theme = d.get("theme", "matrix")
    # Guardar en config por usuario
    try:
        from modules.config_manager import load_config, save_config
        config = load_config()
        if config:
            if "user_themes" not in config:
                config["user_themes"] = {}
            config["user_themes"][session["user"]] = theme
            save_config(config)
    except Exception:
        pass
    return jsonify({"ok": True})

# ── API ───────────────────────────────────────────────────────────────────────
@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(system_info.get_quick_stats())

@app.route("/api/servers")
@login_required
def api_servers():
    return jsonify(fetch_all_parallel(load_servers(), _fetch_server))

@app.route("/api/switch/<path:server_id>")
@login_required
def api_switch_single(server_id):
    """Datos de un switch individual — para carga lazy"""
    server_id = _decode_id(server_id)
    server = get_server(server_id)
    if not server:
        return jsonify({"connected": False, "error": "Servidor no encontrado"})
    # Intentar caché primero
    cached = get_cached(server_id)
    if cached:
        return jsonify(cached)
    # Si no hay caché, consultar
    data = _fetch_server(server)
    set_cache(server_id, data)
    return jsonify(data)


@app.route("/api/server/<path:server_id>")
@login_required
def api_server_single(server_id):
    """Datos de un servidor individual — para carga lazy"""
    server_id = _decode_id(server_id)
    server = get_server(server_id)
    if not server:
        return jsonify({"connected": False, "error": "Servidor no encontrado"})
    cached = get_cached(server_id)
    if cached:
        return jsonify(cached)
    data = _fetch_server(server)
    set_cache(server_id, data)
    return jsonify(data)


@app.route("/api/updates/check")
@admin_required
def api_updates_check():
    return jsonify(check_for_updates())


# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    args = parse_args()
    if args.matrix_mode:
        run_matrix_intro(duration=args.matrix_duration)
    cfg  = get_app_config()
    port = args.port if args.port != 5000 else cfg.get("port", 5000)
    print("\n" + "="*60)
    print("  ⬡  ServerShield — Hardening Tool iniciando...")
    print(f"  URL: http://0.0.0.0:{port}")
    if args.matrix_mode:
        print("  Modo: MATRIX MODE ACTIVATED 🟢")
    print("="*60 + "\n")
    socketio.run(app, host=args.host, port=port, debug=False, allow_unsafe_werkzeug=True)
