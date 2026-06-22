"""
Módulo: terminal_ssh
Manejo de sesiones SSH interactivas via WebSocket/SocketIO
"""

import paramiko
import threading
import time


# Almacén de sesiones activas { sid: { client, channel, thread } }
_sessions = {}
_sessions_lock = threading.Lock()


def _get_server(server_id, load_servers_fn):
    """Obtener configuración del servidor por ID"""
    for s in load_servers_fn():
        if s["id"] == server_id:
            return s
    return None


def connect_ssh(sid, server, socketio, rows=24, cols=80):
    """
    Establecer conexión SSH y comenzar a leer output.
    Corre en un thread separado.
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        kwargs = {
            "hostname": server["host"],
            "port":     server["port"],
            "username": server["username"],
            "timeout":  15,
            "banner_timeout": 20,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if server.get("auth_type") == "key" and server.get("key_path"):
            import os
            kwargs["key_filename"] = os.path.expanduser(server["key_path"])
        else:
            kwargs["password"] = server.get("password", "")

        client.connect(**kwargs)

        # Shell interactivo con tamaño de terminal
        channel = client.invoke_shell(
            term="xterm-256color",
            width=cols,
            height=rows
        )
        channel.setblocking(False)

        with _sessions_lock:
            _sessions[sid] = {
                "client":  client,
                "channel": channel,
                "active":  True
            }

        # Notificar conexión exitosa
        socketio.emit("ssh_connected", {
            "host": server["host"],
            "message": "Conexión establecida"
        }, to=sid)

        # Loop de lectura de output
        _read_loop(sid, channel, socketio)

    except paramiko.AuthenticationException:
        socketio.emit("ssh_error", {
            "message": "Error de autenticación — verificar usuario/contraseña"
        }, to=sid)
    except Exception as e:
        socketio.emit("ssh_error", {
            "message": str(e)[:120]
        }, to=sid)


def _read_loop(sid, channel, socketio):
    """Leer output del canal SSH y enviarlo al cliente"""
    while True:
        with _sessions_lock:
            session = _sessions.get(sid)
            if not session or not session.get("active"):
                break

        try:
            if channel.closed or channel.exit_status_ready():
                break

            if channel.recv_ready():
                data = channel.recv(4096)
                if data:
                    socketio.emit("ssh_output", {
                        "output": data.decode("utf-8", errors="replace")
                    }, to=sid)
            else:
                time.sleep(0.05)

        except Exception:
            break

    # Canal cerrado
    socketio.emit("ssh_closed", {}, to=sid)
    disconnect_ssh(sid)


def send_input(sid, data):
    """Enviar input del usuario al canal SSH"""
    with _sessions_lock:
        session = _sessions.get(sid)
    if session and session.get("channel"):
        try:
            session["channel"].send(data)
        except Exception:
            pass


def resize_terminal(sid, rows, cols):
    """Redimensionar el terminal"""
    with _sessions_lock:
        session = _sessions.get(sid)
    if session and session.get("channel"):
        try:
            session["channel"].resize_pty(width=cols, height=rows)
        except Exception:
            pass


def disconnect_ssh(sid):
    """Cerrar sesión SSH"""
    with _sessions_lock:
        session = _sessions.pop(sid, None)
    if session:
        try:
            session["active"] = False
            if session.get("channel"):
                session["channel"].close()
            if session.get("client"):
                session["client"].close()
        except Exception:
            pass
