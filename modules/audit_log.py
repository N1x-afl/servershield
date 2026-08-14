"""
Módulo: audit_log
Registro de auditoría para comandos ejecutados en la terminal web
Guarda logs en /logs/audit.log con rotación automática
"""

import os
import json
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR  = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "audit.log")

# Crear directorio de logs si no existe
os.makedirs(LOG_DIR, exist_ok=True)

# Configurar logger con rotación — max 5MB, 3 backups
_handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=3)
_handler.setFormatter(logging.Formatter('%(message)s'))

_logger = logging.getLogger("servershield.audit")
_logger.setLevel(logging.INFO)
_logger.addHandler(_handler)
_logger.propagate = False


def log_terminal_connect(user, server_name, host, protocol="ssh"):
    """Registrar inicio de sesión en terminal"""
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event":     "TERMINAL_CONNECT",
        "user":      user,
        "server":    server_name,
        "host":      host,
        "protocol":  protocol.upper()
    }
    _logger.info(json.dumps(entry))


def log_terminal_disconnect(user, server_name, host):
    """Registrar cierre de sesión en terminal"""
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event":     "TERMINAL_DISCONNECT",
        "user":      user,
        "server":    server_name,
        "host":      host,
    }
    _logger.info(json.dumps(entry))


def log_terminal_command(user, server_name, host, command):
    """Registrar comando ejecutado en terminal"""
    command = command.strip()
    if not command or command in ["\r", "\n", ""]:
        return
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event":     "TERMINAL_COMMAND",
        "user":      user,
        "server":    server_name,
        "host":      host,
        "command":   command
    }
    _logger.info(json.dumps(entry))


def log_login(user, ip, success=True):
    """Registrar intento de login"""
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event":     "LOGIN_SUCCESS" if success else "LOGIN_FAILED",
        "user":      user,
        "ip":        ip
    }
    _logger.info(json.dumps(entry))


def get_audit_logs(limit=100, event_filter=None):
    """Leer los últimos N registros del log de auditoría"""
    if not os.path.exists(LOG_FILE):
        return []

    entries = []
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()

        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if event_filter and entry.get("event") != event_filter:
                    continue
                entries.append(entry)
                if len(entries) >= limit:
                    break
            except json.JSONDecodeError:
                continue
    except Exception:
        pass

    return entries
