"""
Módulo: config_manager
Gestión de usuarios, contraseñas y configuración de la app
"""

import json
import os
import bcrypt
from datetime import datetime

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "..", "config.json")

# Configuración por defecto
DEFAULT_CONFIG = {
    "port": 5000,
    "host": "0.0.0.0",
    "app_name": "ServerShield",
    "session_timeout": 60,
    "users": {
        "admin": {
            "password_hash": "",
            "role": "admin",
            "created_at": "",
            "last_login": None
        },
        "auditor": {
            "password_hash": "",
            "role": "auditor",
            "created_at": "",
            "last_login": None
        }
    }
}


def _hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _check_password(password, hashed):
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def load_config():
    """Cargar configuración desde archivo"""
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_config(config):
    """Guardar configuración en archivo"""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def initialize_config(default_users=None):
    """
    Inicializar config.json si no existe.
    default_users: dict {username: (password, role)}
    """
    if os.path.exists(CONFIG_FILE):
        return load_config()

    config = DEFAULT_CONFIG.copy()
    config["users"] = {}

    if default_users:
        for username, (password, role) in default_users.items():
            config["users"][username] = {
                "password_hash": _hash_password(password),
                "role": role,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_login": None
            }

    save_config(config)
    return config


def verify_user(username, password):
    """Verificar credenciales. Devuelve rol o None"""
    config = load_config()
    if not config:
        return None
    user = config.get("users", {}).get(username)
    if not user:
        return None
    if _check_password(password, user["password_hash"]):
        # Actualizar último login
        config["users"][username]["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_config(config)
        return user["role"]
    return None


def change_password(username, current_password, new_password):
    """Cambiar contraseña de un usuario"""
    if len(new_password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"

    config = load_config()
    if not config:
        return False, "Error al leer configuración"

    user = config.get("users", {}).get(username)
    if not user:
        return False, "Usuario no encontrado"

    if not _check_password(current_password, user["password_hash"]):
        return False, "Contraseña actual incorrecta"

    config["users"][username]["password_hash"] = _hash_password(new_password)
    save_config(config)
    return True, "Contraseña actualizada correctamente"


def admin_change_password(target_username, new_password):
    """Admin cambia contraseña de cualquier usuario sin verificar la actual"""
    if len(new_password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"

    config = load_config()
    if not config:
        return False, "Error al leer configuración"

    if target_username not in config.get("users", {}):
        return False, "Usuario no encontrado"

    config["users"][target_username]["password_hash"] = _hash_password(new_password)
    save_config(config)
    return True, f"Contraseña de '{target_username}' actualizada"


def add_user(username, password, role):
    """Agregar nuevo usuario"""
    if not username or len(username) < 3:
        return False, "El usuario debe tener al menos 3 caracteres"
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    if role not in ["admin", "auditor"]:
        return False, "Rol inválido"

    config = load_config()
    if not config:
        return False, "Error al leer configuración"

    if username in config.get("users", {}):
        return False, f"El usuario '{username}' ya existe"

    config["users"][username] = {
        "password_hash": _hash_password(password),
        "role": role,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_login": None
    }
    save_config(config)
    return True, f"Usuario '{username}' creado correctamente"


def remove_user(username, requesting_user):
    """Eliminar usuario — no puede eliminarse a sí mismo"""
    if username == requesting_user:
        return False, "No podés eliminar tu propio usuario"
    if username == "admin":
        return False, "No se puede eliminar el usuario admin"

    config = load_config()
    if not config:
        return False, "Error al leer configuración"

    if username not in config.get("users", {}):
        return False, "Usuario no encontrado"

    del config["users"][username]
    save_config(config)
    return True, f"Usuario '{username}' eliminado"


def get_users():
    """Obtener lista de usuarios sin hashes"""
    config = load_config()
    if not config:
        return []
    users = []
    for username, data in config.get("users", {}).items():
        users.append({
            "username": username,
            "role": data.get("role", "auditor"),
            "created_at": data.get("created_at", "?"),
            "last_login": data.get("last_login", "Nunca")
        })
    return users


def get_app_config():
    """Obtener configuración de la app"""
    config = load_config()
    if not config:
        return {"port": 5000, "host": "0.0.0.0",
                "app_name": "ServerShield", "session_timeout": 60}
    return {
        "port": config.get("port", 5000),
        "host": config.get("host", "0.0.0.0"),
        "app_name": config.get("app_name", "ServerShield"),
        "session_timeout": config.get("session_timeout", 60)
    }


def update_app_config(port=None, host=None, app_name=None, session_timeout=None):
    """Actualizar configuración de la app"""
    config = load_config()
    if not config:
        return False, "Error al leer configuración"

    if port:
        try:
            p = int(port)
            if not 1024 <= p <= 65535:
                return False, "Puerto debe estar entre 1024 y 65535"
            config["port"] = p
        except ValueError:
            return False, "Puerto inválido"

    if host:
        config["host"] = host
    if app_name:
        config["app_name"] = app_name
    if session_timeout:
        try:
            config["session_timeout"] = int(session_timeout)
        except ValueError:
            return False, "Timeout inválido"

    save_config(config)
    return True, "Configuración actualizada. Reiniciá la app para aplicar cambios de puerto."
