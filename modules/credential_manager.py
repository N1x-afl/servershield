"""
Módulo: credential_manager
Cifrado de credenciales en servers.json usando Fernet (AES-128)
La clave maestra se guarda en .secret_key (excluido del repo)
"""

import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY_FILE    = os.path.join(BASE_DIR, ".secret_key")
SERVERS_FILE = os.path.join(BASE_DIR, "servers.json")


def _get_or_create_key():
    """Obtener o generar la clave maestra de cifrado"""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read().strip()
    # Generar nueva clave
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    os.chmod(KEY_FILE, 0o600)  # Solo root puede leerla
    return key


def _get_fernet():
    return Fernet(_get_or_create_key())


def encrypt_password(password):
    """Cifrar una contraseña"""
    if not password:
        return ""
    try:
        f = _get_fernet()
        return "ENC:" + f.encrypt(password.encode()).decode()
    except Exception:
        return password


def decrypt_password(encrypted):
    """Descifrar una contraseña"""
    if not encrypted:
        return ""
    if not encrypted.startswith("ENC:"):
        return encrypted  # Ya está en texto plano
    try:
        f = _get_fernet()
        return f.decrypt(encrypted[4:].encode()).decode()
    except Exception:
        return encrypted


def encrypt_servers_file():
    """
    Cifrar todas las contraseñas en servers.json
    Solo cifra las que no están cifradas todavía
    """
    if not os.path.exists(SERVERS_FILE):
        return 0

    with open(SERVERS_FILE) as f:
        servers = json.load(f)

    count = 0
    for s in servers:
        pw = s.get("password", "")
        if pw and not pw.startswith("ENC:"):
            s["password"] = encrypt_password(pw)
            count += 1

    with open(SERVERS_FILE, "w") as f:
        json.dump(servers, f, indent=2)

    return count


def decrypt_server(server):
    """
    Devolver una copia del servidor con la contraseña descifrada.
    Usar esto antes de conectar por SSH/Telnet.
    """
    s = dict(server)
    s["password"] = decrypt_password(s.get("password", ""))
    return s


def migrate_to_encrypted():
    """
    Script de migración — cifra todas las contraseñas existentes.
    Ejecutar una sola vez.
    """
    count = encrypt_servers_file()
    print(f"✓ {count} contraseña(s) cifrada(s) en servers.json")
    print(f"✓ Clave guardada en {KEY_FILE}")
    return count
