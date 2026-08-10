"""
Módulo: remote_cache
Caché en memoria + consultas paralelas para servidores remotos
"""

import threading
import time
from datetime import datetime

# Caché global — { server_id: { data: {...}, timestamp: float } }
_cache = {}
_cache_lock = threading.Lock()
CACHE_TTL = 600  # 5 minutos


def get_cached(server_id):
    """Devuelve datos cacheados si son recientes, None si expiraron"""
    with _cache_lock:
        entry = _cache.get(server_id)
        if entry and (time.time() - entry["timestamp"]) < CACHE_TTL:
            return entry["data"]
    return None


def set_cache(server_id, data):
    with _cache_lock:
        _cache[server_id] = {"data": data, "timestamp": time.time()}


def invalidate(server_id=None):
    """Invalidar caché de un servidor o de todos"""
    with _cache_lock:
        if server_id:
            _cache.pop(server_id, None)
        else:
            _cache.clear()


def get_cache_age(server_id):
    """Devuelve cuántos segundos tiene el caché"""
    with _cache_lock:
        entry = _cache.get(server_id)
        if entry:
            return int(time.time() - entry["timestamp"])
    return None


def fetch_all_parallel(servers, fetch_fn):
    """
    Consulta todos los servidores en paralelo usando threads.
    fetch_fn: función que recibe un servidor y devuelve sus stats.
    Devuelve lista de resultados en el mismo orden que servers.
    """
    results = [None] * len(servers)

    def worker(idx, server):
        # Intentar caché primero
        cached = get_cached(server["id"])
        if cached:
            results[idx] = cached
            return
        # Si no hay caché, consultar y guardar
        data = fetch_fn(server)
        set_cache(server["id"], data)
        results[idx] = data

    threads = []
    for i, server in enumerate(servers):
        t = threading.Thread(target=worker, args=(i, server))
        t.start()
        threads.append(t)

    # Esperar a todos con timeout de 30 segundos
    for t in threads:
        t.join(timeout=45)

    return results
