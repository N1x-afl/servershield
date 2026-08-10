#!/bin/bash
cd ~/Descargas/servershield/hardening

# Fix async_mode si quedó mal
sed -i 's/async_mode="eventlet"/async_mode="threading"/g' app.py

# Lanzar
sudo venv/bin/python3 app.py "$@"
