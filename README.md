# ⬡ ServerShield — Hardening Toolkit

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-00aa2e?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-00aa2e?style=for-the-badge&logo=flask&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Zorin%20%7C%20Ubuntu%20%7C%20Debian-00aa2e?style=for-the-badge&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-00aa2e?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-00ff41?style=for-the-badge)

**Herramienta web de hardening y monitoreo de seguridad para servidores Linux.**  
Interfaz estilo terminal. Multi-servidor vía SSH. Easter egg incluido. 🟢

</div>

---

## 📸 Vista previa

```
┌─────────────────────────────────────────────────────────────┐
│  ⬡ SERVERSHIELD  │  HARDENING TOOLKIT          ● admin SALIR│
├──────────────┬──────────────────────────────────────────────┤
│ NAVEGACIÓN   │                                              │
│              │   DASHBOARD    Vista general del servidor    │
│ ◈ Dashboard  │                                              │
│              │   17.0%    72.7%    98%      420            │
│ MÓDULOS      │   CPU      RAM      DISCO    PROCESOS        │
│              │                                              │
│ ◉ Estado     │   HOSTNAME: NB   KERNEL: 6.17.0-23-generic  │
│ ⚑ CVE        │   IP: 192.168.10.253   UPTIME: 15 min       │
│ ⛊ CrowdSec   │   MEMORIA: 11450 MB / 15754 MB              │
│ ⬡ Seguridad  │                                              │
│ ◎ Usuarios   │   [ACTIVIDAD DEL TERMINAL]                  │
│ ⊟ Puertos    │   [STATUS] Todos los módulos cargados ✓     │
│              │                                              │
│ INFRAESTRUC. │                                              │
│ ⊞ Remotos    │                                              │
└──────────────┴──────────────────────────────────────────────┘
```

---

## ✨ Características

### 🖥️ Análisis Local
| Módulo | Descripción |
|--------|-------------|
| **Dashboard** | CPU, RAM, disco, uptime, procesos en tiempo real |
| **Estado Servidor** | Servicios systemd, top procesos, interfaces de red |
| **CVE / Vulnerabilidades** | Integración con NVD API (NIST), paquetes críticos, Lynis |
| **CrowdSec IDS** | IPs baneadas, alertas activas, bouncers, hub collections |
| **Seguridad / Firewall** | Hardening score, UFW, SSH, sysctl, AppArmor/SELinux |
| **Usuarios / Root** | Sudo, UID 0, /etc/shadow, grupos críticos, lastlog |
| **Puertos / Red** | Clasificación de riesgo, exposición pública, reglas firewall |

### 🌐 Análisis Multi-Servidor (SSH)
- Conectá y monitoreá **múltiples servidores remotos** desde una sola interfaz
- Autenticación por **contraseña o clave SSH**
- Dashboard unificado con **security score** por servidor
- Vista detallada: métricas, puertos, servicios, últimos logins
- Detección automática de UFW, fail2ban, CrowdSec en servidores remotos

### 🎨 Extras
- Login de **dos columnas** con ASCII art del servidor
- **Easter egg Matrix** (`--matrix-mode`) con lluvia de katakana y boot sequence
- Interfaz 100% estilo terminal — verde fosforescente / negro
- Corre como **servicio systemd** con arranque automático

---

## 🚀 Instalación rápida

```bash
# 1. Clonar el repositorio
git clone https://github.com/TU_USUARIO/servershield.git
cd servershield

# 2. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Ejecutar (modo normal)
python3 app.py

# 5. Ejecutar con privilegios completos (recomendado)
sudo venv/bin/python3 app.py
```

Abrí el navegador en **http://localhost:5000**

---

## 🔐 Credenciales por defecto

| Usuario | Contraseña | Rol |
|---------|-----------|-----|
| `admin` | `Adm1n@Shield2024` | Administrador — acceso total |
| `auditor` | `Aud1t@2024` | Solo visualización |

> ⚠️ **Importante:** Cambiá las contraseñas antes de usar en producción.  
> Editá el diccionario `USERS` en `app.py`:

```python
USERS = {
    "tu_usuario": "TuContraseñaSegura123!",
    "otro_usuario": "OtraContraseña456@"
}
```

---

## 🟢 Easter Egg — Matrix Mode

```bash
# Activar animación Matrix al lanzar
sudo venv/bin/python3 app.py --matrix-mode

# Con duración personalizada (segundos)
sudo venv/bin/python3 app.py --matrix-mode --matrix-duration 10

# Puerto personalizado
sudo venv/bin/python3 app.py --port 8080
```

---

## 🌐 Agregar Servidores Remotos

1. Ir a **Infraestructura → Servidores Remotos** en el sidebar
2. Clic en **＋ Agregar Servidor**
3. Completar: nombre, IP/host, puerto SSH, usuario
4. Elegir autenticación: **contraseña** o **clave SSH**
5. ServerShield prueba la conexión automáticamente

### Autenticación con clave SSH (recomendada)

```bash
# Generar clave SSH si no tenés una
ssh-keygen -t rsa -b 4096 -C "servershield"

# Copiar la clave pública al servidor remoto
ssh-copy-id usuario@IP-del-servidor

# En ServerShield usar:
# Tipo: Clave SSH / Ruta: ~/.ssh/id_rsa
```

---

## 🛠️ Instalación como servicio (arranque automático)

```bash
sudo mv servershield /opt/servershield
cd /opt/servershield
sudo python3 -m venv venv
sudo venv/bin/pip install -r requirements.txt
sudo nano /etc/systemd/system/servershield.service
```

```ini
[Unit]
Description=ServerShield Hardening Toolkit
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/servershield
ExecStart=/opt/servershield/venv/bin/python3 /opt/servershield/app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable servershield
sudo systemctl start servershield
```

---

## 📋 Requisitos

- Python 3.8+
- Linux (Zorin OS / Ubuntu 20.04+ / Debian 11+)

```bash
sudo apt install python3-venv python3-pip unzip -y
```

**`requirements.txt`**
```
flask>=3.0.0
paramiko>=3.0.0
```

---

## 🔒 Seguridad en producción

```nginx
server {
    listen 443 ssl;
    server_name tu-dominio.com;
    allow 192.168.1.0/24;
    deny all;
    location / {
        proxy_pass http://127.0.0.1:5000;
    }
}
```

---

## 📁 Estructura del proyecto

```
servershield/
├── app.py                    # Aplicación Flask principal
├── matrix_mode.py            # Easter egg Matrix + argparse
├── requirements.txt
├── .gitignore
├── modules/
│   ├── system_info.py
│   ├── security_check.py
│   ├── cve_check.py
│   ├── crowdsec_mod.py
│   ├── users_mod.py
│   ├── ports_mod.py
│   └── remote_ssh.py         # Multi-servidor SSH
└── templates/
    ├── login.html
    ├── base.html
    ├── dashboard.html
    ├── status.html
    ├── cve.html
    ├── crowdsec.html
    ├── security.html
    ├── users.html
    ├── ports.html
    ├── servers.html           # Dashboard multi-servidor
    └── server_detail.html
```

---

## 🤝 Contribuir

1. Fork del repositorio
2. `git checkout -b feature/nueva-funcionalidad`
3. `git commit -m 'feat: descripción'`
4. `git push origin feature/nueva-funcionalidad`
5. Abrir Pull Request

### Ideas para contribuir
- [ ] Alertas por email/Telegram cuando un servidor cae
- [ ] Gráficos históricos de CPU/RAM
- [ ] Autenticación con 2FA
- [ ] Exportar análisis en PDF desde la web
- [ ] Soporte para múltiples nodos simultáneos

---

## 📄 Licencia

MIT License — libre para usar, modificar y distribuir.  
Si lo usás en producción o lo mejorás, una ⭐ en el repo es bienvenida.

---

<div align="center">

**Desarrollado con Python, Flask y demasiado café ☕**  
*"El que no monitorea, no administra."*

</div>
