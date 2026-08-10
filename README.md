# ⬡ ServerShield — Hardening Toolkit

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-00aa2e?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-00aa2e?style=for-the-badge&logo=flask&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Zorin%20%7C%20Ubuntu%20%7C%20Debian%20%7C%20Fedora-00aa2e?style=for-the-badge&logo=linux&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-WinRM-0078d4?style=for-the-badge&logo=windows&logoColor=white)
![Network](https://img.shields.io/badge/Network-Cisco%20%7C%20Fortinet%20%7C%20MikroTik-ff6600?style=for-the-badge&logo=cisco&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-00aa2e?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.7.0-00ff41?style=for-the-badge)

**Herramienta web de hardening y monitoreo de seguridad para infraestructura híbrida.**
Linux · Windows · Switches · Firewalls · Terminal Web SSH/Telnet · Temas visuales. Easter egg incluido. 🟢

</div>

---

## 📸 Vista previa

![Login](docs/login.png)
![Dashboard](docs/dashboard.png)
![Servers](docs/servers.png)
![CrowdSec](docs/crowdsec.png)

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

### 🌐 Servidores Remotos
| Tipo | Protocolo | Info recopilada |
|------|-----------|----------------|
| 🐧 **Linux** | SSH | CPU, RAM, disco, CVE, CrowdSec, usuarios, puertos, hardening completo |
| 🪟 **Windows** | WinRM | CPU, RAM, disco, Defender, Firewall, UAC, SMBv1, RDP, Windows Update |

### 🔀 Switches / Red
| Vendor | Protocolo | Capacidades |
|--------|-----------|-------------|
| 🔵 **Cisco** IOS/IOS-XE | SSH | VLANs, interfaces, ACLs, port security, STP |
| 🟢 **HP / Aruba** | SSH | VLANs, interfaces, usuarios, ACLs |
| 🟡 **MikroTik** RouterOS | SSH | Interfaces, VLANs, usuarios, firewall rules |
| 🔴 **Juniper** JunOS | SSH | Interfaces, VLANs, firewall, usuarios |
| 🟠 **Fortinet** FortiGate/FortiSwitch | SSH | Interfaces, políticas, usuarios admin, NTP, logging |
| 🔌 **Dispositivos Legacy** | Telnet | Cisco Catalyst 2960 y similares sin SSH |

**Chequeos de seguridad:** SSH v2 · Telnet deshabilitado · SNMP seguro · ACLs · AAA · NTP · Logging · Port Security · STP · Banner

### 🖥️ Terminal Web SSH/Telnet
- Terminal interactiva en el navegador con **xterm.js**
- Conexión en tiempo real vía **WebSocket** (Flask-SocketIO)
- Soporte **SSH** (Linux y switches) y **Telnet** (dispositivos legacy)
- Botones rápidos: ver updates, stats, puertos
- Solo accesible para el rol **admin**

### 🎨 Temas Visuales
- **6 temas** seleccionables desde Configuración: Matrix · Cyber Blue · Purple Haze · Red Alert · Ghost · Amber Terminal
- Cambio instantáneo sin recargar — persiste en `localStorage`
- Login y toda la app adaptan su color al tema elegido

### 🔤 Selector de Tipografía
- **6 familias de fuentes** con preview en tiempo real
- Terminal Clásica · Retro Pixel · Coder Pro · JetBrains · IBM Terminal · Classic Pro
- Panel en **Configuración → 🎨 TEMA**

### ⚙️ Gestión y Configuración
- **Panel de usuarios** — agregar, eliminar, cambiar contraseñas (hash bcrypt)
- **Roles** — Admin (acceso total) y Auditor (solo visualización)
- **Panel de actualizaciones** — verificar y aplicar `git pull` desde la UI
- **Favicon** ⬡ personalizado en la pestaña del navegador

### 🎮 Extras
- Login de **dos columnas** con ASCII art del servidor
- **Easter egg Matrix** (`--matrix-mode`) con lluvia de katakana y boot sequence
- Interfaz 100% estilo terminal con soporte de temas y fuentes
- Caché inteligente + consultas en paralelo
- Corre como **servicio systemd** con arranque automático

---

## 🚀 Instalación rápida

```bash
# 1. Clonar el repositorio
git clone https://github.com/N1x-afl/servershield.git
cd servershield

# 2. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Ejecutar
sudo venv/bin/python3 app.py
```

Abrí el navegador en **http://localhost:5000**

---

## 🔐 Credenciales por defecto

| Usuario | Contraseña | Rol |
|---------|-----------|-----|
| `admin` | `Adm1n@Shield2024` | Administrador — acceso total |
| `auditor` | `Aud1t@2024` | Solo visualización |

> ⚠️ **Cambiar las contraseñas** desde **Configuración → Contraseña** antes de usar en producción.

---

## 🟢 Easter Egg — Matrix Mode

```bash
sudo venv/bin/python3 app.py --matrix-mode
sudo venv/bin/python3 app.py --matrix-mode --matrix-duration 10
sudo venv/bin/python3 app.py --port 8080
```

---

## 🌐 Agregar Dispositivos Remotos

### 🐧 Linux (SSH)
```bash
ssh-keygen -t rsa -b 4096 -C "servershield"
ssh-copy-id usuario@IP-del-servidor
```
En ServerShield: **Servidores Remotos → Agregar Servidor → 🐧 Linux**

### 🪟 Windows (WinRM)
```powershell
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
```
En ServerShield: **Servidores Remotos → Agregar Servidor → 🪟 Windows**

### 🔀 Switch SSH
```
# Cisco IOS:
ip ssh version 2
line vty 0 4
 transport input ssh
 login local
```
En ServerShield: **Switches / Red → Agregar Switch → 🔒 SSH**

### 🔌 Switch Telnet (legacy)
En ServerShield: **Switches / Red → Agregar Switch → ⚠ Telnet** — puerto 23 automático.

### 🟠 Fortinet FortiGate
```
config system global
    set admin-ssh-port 22
end
```

---

## 🎨 Personalización

### Temas de color
**Configuración → 🎨 TEMA** → elegí entre 6 temas. El cambio es instantáneo.

### Tipografía
**Configuración → 🎨 TEMA** → sección **Selector de Tipografía** → 6 familias de fuentes con preview.

---

## 🖥️ Terminal Web

1. Ir al detalle de cualquier servidor Linux o switch
2. Clic en **▶ TERMINAL** (solo admin)
3. Terminal interactiva en el navegador

---

## ⬆️ Actualizaciones desde la UI

**Sistema → Actualizaciones** → verificar y aplicar `git pull` sin detener la app.

```bash
sudo systemctl restart servershield
```

---

## 🛠️ Instalación como servicio

```bash
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
ExecStartPre=/bin/sed -i 's/async_mode="eventlet"/async_mode="threading"/g' /opt/servershield/app.py
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

```
flask>=3.0.0
paramiko>=3.0.0
pywinrm>=0.4.3
bcrypt>=4.0.0
flask-socketio>=5.0.0
telnetlib3>=4.0.0
```

> Requiere Python 3.8+. Probado en Python 3.13 con `async_mode="threading"`.

---

## 📁 Estructura

```
servershield/
├── app.py                    # Flask principal + SocketIO
├── matrix_mode.py            # Easter egg Matrix
├── remote_cache.py           # Caché + consultas paralelas
├── requirements.txt
├── static/
│   ├── favicon.svg           # Favicon ⬡
│   └── js/themes.js          # Gestor de temas y fuentes
├── modules/
│   ├── system_info.py
│   ├── security_check.py
│   ├── cve_check.py
│   ├── crowdsec_mod.py
│   ├── users_mod.py
│   ├── ports_mod.py
│   ├── remote_ssh.py         # Linux remoto
│   ├── windows_remote.py     # Windows WinRM
│   ├── switch_remote.py      # Switches SSH multi-vendor
│   ├── telnet_remote.py      # Switches Telnet legacy
│   ├── terminal_ssh.py       # Terminal web SSH
│   ├── updater.py            # Auto-actualización
│   └── config_manager.py     # Usuarios y configuración
└── templates/
    ├── login.html
    ├── base.html
    ├── dashboard.html
    ├── servers.html
    ├── server_detail.html
    ├── switches.html
    ├── terminal.html
    ├── settings.html
    └── updates.html
```

---

## 🗺️ Roadmap

- [ ] Alertas por email/Telegram cuando un dispositivo cae
- [ ] Gráficos históricos de CPU/RAM
- [ ] Exportar reporte de hardening en PDF
- [ ] 2FA en el login
- [ ] Carga lazy de dispositivos (sin espera inicial)

---

## 🤝 Contribuir

1. Fork del repositorio
2. `git checkout -b feature/nueva-funcionalidad`
3. `git commit -m 'feat: descripción'`
4. `git push origin feature/nueva-funcionalidad`
5. Abrir Pull Request

---

## 📄 Licencia

MIT License — libre para usar, modificar y distribuir.
Si lo usás en producción o lo mejorás, una ⭐ en el repo es bienvenida.

---

<div align="center">

**Desarrollado con Python, Flask y demasiado café ☕**
*"El que no monitorea, no administra."*

[⭐ Star en GitHub](https://github.com/N1x-afl/servershield) · [🐛 Reportar issue](https://github.com/N1x-afl/servershield/issues) · [🔀 Pull Requests](https://github.com/N1x-afl/servershield/pulls)

</div>
