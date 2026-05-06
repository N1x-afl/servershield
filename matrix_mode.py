#!/usr/bin/env python3
"""
ServerShield — Matrix Mode Easter Egg
Activar con: python3 app.py --matrix-mode
"""

import sys
import os
import time
import random
import threading
import argparse
import shutil


# ── CARACTERES MATRIX ─────────────────────────────────────────────────────────
MATRIX_CHARS = (
    "ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ"
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
    "アイウエオカキクケコサシスセソタチツテトナニヌネノ"
)

GREEN       = "\033[92m"
GREEN_BRIGHT= "\033[1;92m"
GREEN_DIM   = "\033[2;32m"
GREEN_MID   = "\033[32m"
WHITE       = "\033[1;97m"
BLACK_BG    = "\033[40m"
RESET       = "\033[0m"
CLEAR       = "\033[2J\033[H"
HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"

def _move(row, col):
    return f"\033[{row};{col}H"

def _term_size():
    s = shutil.get_terminal_size((80, 24))
    return s.lines, s.columns


# ── ANIMACIÓN MATRIX ──────────────────────────────────────────────────────────

class MatrixRain:
    def __init__(self, rows, cols):
        self.rows = rows
        self.cols = cols
        self.drops = {}        # col → fila actual
        self.trails = {}       # col → lista de (row, char, brightness)
        self.trail_len = 18
        self._init_drops()

    def _init_drops(self):
        for c in range(0, self.cols, random.randint(1, 2)):
            self.drops[c] = random.randint(-self.rows, 0)
            self.trails[c] = []

    def step(self):
        buf = []
        for c in list(self.drops.keys()):
            r = self.drops[c]
            char = random.choice(MATRIX_CHARS)

            # Cabeza brillante
            if 1 <= r <= self.rows:
                buf.append(_move(r, c) + GREEN_BRIGHT + WHITE + char + RESET)

            # Agregar al trail
            if 1 <= r <= self.rows:
                self.trails[c].append((r, char))

            # Dibujar trail con degradado
            trail = self.trails[c]
            for i, (tr, tc) in enumerate(trail[-self.trail_len:]):
                age = len(trail) - self.trail_len + i
                if tr < 1 or tr > self.rows:
                    continue
                pos = i / self.trail_len
                if pos > 0.8:
                    color = GREEN_BRIGHT
                elif pos > 0.5:
                    color = GREEN
                elif pos > 0.25:
                    color = GREEN_MID
                else:
                    color = GREEN_DIM
                # Cambiar char aleatoriamente a veces
                display = random.choice(MATRIX_CHARS) if random.random() < 0.05 else tc
                buf.append(_move(tr, c) + color + display + RESET)

            # Limpiar cola vieja
            if len(trail) > self.trail_len + 5:
                old_row = trail[0][0]
                if 1 <= old_row <= self.rows:
                    buf.append(_move(old_row, c) + " ")
                self.trails[c].pop(0)

            # Avanzar gota
            self.drops[c] += 1

            # Reset cuando sale de pantalla
            if self.drops[c] > self.rows + self.trail_len:
                self.drops[c] = random.randint(-self.rows // 2, 0)
                self.trails[c] = []

        sys.stdout.write("".join(buf))
        sys.stdout.flush()


# ── TEXTOS DE INTRO ───────────────────────────────────────────────────────────

BOOT_LINES = [
    (GREEN_DIM,   "  [SYSTEM] Initializing secure channel..."),
    (GREEN,       "  [KERNEL] Loading ServerShield kernel modules..."),
    (GREEN,       "  [CRYPTO] Establishing encrypted session..."),
    (GREEN_BRIGHT,"  [AUTH]   Identity verification... "),
    (WHITE,       "  [AUTH]   ✓ ACCESS GRANTED"),
    (GREEN,       "  [IDS]    CrowdSec threat intelligence synced..."),
    (GREEN,       "  [FW]     Firewall rules loaded..."),
    (GREEN_BRIGHT,"  [SHIELD] All systems nominal."),
    ("",          ""),
]

ASCII_LOGO = r"""
 ██████╗███████╗██████╗ ██╗   ██╗███████╗██████╗ ███████╗██╗  ██╗██╗███████╗██╗     ██████╗
██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
╚█████╗ █████╗  ██████╔╝╚██╗ ██╔╝█████╗  ██████╔╝███████╗███████║██║█████╗  ██║     ██║  ██║
 ╚═══██╗██╔══╝  ██╔══██╗ ╚████╔╝ ██╔══╝  ██╔══██╗╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
██████╔╝███████╗██║  ██║  ╚██╔╝  ███████╗██║  ██║███████║██║  ██║██║███████╗███████╗██████╔╝
╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
"""

def _center(text, width):
    stripped = text.replace("\033[0m","").replace("\033[1;92m","").replace("\033[32m","")
    pad = max(0, (width - len(stripped)) // 2)
    return " " * pad + text


def run_matrix_intro(duration=6):
    """Corre la lluvia matrix por `duration` segundos y luego hace el boot"""
    rows, cols = _term_size()

    sys.stdout.write(HIDE_CURSOR + CLEAR + BLACK_BG)
    sys.stdout.flush()

    rain = MatrixRain(rows, cols)

    start = time.time()
    try:
        while time.time() - start < duration:
            rain.step()
            time.sleep(0.045)
    except KeyboardInterrupt:
        pass

    # ── TRANSICIÓN: overlay con logo y boot sequence ──────────────────────────
    sys.stdout.write(CLEAR)
    sys.stdout.flush()

    # Imprimir logo centrado
    logo_lines = ASCII_LOGO.strip("\n").split("\n")
    start_row = max(1, (rows - len(logo_lines) - len(BOOT_LINES) - 4) // 2)

    for i, line in enumerate(logo_lines):
        sys.stdout.write(_move(start_row + i, 1))
        sys.stdout.write(GREEN_BRIGHT + _center(line, cols) + RESET)
        sys.stdout.flush()
        time.sleep(0.04)

    sys.stdout.write("\n")

    # Línea divisoria
    div_row = start_row + len(logo_lines) + 1
    sys.stdout.write(_move(div_row, 1))
    div = "─" * min(cols - 4, 88)
    sys.stdout.write(GREEN_DIM + _center(div, cols) + RESET + "\n\n")
    sys.stdout.flush()

    # Boot sequence línea por línea con efecto de typing
    boot_row = div_row + 2
    for j, (color, line) in enumerate(BOOT_LINES):
        sys.stdout.write(_move(boot_row + j, 1))
        if line:
            sys.stdout.write(color)
            for ch in line:
                sys.stdout.write(ch)
                sys.stdout.flush()
                time.sleep(random.uniform(0.008, 0.025))
            sys.stdout.write(RESET)
        sys.stdout.write("\n")
        sys.stdout.flush()
        time.sleep(random.uniform(0.08, 0.22))

    time.sleep(0.5)

    # Mensaje final
    final_row = boot_row + len(BOOT_LINES) + 1
    launch_msg = "  ▶  Launching ServerShield Web Interface on http://localhost:5000 ..."
    sys.stdout.write(_move(final_row, 1))
    for ch in launch_msg:
        sys.stdout.write(GREEN_BRIGHT + ch + RESET)
        sys.stdout.flush()
        time.sleep(0.018)

    time.sleep(0.8)

    # Segunda lluvia corta mientras carga Flask
    rain2 = MatrixRain(rows, cols)
    start2 = time.time()
    while time.time() - start2 < 1.8:
        rain2.step()
        time.sleep(0.045)

    # Restaurar terminal
    sys.stdout.write(CLEAR + SHOW_CURSOR + RESET)
    sys.stdout.flush()


# ── ARGPARSE INTEGRATION ──────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="ServerShield — Hardening Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 app.py                    # Modo normal
  python3 app.py --matrix-mode      # 🟢 Activar Matrix Easter Egg
  sudo python3 app.py --matrix-mode # Con privilegios completos + Matrix
        """
    )
    parser.add_argument(
        "--matrix-mode",
        action="store_true",
        help="[EASTER EGG] Iniciar con animación Matrix en la terminal"
    )
    parser.add_argument(
        "--port", type=int, default=5000,
        help="Puerto del servidor web (default: 5000)"
    )
    parser.add_argument(
        "--host", default="0.0.0.0",
        help="Host del servidor web (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--matrix-duration", type=int, default=6,
        help="Duración de la animación matrix en segundos (default: 6)"
    )
    return parser.parse_args()
