"""
J.A.R.V.I.S — IRON PROTOCOL · NEXUS EDITION
ui.py — Holographic Interface System  [FULL OVERHAUL]

Upgrades over previous edition:
  ✦ Film-accurate teal arc reactor (#00ffe8) palette
  ✦ Frameless draggable + resizable window
  ✦ CRT scanline overlay cached as QPixmap (no per-frame regen)
  ✦ Depth vignette + edge plasma glow on HUD canvas
  ✦ Ring motion-blur trails (history buffer)
  ✦ Particle pool with hard cap (perf)
  ✦ ConversationPanel — threaded chat bubbles (replaces flat log)
  ✦ ThreatMeter widget — live alert level bar
  ✦ MissionTimer widget — elapsed + lap
  ✦ FlashOverlay — full-screen message flash
  ✦ ResizeGrip — frameless window corner resize
  ✦ set_alert(level) public API  ("nominal"|"caution"|"critical")
  ✦ flash_message(txt, ms) public API
  ✦ clear_chat() public API
  ✦ Ctrl+W clears loaded file
  ✦ All public API from previous editions preserved
"""
from __future__ import annotations

import json
import math
import os
import urllib.request
os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "0")
os.environ.setdefault("QT_SCALE_FACTOR_ROUNDING_POLICY", "PassThrough")
import platform
import random
import sys
import threading
import time
from pathlib import Path

import psutil

from PyQt6.QtCore import (
    QEasingCurve, QMimeData, QObject, QPointF, QRectF, QSize,
    QSizeF, Qt, QTimer, QUrl, pyqtSignal,
)
from PyQt6.QtGui import (
    QBrush, QColor, QCursor, QConicalGradient, QDragEnterEvent,
    QDropEvent, QFont, QFontDatabase, QKeySequence, QLinearGradient,
    QPainter, QPainterPath, QPen, QPixmap, QRadialGradient, QShortcut,
)
from PyQt6.QtWidgets import (
    QApplication, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QMainWindow, QPushButton, QScrollArea, QSizePolicy, QTextEdit,
    QVBoxLayout, QWidget, QGraphicsDropShadowEffect, QSizeGrip,
)


# ─────────────────────────────────────────────────────────────────
#  PATHS
# ─────────────────────────────────────────────────────────────────
def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent

BASE_DIR   = _base_dir()
CONFIG_DIR = BASE_DIR / "config"
API_FILE   = CONFIG_DIR / "api_keys.json"

_DEFAULT_W, _DEFAULT_H = 1440, 900
_MIN_W,     _MIN_H     = 1100, 720
_LEFT_W  = 300
_RIGHT_W = 460
_OS = platform.system()
_MAX_PARTICLES = 120   # hard pool cap
_USER_NAME = "PRANAV"   # ← change your name here


# ─────────────────────────────────────────────────────────────────
#  COLOUR PALETTE — Iron Man Film-Accurate
# ─────────────────────────────────────────────────────────────────
class C:
    BG        = "#000000"
    PANEL     = "#020b0e"
    PANEL2    = "#030e12"
    PANEL3    = "#041218"
    VOID      = "#000000"

    BORDER    = "#041a20"
    BORDER_B  = "#083040"
    BORDER_A  = "#0a3a48"
    BORDER_G  = "#041a10"

    # Arc reactor teal (film-accurate)
    PRI       = "#00ffe8"
    PRI_DIM   = "#006655"
    PRI_GHO   = "#001a15"
    PRI_GLOW  = "#aaffee"
    PRI_ULTRA = "#ffffff"
    PRI_DEEP  = "#002820"

    # Holographic orange (Stark display)
    ACC       = "#ff6600"
    ACC2      = "#ff9944"
    ACC_DIM   = "#662200"
    ACC_GLOW  = "#ffcc88"
    ACC_DEEP  = "#1a0a00"

    GREEN     = "#00ff88"
    GREEN_D   = "#009952"
    GREEN_G   = "#001a10"
    GREEN_ULT = "#80ffcc"

    RED       = "#ff2244"
    RED_G     = "#1a0010"
    RED_D     = "#7a0025"
    MUTED_C   = "#ff2244"

    VIOLET    = "#7b00ff"
    VIOLET_D  = "#3a0a70"
    VIOLET_G  = "#0d0020"

    TEXT        = "#00bfa8"
    TEXT_DIM    = "#004a3a"
    TEXT_MED    = "#008877"
    TEXT_BRIGHT = "#80ffe8"
    WHITE       = "#e8fff8"

    BAR_BG    = "#010c0e"
    TEAL      = "#00ffe8"
    TEAL_D    = "#004a3a"
    CYAN      = "#00ffff"
    ORANGE    = "#ff6600"
    GOLD      = "#ffaa00"
    AMBER     = "#ff8800"
    AMBER2    = "#ffbb44"
    AMBER_D   = "#663300"
    AMBER_G   = "#110800"

    # Alert level colours
    ALERT_NOM = "#00ff88"    # nominal green
    ALERT_CAU = "#ff8800"    # caution amber
    ALERT_CRI = "#ff2244"    # critical red


def qcol(h: str, a: int = 255) -> QColor:
    c = QColor(h)
    c.setAlpha(max(0, min(255, int(a))))
    return c


# ─────────────────────────────────────────────────────────────────
#  SYSTEM METRICS
# ─────────────────────────────────────────────────────────────────
class _SysMetrics:
    # Processes considered suspicious/high-risk
    _SUSPICIOUS_PROCS = {
        "mimikatz", "wireshark", "nmap", "netcat", "nc", "meterpreter",
        "keylogger", "rat", "torrent", "cryptominer", "xmrig", "minerd",
        "coinhive", "wscript", "cscript", "mshta", "regsvr32",
    }

    def __init__(self):
        self.cpu        = 0.0
        self.mem        = 0.0
        self.net        = 0.0   # MB/s total
        self.net_dl     = 0.0   # MB/s download (recv)
        self.net_ul     = 0.0   # MB/s upload (sent)
        self.disk       = 0.0   # disk usage %
        self.proc_count = 0     # total running processes
        self.sus_count  = 0     # suspicious process matches
        self.open_conns = 0     # active network connections
        self.threat_pct = 0.0   # 0–100 composite threat score
        self.threat_lvl = "nominal"  # nominal | caution | critical

        self._lock       = threading.Lock()
        self._last_net   = psutil.net_io_counters()
        self._last_net_t = time.time()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                self._update()
            except Exception:
                pass
            time.sleep(1.5)

    def _update(self):
        # ── CPU & RAM ─────────────────────────────────────────────
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent

        # ── Network throughput ────────────────────────────────────
        nc  = psutil.net_io_counters()
        now = time.time()
        dt  = max(now - self._last_net_t, 0.001)
        dl_mbps = (nc.bytes_recv - self._last_net.bytes_recv) / dt / (1024 * 1024)
        ul_mbps = (nc.bytes_sent - self._last_net.bytes_sent) / dt / (1024 * 1024)
        net_mbps = dl_mbps + ul_mbps
        self._last_net   = nc
        self._last_net_t = now

        # ── Disk usage (busiest partition) ────────────────────────
        disk_max = 0.0
        try:
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    if usage.percent > disk_max:
                        disk_max = usage.percent
                except Exception:
                    pass
        except Exception:
            pass

        # ── Process scan ─────────────────────────────────────────
        proc_count = 0
        sus_count  = 0
        try:
            for p in psutil.process_iter(["name"]):
                proc_count += 1
                pname = (p.info.get("name") or "").lower()
                for s in self._SUSPICIOUS_PROCS:
                    if s in pname:
                        sus_count += 1
                        break
        except Exception:
            pass

        # ── Open network connections ──────────────────────────────
        open_conns = 0
        try:
            open_conns = len(psutil.net_connections(kind="inet"))
        except Exception:
            pass

        # ── Composite threat score (0–100) ───────────────────────
        # Weights: CPU 25%, RAM 20%, Network 20%, Disk 15%, Conns 10%, Sus procs 10%
        net_score  = min(100.0, net_mbps * 10)          # 10 MB/s = 100%
        conn_score = min(100.0, open_conns * 2)         # 50 conns = 100%
        sus_score  = min(100.0, sus_count * 33.3)       # 3 hits = 100%

        threat = (
            cpu        * 0.25 +
            mem        * 0.20 +
            net_score  * 0.20 +
            disk_max   * 0.15 +
            conn_score * 0.10 +
            sus_score  * 0.10
        )
        threat = max(0.0, min(100.0, threat))

        if threat >= 70:
            lvl = "critical"
        elif threat >= 40:
            lvl = "caution"
        else:
            lvl = "nominal"

        with self._lock:
            self.cpu        = cpu
            self.mem        = mem
            self.net        = net_mbps
            self.net_dl     = dl_mbps
            self.net_ul     = ul_mbps
            self.disk       = disk_max
            self.proc_count = proc_count
            self.sus_count  = sus_count
            self.open_conns = open_conns
            self.threat_pct = threat
            self.threat_lvl = lvl

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "cpu":        self.cpu,
                "mem":        self.mem,
                "net":        self.net,
                "net_dl":     self.net_dl,
                "net_ul":     self.net_ul,
                "disk":       self.disk,
                "proc_count": self.proc_count,
                "sus_count":  self.sus_count,
                "open_conns": self.open_conns,
                "threat_pct": self.threat_pct,
                "threat_lvl": self.threat_lvl,
            }

_metrics = _SysMetrics()


# ─────────────────────────────────────────────────────────────────
#  SCANLINE CACHE — built once, reused every frame
# ─────────────────────────────────────────────────────────────────
class _ScanlineCache:
    """Renders horizontal CRT scan-lines into a QPixmap of given size."""
    _cache: dict[tuple, QPixmap] = {}

    @classmethod
    def get(cls, w: int, h: int, col: str = C.PRI) -> QPixmap:
        key = (w, h, col)
        if key not in cls._cache:
            px = QPixmap(w, h)
            px.fill(Qt.GlobalColor.transparent)
            p = QPainter(px)
            p.setOpacity(0.022)
            pen = QPen(qcol(col, 18), 1)
            p.setPen(pen)
            for y in range(0, h, 4):
                p.drawLine(0, y, w, y)
            p.end()
            cls._cache[key] = px
        return cls._cache[key]

    @classmethod
    def invalidate(cls):
        cls._cache.clear()


# ─────────────────────────────────────────────────────────────────
#  HUD CANVAS — Arc Reactor + all overlays
# ─────────────────────────────────────────────────────────────────
class HudCanvas(QWidget):
    def __init__(self, face_path: str, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent)
        self.setMinimumSize(340, 340)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.muted     = False
        self.speaking  = False
        self.state     = "INITIALISING"
        self.alert_col = C.ALERT_NOM   # set_alert() writes here

        self._tick       = 0
        self._scale      = 1.0
        self._tgt_scale  = 1.0
        self._halo       = 50.0
        self._tgt_halo   = 50.0
        self._last_t     = time.time()
        self._blink      = True
        self._blink_tick = 0

        # Ring history for motion-blur trails
        self._ring_hist: list[list[float]] = []
        self._rings = [i * (360 / 8) for i in range(8)]
        self._ring_speeds = [0.8, -0.5, 1.2, -0.3, 0.6, -0.9, 0.4, -0.7]

        self._hex_grid: list[tuple] = []
        self._regen_hex_grid()

        self._conduits: list[dict] = []
        self._regen_conduits()

        self._particles: list[dict] = []
        self._particle_timer = 0

        self._pulses: list[dict] = []
        self._wave_data   = [0.0] * 80
        self._wave_phase  = 0.0
        self._bracket_rot = 0.0
        self._data_nodes: list[dict] = []
        self._regen_data_nodes()
        self._tri_rot = 0.0
        self._arc_t   = 0.0
        self._chrom_t = 0.0

        # Vignette cache
        self._vignette_px: QPixmap | None = None
        self._vig_size = (0, 0)

        self._face_px: QPixmap | None = None
        self._face_cache: QPixmap | None = None   # pre-scaled cache
        self._face_cache_sz: int = 0
        self._load_face(face_path)

        self._tmr = QTimer(self)
        self._tmr.timeout.connect(self._step)
        self._tmr.start(20)   # ~50 fps — smoother without killing CPU

    # ── DATA GENERATION ──────────────────────────────────────────

    def _regen_hex_grid(self):
        self._hex_grid = []
        for q in range(-6, 7):
            for r in range(-6, 7):
                x = q + r * 0.5
                y = r * 0.866
                dist = math.hypot(x, y)
                if 1.5 < dist < 5.8:
                    self._hex_grid.append((x, y,
                                           random.uniform(0, math.pi * 2),
                                           random.uniform(0.008, 0.025)))

    def _regen_conduits(self):
        self._conduits = []
        for ang in [0, 30, 60, 90, 120, 150, 210, 240, 270, 300, 330]:
            self._conduits.append({
                "angle":   math.radians(ang),
                "r_start": 0.22,
                "r_end":   random.uniform(0.55, 0.72),
                "color":   random.choice([C.PRI, C.PRI, C.ACC, C.GREEN]),
                "width":   random.uniform(0.5, 1.8),
                "phase":   random.uniform(0, math.pi * 2),
            })

    def _regen_data_nodes(self):
        self._data_nodes = []
        labels = ["SYS", "NET", "AI", "MEM", "PWR", "SEC", "QTM", "SYN"]
        colors = [C.PRI, C.ACC, C.GREEN, C.VIOLET, C.PRI, C.GREEN, C.ACC, C.PRI]
        for i, (lbl, col) in enumerate(zip(labels, colors)):
            self._data_nodes.append({
                "label":  lbl,
                "color":  col,
                "angle":  math.radians(i * 45 + 22.5),
                "r_frac": random.uniform(0.60, 0.72),
                "phase":  random.uniform(0, math.pi * 2),
                "val":    random.randint(20, 95),
            })

    # ── STEP ─────────────────────────────────────────────────────

    def _step(self):
        self._tick += 1
        now   = time.time()
        speak = self.speaking
        muted = self.muted

        # Scale / halo targets
        if now - self._last_t > (0.07 if speak else 0.40):
            if speak:
                self._tgt_scale = random.uniform(1.04, 1.10)
                self._tgt_halo  = random.uniform(160, 220)
            elif muted:
                self._tgt_scale = random.uniform(0.998, 1.002)
                self._tgt_halo  = random.uniform(6, 18)
            else:
                self._tgt_scale = random.uniform(1.0, 1.015)
                self._tgt_halo  = random.uniform(55, 85)
            self._last_t = now

        self._scale = self._scale + (self._tgt_scale - self._scale) * 0.12
        self._halo  = self._halo  + (self._tgt_halo  - self._halo)  * 0.10

        # Store ring history for motion-blur (keep 3 frames)
        self._ring_hist.append(list(self._rings))
        if len(self._ring_hist) > 3:
            self._ring_hist.pop(0)

        spd_mul = 2.2 if speak else 1.0
        for i, spd in enumerate(self._ring_speeds):
            self._rings[i] = (self._rings[i] + spd * spd_mul) % 360

        self._bracket_rot = (self._bracket_rot + (0.4 if speak else 0.15)) % 360
        self._tri_rot     = (self._tri_rot     + (0.6 if speak else 0.2))  % 360
        self._chrom_t    += 0.045
        self._arc_t      += 0.012

        self._blink_tick += 1
        if self._blink_tick >= (8 if speak else 24):
            self._blink = not self._blink
            self._blink_tick = 0

        self._hex_grid = [
            (x, y, ph + sp, sp) for x, y, ph, sp in self._hex_grid
        ]

        if self._tick % 45 == 0:
            for nd in self._data_nodes:
                nd["val"]    = max(5, min(99, nd["val"] + random.randint(-8, 8)))
                nd["r_frac"] = 0.60 + 0.12 * math.sin(nd["phase"] + self._tick * 0.008)

        # Particles — capped pool
        self._particle_timer += 1
        if self._particle_timer >= (3 if speak else 8):
            self._particle_timer = 0
            if len(self._particles) < _MAX_PARTICLES:
                cond = random.choice(self._conduits)
                self._particles.append({
                    "angle": cond["angle"], "r": cond["r_start"],
                    "r_end": cond["r_end"], "color": cond["color"],
                    "speed": random.uniform(0.008, 0.022),
                    "size":  random.uniform(1.8, 4.0),  "life": 1.0,
                })

        dead = []
        for p2 in self._particles:
            p2["r"] += p2["speed"]
            if p2["r"] >= p2["r_end"]:
                dead.append(p2)
            else:
                p2["life"] = 1.0 - (p2["r"] - p2["r_end"] * 0.5) / (p2["r_end"] * 0.5 + 1e-6)
        for d in dead:
            self._particles.remove(d)

        if self._tick % (12 if speak else 40) == 0:
            self._pulses.append({"r": 0.0, "life": 1.0,
                                  "color": C.PRI if not muted else C.RED})
        self._pulses = [p3 for p3 in self._pulses if p3["life"] > 0]
        for p3 in self._pulses:
            p3["r"] += 0.012; p3["life"] -= 0.025

        self._wave_phase += 0.08 if speak else 0.03
        tgt_amp = random.uniform(0.5, 1.0) if speak else random.uniform(0.05, 0.25)
        for i in range(80):
            t_v = tgt_amp * abs(math.sin(i * 0.22 + self._wave_phase))
            self._wave_data[i] = self._wave_data[i] * 0.7 + t_v * 0.3

        self.update()

    # ── PAINT ─────────────────────────────────────────────────────

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)

        W, H   = self.width(), self.height()
        cx, cy = W / 2.0, H / 2.0
        fw     = min(W, H) * 0.5

        # Background
        bg_g = QRadialGradient(QPointF(cx, cy), fw * 1.4)
        bg_g.setColorAt(0.0, qcol(C.PANEL,  255))
        bg_g.setColorAt(0.5, qcol(C.PANEL2, 255))
        bg_g.setColorAt(1.0, qcol(C.VOID,   255))
        p.fillRect(self.rect(), QBrush(bg_g))

        # Edge plasma glow (4 sides)
        self._draw_edge_glow(p, W, H)

        # Cached scanlines
        sl = _ScanlineCache.get(W, H)
        p.drawPixmap(0, 0, sl)

        self._draw_hex_grid(p, cx, cy, fw)
        self._draw_conduits(p, cx, cy, fw)
        self._draw_outer_rings_blurred(p, cx, cy, fw)
        self._draw_pulse_rings(p, cx, cy, fw)
        self._draw_arc_corona(p, cx, cy, fw)
        self._draw_bracket_ring(p, cx, cy, fw)
        self._draw_inner_hex(p, cx, cy, fw)
        self._draw_face(p, cx, cy, fw)
        self._draw_particles(p, cx, cy, fw)
        self._draw_data_nodes(p, cx, cy, fw)
        self._draw_corner_triangles(p, cx, cy, fw, W, H)
        self._draw_crosshair(p, cx, cy, fw)
        self._draw_state_label(p, cx, cy, fw, W, H)
        self._draw_wave(p, cx, cy, fw, W, H)

        # Depth vignette (topmost layer)
        self._draw_vignette(p, W, H)

    # ── EDGE GLOW ─────────────────────────────────────────────────

    def _draw_edge_glow(self, p: QPainter, W: int, H: int):
        """Plasma edge glow — makes panels feel holographic."""
        col = C.MUTED_C if self.muted else C.PRI
        a   = max(0, min(60, int(self._halo * 0.45)))
        g_w = 40
        # Top
        g = QLinearGradient(0, 0, 0, g_w)
        g.setColorAt(0, qcol(col, a)); g.setColorAt(1, qcol(col, 0))
        p.fillRect(QRectF(0, 0, W, g_w), QBrush(g))
        # Bottom
        g2 = QLinearGradient(0, H - g_w, 0, H)
        g2.setColorAt(0, qcol(col, 0)); g2.setColorAt(1, qcol(col, a))
        p.fillRect(QRectF(0, H - g_w, W, g_w), QBrush(g2))
        # Left
        g3 = QLinearGradient(0, 0, g_w, 0)
        g3.setColorAt(0, qcol(col, a)); g3.setColorAt(1, qcol(col, 0))
        p.fillRect(QRectF(0, 0, g_w, H), QBrush(g3))
        # Right
        g4 = QLinearGradient(W - g_w, 0, W, 0)
        g4.setColorAt(0, qcol(col, 0)); g4.setColorAt(1, qcol(col, a))
        p.fillRect(QRectF(W - g_w, 0, g_w, H), QBrush(g4))

    # ── VIGNETTE ──────────────────────────────────────────────────

    def _draw_vignette(self, p: QPainter, W: int, H: int):
        """Render/cache a radial vignette darkening the HUD corners."""
        if (W, H) != self._vig_size:
            self._vig_size = (W, H)
            px = QPixmap(W, H)
            px.fill(Qt.GlobalColor.transparent)
            pp = QPainter(px)
            rg = QRadialGradient(QPointF(W / 2, H / 2), max(W, H) * 0.7)
            rg.setColorAt(0.55, QColor(0, 0, 0, 0))
            rg.setColorAt(1.00, QColor(0, 0, 0, 160))
            pp.fillRect(px.rect(), QBrush(rg))
            pp.end()
            self._vignette_px = px
        if self._vignette_px:
            p.drawPixmap(0, 0, self._vignette_px)

    # ── OUTER RINGS WITH MOTION BLUR ──────────────────────────────

    def _draw_outer_rings_blurred(self, p: QPainter, cx: float, cy: float, fw: float):
        """Draw ring history as fading ghost copies (motion blur)."""
        n_hist = len(self._ring_hist)
        for hi, hist_rings in enumerate(self._ring_hist):
            fade = (hi + 1) / (n_hist + 1)   # 0 → old, 1 → newest
            self._draw_outer_rings_frame(p, cx, cy, fw, hist_rings, alpha_scale=fade * 0.55)
        # Current frame at full alpha
        self._draw_outer_rings_frame(p, cx, cy, fw, self._rings, alpha_scale=1.0)

    def _draw_outer_rings_frame(self, p: QPainter, cx: float, cy: float,
                                 fw: float, rings: list[float], alpha_scale: float = 1.0):
        ring_configs = [
            (0.85, 1.4, 80, 55, C.PRI, 40),
            (0.78, 2.0, 72, 42, C.PRI, 30),
            (0.71, 1.2, 110, 28, C.ACC, 22),
            (0.64, 1.8, 88, 35, C.PRI, 28),
        ]
        for r_frac, ww, arc_l, gap, col_h, base_a in ring_configs:
            ring_r = fw * r_frac
            base   = rings[0]
            a_val  = max(0, min(220, int(self._halo * 0.9 * base_a / 60 * alpha_scale)))
            col    = qcol(C.MUTED_C if self.muted else col_h, a_val)
            p.setPen(QPen(col, ww))
            p.setBrush(Qt.BrushStyle.NoBrush)
            rect  = QRectF(cx - ring_r, cy - ring_r, ring_r * 2, ring_r * 2)
            angle = base
            while angle < base + 360:
                p.drawArc(rect, int(angle * 16), int(arc_l * 16))
                angle += arc_l + gap

        if alpha_scale < 0.8:
            return   # skip tick marks for ghost frames

        tick_r = fw * 0.68
        for deg in range(0, 360, 3):
            rad   = math.radians(deg + rings[1] * 0.02)
            major = deg % 30 == 0
            mid_t = deg % 10 == 0
            r_out = tick_r
            r_in  = tick_r - (8 if major else (4 if mid_t else 2))
            alpha = int((200 if major else (100 if mid_t else 40)) * alpha_scale)
            col   = qcol(C.PRI if major else (C.ACC if mid_t else C.TEAL), alpha)
            p.setPen(QPen(col, 2.0 if major else (1.0 if mid_t else 0.5)))
            p.drawLine(
                QPointF(cx + r_out * math.cos(rad), cy + r_out * math.sin(rad)),
                QPointF(cx + r_in  * math.cos(rad), cy + r_in  * math.sin(rad)),
            )

    # ── REMAINING DRAW METHODS (unchanged from previous edition) ──

    def _draw_hex_grid(self, p: QPainter, cx: float, cy: float, fw: float):
        hex_scale = fw * 0.088
        for x, y, phase, _ in self._hex_grid:
            sx   = cx + x * hex_scale
            sy   = cy + y * hex_scale
            dist = math.hypot(x, y) / 5.8
            alpha = max(0, int(22 * (1.0 - dist) * (0.5 + 0.5 * math.sin(phase))))
            if alpha < 2:
                continue
            p.setPen(QPen(qcol(C.PRI, alpha), 0.5))
            p.setBrush(Qt.BrushStyle.NoBrush)
            path  = QPainterPath()
            r_hex = hex_scale * 0.48
            for k in range(6):
                hang = math.radians(k * 60 + 30)
                hx   = sx + math.cos(hang) * r_hex
                hy   = sy + math.sin(hang) * r_hex
                if k == 0: path.moveTo(hx, hy)
                else:       path.lineTo(hx, hy)
            path.closeSubpath()
            p.drawPath(path)

    def _draw_conduits(self, p: QPainter, cx: float, cy: float, fw: float):
        for cond in self._conduits:
            ang   = cond["angle"] + self._rings[0] * 0.002
            r1    = cond["r_start"] * fw
            r2    = cond["r_end"]   * fw
            alpha = int(35 + 25 * math.sin(cond["phase"] + self._tick * 0.04))
            p.setPen(QPen(qcol(cond["color"], alpha), cond["width"]))
            p.drawLine(QPointF(cx + math.cos(ang) * r1, cy + math.sin(ang) * r1),
                       QPointF(cx + math.cos(ang) * r2, cy + math.sin(ang) * r2))

    def _draw_pulse_rings(self, p: QPainter, cx: float, cy: float, fw: float):
        for pulse in self._pulses:
            r_p = pulse["r"] * fw * 1.2
            a_p = int(pulse["life"] * 140)
            p.setPen(QPen(qcol(pulse["color"], a_p), 1.5))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(QRectF(cx - r_p, cy - r_p, r_p * 2, r_p * 2))

    def _draw_arc_corona(self, p: QPainter, cx: float, cy: float, fw: float):
        base_r = fw * 0.30
        for i in range(20):
            r4  = base_r * (1.0 - i * 0.048) * self._scale
            frc = 1.0 - i / 20
            a   = max(0, int(self._halo * 0.075 * frc))
            col = qcol(C.MUTED_C if self.muted else (C.PRI if i < 10 else C.ACC), a)
            p.setPen(QPen(col, max(0.3, 2.8 - i * 0.12)))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(QRectF(cx - r4, cy - r4, r4 * 2, r4 * 2))

        grad = QRadialGradient(QPointF(cx, cy), base_r * self._scale)
        if self.muted:
            grad.setColorAt(0.0, qcol(C.RED,   int(self._halo * 0.9)))
            grad.setColorAt(0.5, qcol(C.RED_D, int(self._halo * 0.4)))
            grad.setColorAt(1.0, qcol(C.VOID, 0))
        else:
            grad.setColorAt(0.0, qcol(C.PRI,     int(self._halo * 1.1)))
            grad.setColorAt(0.3, qcol(C.PRI_DIM, int(self._halo * 0.35)))
            grad.setColorAt(0.7, qcol(C.ACC,     int(self._halo * 0.06)))
            grad.setColorAt(1.0, qcol(C.VOID, 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(grad))
        r_fill = base_r * self._scale
        p.drawEllipse(QRectF(cx - r_fill, cy - r_fill, r_fill * 2, r_fill * 2))

    def _draw_bracket_ring(self, p: QPainter, cx: float, cy: float, fw: float):
        half = fw * 0.515
        rot  = math.radians(self._bracket_rot)
        col  = qcol(C.MUTED_C if self.muted else C.PRI, 200)
        p.setPen(QPen(col, 2.0))
        for base_ang in [0, math.pi / 2, math.pi, 3 * math.pi / 2]:
            ang   = base_ang + rot
            hx    = cx + math.cos(ang) * half
            hy    = cy + math.sin(ang) * half
            tang  = ang + math.pi / 2
            arm_l = fw * 0.052
            p.drawLine(QPointF(hx + math.cos(tang) * arm_l, hy + math.sin(tang) * arm_l),
                       QPointF(hx - math.cos(tang) * arm_l, hy - math.sin(tang) * arm_l))
            p.setPen(QPen(qcol(C.ACC, 160), 1.2))
            inner = fw * 0.030
            p.drawLine(QPointF(hx, hy),
                       QPointF(cx + math.cos(ang) * (half - inner),
                               cy + math.sin(ang) * (half - inner)))
            p.setPen(QPen(col, 2.0))
            dm = fw * 0.012
            diamond = QPainterPath()
            diamond.moveTo(hx, hy - dm); diamond.lineTo(hx + dm, hy)
            diamond.lineTo(hx, hy + dm); diamond.lineTo(hx - dm, hy)
            diamond.closeSubpath()
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(qcol(C.PRI_GLOW, 220)))
            p.drawPath(diamond)
            p.setPen(QPen(col, 2.0))
        rot2  = math.radians(-self._bracket_rot * 0.6 + 45)
        half2 = fw * 0.42
        p.setPen(QPen(qcol(C.ACC, 130), 1.0))
        for base_ang2 in [0, math.pi / 2, math.pi, 3 * math.pi / 2]:
            ang2  = base_ang2 + rot2
            hx2   = cx + math.cos(ang2) * half2
            hy2   = cy + math.sin(ang2) * half2
            tang2 = ang2 + math.pi / 2
            arm2  = fw * 0.038
            p.drawLine(QPointF(hx2 + math.cos(tang2) * arm2, hy2 + math.sin(tang2) * arm2),
                       QPointF(hx2 - math.cos(tang2) * arm2, hy2 - math.sin(tang2) * arm2))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(qcol(C.ACC, 200)))
            p.drawEllipse(QPointF(hx2, hy2), 2.5, 2.5)
            p.setPen(QPen(qcol(C.ACC, 130), 1.0))

    def _draw_inner_hex(self, p: QPainter, cx: float, cy: float, fw: float):
        hex_r = fw * 0.245
        col   = qcol(C.MUTED_C if self.muted else C.PRI, int(self._halo * 2.2))
        p.setPen(QPen(col, 2.5))
        p.setBrush(Qt.BrushStyle.NoBrush)
        rot  = math.radians(self._rings[3] * 0.15)
        path = QPainterPath()
        for k in range(6):
            hang = math.radians(k * 60) + rot
            hx   = cx + math.cos(hang) * hex_r
            hy   = cy + math.sin(hang) * hex_r
            if k == 0: path.moveTo(hx, hy)
            else:       path.lineTo(hx, hy)
        path.closeSubpath()
        p.drawPath(path)
        grad2 = QRadialGradient(QPointF(cx, cy), hex_r)
        grad2.setColorAt(0.0, qcol(C.RED if self.muted else C.PRI, int(self._halo * 0.5)))
        grad2.setColorAt(1.0, qcol(C.VOID, 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(grad2))
        p.drawPath(path)

    def _draw_face(self, p: QPainter, cx: float, cy: float, fw: float):
        chrom = 2.8 * math.sin(self._chrom_t)
        if self._face_px:
            fsz = int(fw * 0.54 * self._scale)
            # Only re-scale when size changes meaningfully (saves ~5ms/frame)
            if self._face_cache is None or abs(fsz - self._face_cache_sz) > 2:
                self._face_cache = self._face_px.scaled(
                    fsz, fsz,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
                self._face_cache_sz = fsz
            scaled = self._face_cache
            p.setOpacity(0.10)
            p.drawPixmap(int(cx - fsz / 2 + chrom), int(cy - fsz / 2), scaled)
            p.setOpacity(0.07)
            p.drawPixmap(int(cx - fsz / 2 - chrom), int(cy - fsz / 2 + 1), scaled)
            p.setOpacity(1.0)
            p.drawPixmap(int(cx - fsz / 2), int(cy - fsz / 2), scaled)
        else:
            self._draw_arc_reactor(p, cx, cy, fw)

    def _draw_arc_reactor(self, p: QPainter, cx: float, cy: float, fw: float):
        """Full rotating arc reactor — film-accurate JARVIS teal/orange."""
        t     = self._arc_t
        s     = fw / 210.0
        pulse  = 0.5 + 0.5 * math.sin(t * 2)
        pulse2 = 0.5 + 0.5 * math.sin(t * 3 + 1)

        def _a(f): return max(0, min(255, int(f * 255)))
        def _ring(r, w, rr, gg, bb, af):
            rad = r * s
            p.setPen(QPen(QColor(rr, gg, bb, _a(af)), w * s))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(QRectF(cx-rad, cy-rad, rad*2, rad*2))
        def _glow(r, rr, gg, bb, bl, af):
            for bw, ba in [(bl, af*.55), (bl*.5, af*.75), (2, af)]:
                _ring(r, bw, rr, gg, bb, ba)
        def _poly(n, r, off):
            path = QPainterPath()
            for i in range(n):
                a = off + (i/n)*math.pi*2
                x = cx + math.cos(a)*r*s; y = cy + math.sin(a)*r*s
                if i == 0: path.moveTo(x, y)
                else:       path.lineTo(x, y)
            path.closeSubpath(); return path

        # Outer aura
        ar = 210*s
        ag = QRadialGradient(QPointF(cx, cy), ar)
        ag.setColorAt(0.0, QColor(0,255,232, _a(0.06+pulse*0.04)))
        ag.setColorAt(0.5, QColor(0,200,180, _a(0.03+pulse*0.02)))
        ag.setColorAt(1.0, QColor(0,0,0,0))
        p.setPen(Qt.PenStyle.NoPen); p.setBrush(QBrush(ag))
        p.drawEllipse(QRectF(cx-ar, cy-ar, ar*2, ar*2))

        _ring(195,1, 0,255,232,0.15); _ring(190,.5, 0,200,180,0.08)

        # Segment rings
        for rot_mul, num_segs, seg_frac, w_seg, rr, gg, bb, pf in [
            ( 0.30, 24, 0.60, 2.5, 0, 255, 232, 0.20+pulse*0.15),
            (-0.18, 16, 0.50, 1.5, 255,100,  0, 0.15+pulse2*0.10),
        ]:
            p.save()
            p.translate(cx, cy); p.rotate(math.degrees(t*rot_mul)); p.translate(-cx,-cy)
            sr2 = (188 if num_segs==24 else 175) * s
            rect_s = QRectF(cx-sr2, cy-sr2, sr2*2, sr2*2)
            span_s = (1/num_segs)*360*seg_frac
            for i in range(num_segs):
                p.setPen(QPen(QColor(rr,gg,bb, _a(pf)), w_seg*s))
                p.drawArc(rect_s, int((i/num_segs)*360*16), int(span_s*16))
            p.restore()

        # Outer ticks
        p.save()
        p.translate(cx,cy); p.rotate(math.degrees(t*0.1)); p.translate(-cx,-cy)
        for i in range(48):
            a = (i/48)*math.pi*2; ro = 162*s
            ri = (155 if i%4==0 else 158)*s
            p.setPen(QPen(QColor(0,255,232,_a(.5 if i%4==0 else .2)),
                          (1.5 if i%4==0 else .8)*s))
            p.drawLine(QPointF(cx+math.cos(a)*ro, cy+math.sin(a)*ro),
                       QPointF(cx+math.cos(a)*ri, cy+math.sin(a)*ri))
        p.restore()
        _ring(155,1, 0,255,232,0.12)

        # Mid hexagons
        for rm, af, rr, gg, bb, ang_off in [
            (.5, .20+pulse*.12, 0,255,232, 0),
            (-.35, .15+pulse2*.10, 255,120,0, math.pi/6),
        ]:
            p.save()
            p.translate(cx,cy); p.rotate(math.degrees(t*rm)); p.translate(-cx,-cy)
            p.setPen(QPen(QColor(rr,gg,bb,_a(af)), 1.2*s))
            p.setBrush(Qt.BrushStyle.NoBrush); p.drawPath(_poly(6,130,ang_off))
            p.restore()

        _glow(120, 0,255,232, 14, 0.25+pulse*0.15)
        _ring(120, 1.5, 0,255,232, 0.40)

        # Petal triangles
        for ba, rr, gg, bb, daf in [
            (t*0.4, 0,255,232, 0.30),
            (-t*0.3+math.pi/6, 255,100,0, 0.20),
        ]:
            for i in range(6):
                a = ba + (i/6)*math.pi*2
                a1 = a - math.pi/6*0.4; a2 = a + math.pi/6*0.4
                r2 = 105*s
                pt = QPainterPath()
                pt.moveTo(cx+math.cos(a)*r2, cy+math.sin(a)*r2)
                pt.lineTo(cx+math.cos(a1)*r2*.7, cy+math.sin(a1)*r2*.7)
                pt.lineTo(cx+math.cos(a2)*r2*.7, cy+math.sin(a2)*r2*.7)
                pt.closeSubpath()
                p.setPen(QPen(QColor(rr,gg,bb,_a(daf)), 1.0*s))
                p.setBrush(Qt.BrushStyle.NoBrush); p.drawPath(pt)

        # 6-star + spokes
        p.save()
        p.translate(cx,cy); p.rotate(math.degrees(t*0.6)); p.translate(-cx,-cy)
        p.setPen(QPen(QColor(0,255,232,_a(.25+pulse*.15)), 1.0*s))
        p.setBrush(Qt.BrushStyle.NoBrush); p.drawPath(_poly(6,90,0))
        for i in range(6):
            a = (i/6)*math.pi*2 + t*0.6
            p.setPen(QPen(QColor(0,255,232,_a(.08+pulse*.04)), .8*s))
            p.drawLine(QPointF(cx,cy), QPointF(cx+math.cos(a)*88*s, cy+math.sin(a)*88*s))
        p.restore()

        # Inner ticks
        p.save()
        p.translate(cx,cy); p.rotate(math.degrees(-t*0.25)); p.translate(-cx,-cy)
        for i in range(36):
            a = (i/36)*math.pi*2; ro = 78*s
            ri = (66 if i%6==0 else 72)*s
            p.setPen(QPen(QColor(0,255,232,_a(.5 if i%6==0 else .15)),
                          (1.5 if i%6==0 else .7)*s))
            p.drawLine(QPointF(cx+math.cos(a)*ro, cy+math.sin(a)*ro),
                       QPointF(cx+math.cos(a)*ri, cy+math.sin(a)*ri))
        p.restore()

        _ring(65,1,0,255,232,0.25); _glow(65,0,255,232,18,0.30+pulse*0.20)

        # Inner arcs
        for rm, num, frac, w2, rr, gg, bb, pf in [
            (1.2, 8,.55,3.0, 0,255,232, 0.35+pulse*0.20),
            (-.9, 6,.45,2.0, 255,100,0, 0.25+pulse2*0.15),
        ]:
            p.save()
            p.translate(cx,cy); p.rotate(math.degrees(t*rm)); p.translate(-cx,-cy)
            rad2 = (56 if num==8 else 46)*s
            rect2 = QRectF(cx-rad2, cy-rad2, rad2*2, rad2*2)
            for i in range(num):
                p.setPen(QPen(QColor(rr,gg,bb,_a(pf)), w2*s))
                p.drawArc(rect2, int((i/num)*360*16), int((1/num)*360*frac*16))
            p.restore()

        # Inner hex
        p.save()
        p.translate(cx,cy); p.rotate(math.degrees(-t*0.7)); p.translate(-cx,-cy)
        p.setPen(QPen(QColor(0,255,232,_a(.30+pulse*.20)), 1.5*s))
        p.setBrush(Qt.BrushStyle.NoBrush); p.drawPath(_poly(6,36,0))
        p.restore()

        # Core triangles
        for rm, rr, gg, bb, pf in [
            (1.5, 0,255,232, 0.50+pulse*0.30),
            (-1.2, 255,120,0, 0.40+pulse2*0.25),
        ]:
            p.save()
            p.translate(cx,cy)
            p.rotate(math.degrees(t*rm + (math.pi if rm < 0 else 0)))
            p.translate(-cx,-cy)
            p.setPen(QPen(QColor(rr,gg,bb,_a(pf)), (2.0 if rm>0 else 1.5)*s))
            p.setBrush(Qt.BrushStyle.NoBrush); p.drawPath(_poly(3,22,0))
            p.restore()

        # Core glow
        cr = 18*s
        cg = QRadialGradient(QPointF(cx,cy), cr)
        cg.setColorAt(0.0, QColor(180,255,250,_a(.90+pulse*.10)))
        cg.setColorAt(0.4, QColor(  0,255,232,_a(.70+pulse*.15)))
        cg.setColorAt(0.8, QColor(  0,200,160,_a(.30+pulse*.10)))
        cg.setColorAt(1.0, QColor(0,0,0,0))
        p.setPen(Qt.PenStyle.NoPen); p.setBrush(QBrush(cg))
        p.drawEllipse(QRectF(cx-cr, cy-cr, cr*2, cr*2))

        # Bright centre dot
        dr = 5*s
        dg = QRadialGradient(QPointF(cx,cy), dr*4)
        dg.setColorAt(0.0, QColor(220,255,252,255))
        dg.setColorAt(0.5, QColor(  0,255,232,_a(.60+pulse*.30)))
        dg.setColorAt(1.0, QColor(0,0,0,0))
        p.setPen(Qt.PenStyle.NoPen); p.setBrush(QBrush(dg))
        p.drawEllipse(QRectF(cx-dr*4, cy-dr*4, dr*8, dr*8))
        p.setBrush(QBrush(QColor(220,255,252,255)))
        p.drawEllipse(QRectF(cx-dr, cy-dr, dr*2, dr*2))

        # Sparks
        for i in range(6):
            a  = t*0.5 + (i/6)*math.pi*2
            rs = (188 + math.sin(t*3+i)*4)*s
            sx = cx + math.cos(a)*rs; sy = cy + math.sin(a)*rs
            sg = QRadialGradient(QPointF(sx,sy), 6*s)
            sg.setColorAt(0.0, QColor(0,255,232,_a(.70+pulse*.30)))
            sg.setColorAt(1.0, QColor(0,0,0,0))
            p.setPen(Qt.PenStyle.NoPen); p.setBrush(QBrush(sg))
            p.drawEllipse(QRectF(sx-6*s, sy-6*s, 12*s, 12*s))
            p.setBrush(QBrush(QColor(0,255,232,_a(.70+pulse*.30))))
            p.drawEllipse(QRectF(sx-2*s, sy-2*s, 4*s, 4*s))

    def _draw_particles(self, p: QPainter, cx: float, cy: float, fw: float):
        p.setPen(Qt.PenStyle.NoPen)
        for part in self._particles:
            r_p = part["r"] * fw
            px  = cx + math.cos(part["angle"]) * r_p
            py  = cy + math.sin(part["angle"]) * r_p
            a_p = max(0, int(part["life"] * 220))
            p.setBrush(QBrush(qcol(part["color"], a_p)))
            p.drawEllipse(QPointF(px, py), part["size"], part["size"])
            p.setBrush(QBrush(qcol(part["color"], a_p // 4)))
            p.drawEllipse(QPointF(px, py), part["size"] * 2, part["size"] * 2)

    def _draw_data_nodes(self, p: QPainter, cx: float, cy: float, fw: float):
        p.setFont(QFont("Courier New", 6, QFont.Weight.Bold))
        for nd in self._data_nodes:
            ang  = nd["angle"] + self._rings[0] * 0.005
            dist = nd["r_frac"] * fw
            nx   = cx + math.cos(ang) * dist
            ny   = cy + math.sin(ang) * dist
            col  = qcol(nd["color"], 170)

            hex_r    = 13
            hex_path = QPainterPath()
            for k in range(6):
                hang = math.radians(k * 60 + 30)
                hx2  = nx + math.cos(hang) * hex_r
                hy2  = ny + math.sin(hang) * hex_r
                if k == 0: hex_path.moveTo(hx2, hy2)
                else:       hex_path.lineTo(hx2, hy2)
            hex_path.closeSubpath()
            p.setPen(QPen(col, 0.9))
            p.setBrush(QBrush(qcol(C.PANEL, 160)))
            p.drawPath(hex_path)

            p.setPen(QPen(col, 1))
            p.setFont(QFont("Courier New", 6, QFont.Weight.Bold))
            p.drawText(QRectF(nx-18, ny-9, 36, 10), Qt.AlignmentFlag.AlignCenter, nd["label"])
            p.setFont(QFont("Courier New", 7, QFont.Weight.Bold))
            p.drawText(QRectF(nx-18, ny+1, 36, 10), Qt.AlignmentFlag.AlignCenter, f"{nd['val']:02d}")
            p.setFont(QFont("Courier New", 6, QFont.Weight.Bold))

            inner_r = fw * 0.52
            ix = cx + math.cos(ang) * inner_r
            iy = cy + math.sin(ang) * inner_r
            p.setPen(QPen(qcol(nd["color"], 40), 0.6))
            p.drawLine(QPointF(ix, iy),
                       QPointF(nx - math.cos(ang) * hex_r, ny - math.sin(ang) * hex_r))

    def _draw_corner_triangles(self, p: QPainter, cx: float, cy: float,
                                fw: float, W: int, H: int):
        col  = qcol(C.PRI, int(self._halo * 0.9))
        col2 = qcol(C.ACC, int(self._halo * 0.6))
        arm  = fw * 0.14 * 0.4
        for bx, by, sx, sy in [
            (cx - fw * 0.58, cy - fw * 0.58,  1,  1),
            (cx + fw * 0.58, cy - fw * 0.58, -1,  1),
            (cx - fw * 0.58, cy + fw * 0.58,  1, -1),
            (cx + fw * 0.58, cy + fw * 0.58, -1, -1),
        ]:
            p.setPen(QPen(col, 1.5))
            p.drawLine(QPointF(bx, by), QPointF(bx + sx * arm, by))
            p.drawLine(QPointF(bx, by), QPointF(bx, by + sy * arm))
            p.setPen(QPen(col2, 0.8))
            p.drawLine(QPointF(bx + sx*6, by + sy*6),
                       QPointF(bx + sx*arm*.6, by + sy*arm*.6))

    def _draw_crosshair(self, p: QPainter, cx: float, cy: float, fw: float):
        ch_r  = fw * 0.545
        gap_h = fw * 0.12
        ra    = int(self._halo * 0.72)
        for off, am in [(0, 1.0), (2.0, 0.2), (-2.0, 0.2)]:
            p.setPen(QPen(qcol(C.MUTED_C if self.muted else C.PRI, int(ra * am)), 1.2))
            p.drawLine(QPointF(cx-ch_r+off, cy), QPointF(cx-gap_h+off, cy))
            p.drawLine(QPointF(cx+gap_h+off, cy), QPointF(cx+ch_r+off, cy))
            p.drawLine(QPointF(cx, cy-ch_r+off), QPointF(cx, cy-gap_h+off))
            p.drawLine(QPointF(cx, cy+gap_h+off), QPointF(cx, cy+ch_r+off))
        for ang_off in [45, 135, 225, 315]:
            rad   = math.radians(ang_off)
            r_in  = fw * 0.22; r_out = fw * 0.30
            p.setPen(QPen(qcol(C.ACC, ra // 2), 0.9))
            p.drawLine(QPointF(cx+r_in*math.cos(rad),  cy+r_in*math.sin(rad)),
                       QPointF(cx+r_out*math.cos(rad), cy+r_out*math.sin(rad)))

    def _draw_state_label(self, p: QPainter, cx: float, cy: float, fw: float,
                          W: int, H: int):
        sy = cy + fw * 0.42
        if self.muted:
            txt, col_h = "⊘  SIGNAL OFFLINE",     C.MUTED_C
        elif self.speaking:
            txt, col_h = "◈  TRANSMITTING",        C.PRI_GLOW
        elif self.state == "THINKING":
            sym = "⬡" if self._blink else "⬢"
            txt, col_h = f"{sym}  PROCESSING",     C.VIOLET
        elif self.state == "PROCESSING":
            sym = "▷" if self._blink else "▶"
            txt, col_h = f"{sym}  COMPUTING",      C.ACC
        elif self.state == "LISTENING":
            sym = "◉" if self._blink else "◎"
            txt, col_h = f"{sym}  ONLINE · READY", C.GREEN
        else:
            sym = "◉" if self._blink else "○"
            txt, col_h = f"{sym}  {self.state}",   C.PRI

        p.setFont(QFont("Courier New", 10, QFont.Weight.Bold))
        for dx2, dy2 in [(-1,-1),(1,-1),(-1,1),(1,1),(0,-2),(0,2)]:
            p.setPen(QPen(qcol(col_h, 28), 1))
            p.drawText(QRectF(dx2, sy+dy2, W, 26), Qt.AlignmentFlag.AlignCenter, txt)
        p.setPen(QPen(qcol(col_h), 1))
        p.drawText(QRectF(0, sy, W, 26), Qt.AlignmentFlag.AlignCenter, txt)

    def _draw_wave(self, p: QPainter, cx: float, cy: float, fw: float, W: int, H: int):
        wy   = cy + fw * 0.49
        N, bw = 80, 4
        wx0  = (W - N * bw) / 2
        for i in range(N):
            h_val = self._wave_data[i]
            max_h = 26
            hgt   = max(1, int(h_val * max_h))
            if self.muted:
                col = qcol(C.RED_D, 110)
            else:
                if   h_val > 0.8:  col = qcol(C.PRI_ULTRA, 240)
                elif h_val > 0.55: col = qcol(C.PRI_GLOW,  210)
                elif h_val > 0.3:  col = qcol(C.PRI,       175)
                else:              col = qcol(C.PRI_DIM,    95)
            dist = abs(i - N // 2) / (N // 2)
            h_sc = max(1, int(hgt * (1.0 - dist * 0.20)))
            glow = qcol(col.name(), col.alpha() // 3)
            p.fillRect(QRectF(wx0+i*bw-1, wy+max_h-h_sc-1, bw+1, h_sc+2), glow)
            p.fillRect(QRectF(wx0+i*bw,   wy+max_h-h_sc,   bw-1, h_sc),   col)

    def _load_face(self, path: str):
        try:
            from PIL import Image, ImageDraw
            import io
            img = Image.open(path).convert("RGBA")
            sz  = min(img.size)
            img = img.resize((sz, sz), Image.LANCZOS)
            mk  = Image.new("L", (sz, sz), 0)
            ImageDraw.Draw(mk).ellipse((2, 2, sz-2, sz-2), fill=255)
            img.putalpha(mk)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            px = QPixmap(); px.loadFromData(buf.getvalue())
            self._face_px = px
        except Exception:
            self._face_px = None


# ─────────────────────────────────────────────────────────────────
#  METRIC BAR
# ─────────────────────────────────────────────────────────────────
class MetricBar(QWidget):
    def __init__(self, label: str, color: str = C.PRI, parent=None):
        super().__init__(parent)
        self._label    = label
        self._color    = color
        self._value    = 0.0
        self._text     = "--"
        self._anim_val = 0.0
        self._peak     = 0.0   # for auto-scaling bars (e.g. network)
        self._use_peak = False # enable auto-scale mode
        self.setFixedHeight(50)
        self.setMinimumWidth(80)
        self._bar_tmr = QTimer(self)
        self._bar_tmr.timeout.connect(self._tick)
        self._bar_tmr.start(30)

    def enable_autoscale(self):
        """Switch to peak-relative auto-scaling (for network bar)."""
        self._use_peak = True

    def _tick(self):
        self._anim_val += (self._value - self._anim_val) * 0.16
        self.update()

    def set_value(self, pct: float, text: str):
        self._value = max(0.0, min(100.0, pct))
        self._text  = text

    def set_value_raw(self, raw: float, text: str, peak_decay: float = 0.98):
        """
        Auto-scale mode: raw is the actual value (e.g. MB/s).
        Bar fills relative to rolling peak; peak decays slowly.
        """
        if raw > self._peak:
            self._peak = raw
        else:
            self._peak = max(raw, self._peak * peak_decay)
        peak = max(self._peak, 0.001)
        self._value = min(100.0, raw / peak * 100.0)
        self._text  = text

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()
        v    = self._anim_val

        cut = 5
        path = QPainterPath()
        path.moveTo(cut,1); path.lineTo(W-1,1)
        path.lineTo(W-1,H-cut); path.lineTo(W-cut,H-1)
        path.lineTo(1,H-1); path.lineTo(1,cut)
        path.closeSubpath()

        bg = QLinearGradient(0,0,W,0)
        bg.setColorAt(0, qcol(C.PANEL2)); bg.setColorAt(1, qcol(C.VOID))
        p.fillPath(path, QBrush(bg))

        if v > 88:
            bar_col  = qcol(C.RED);   glow_col = qcol(C.RED,   60)
        elif v > 68:
            bar_col  = qcol(C.AMBER); glow_col = qcol(C.AMBER, 50)
        else:
            bar_col  = qcol(self._color); glow_col = qcol(self._color, 40)

        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(qcol(self._color, 90)))
        p.drawRect(QRectF(2, 4, 2, H-8))

        p.setFont(QFont("Courier New", 7, QFont.Weight.Bold))
        p.setPen(QPen(qcol(C.TEXT_DIM), 1))
        p.drawText(QRectF(9,3,W-70,16),
                   Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, self._label)

        p.setFont(QFont("Courier New", 11, QFont.Weight.Bold))
        p.setPen(QPen(bar_col if self._text != "--" else qcol(C.TEXT_DIM), 1))
        p.drawText(QRectF(0,3,W-7,16),
                   Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, self._text)

        n_segs = 30
        bar_h = 5; bar_y = H-8; bar_x = 7; bar_w = W-14
        seg_w = (bar_w - (n_segs-1)) / n_segs
        fill  = int(v / 100 * n_segs)
        for s in range(n_segs):
            sx = bar_x + s * (seg_w + 1)
            if s < fill:
                bright = 0.5 + 0.5 * (s / max(1, fill))
                bc2 = QColor(bar_col); bc2.setAlphaF(bright)
                gc2 = QColor(bar_col); gc2.setAlpha(int(50 * bright))
                p.setBrush(QBrush(gc2)); p.setPen(Qt.PenStyle.NoPen)
                p.drawRect(QRectF(sx-1, bar_y-1, seg_w+2, bar_h+2))
                p.setBrush(QBrush(bc2)); p.drawRect(QRectF(sx, bar_y, seg_w, bar_h))
            else:
                p.setBrush(QBrush(qcol(C.BAR_BG)))
                p.setPen(QPen(qcol(C.BORDER, 50), 0.3))
                p.drawRect(QRectF(sx, bar_y, seg_w, bar_h))

        p.strokePath(path, QPen(qcol(self._color if v < 88 else C.RED, 60), 0.6))
        p.setPen(QPen(qcol(self._color if v < 88 else C.RED, 100), 0.8))
        p.drawLine(QPointF(cut,1), QPointF(1,cut))
        p.drawLine(QPointF(W-cut,H-1), QPointF(W-1,H-cut))


# ─────────────────────────────────────────────────────────────────
#  THREAT METER — real-time composite threat bar
# ─────────────────────────────────────────────────────────────────
class ThreatMeter(QWidget):
    """
    Live threat level bar driven by _SysMetrics.
    Scores: CPU · RAM · Network · Disk · Connections · Suspicious Processes
    Updates every 1.5 s from the background thread; animates at 28 ms.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self._level    = "nominal"
        self._value    = 0.0      # target 0–100
        self._anim_val = 0.0      # smoothly animated display value
        self._phase    = 0.0
        self._snap: dict = {}     # latest metrics snapshot

        self.setFixedHeight(72)   # taller to fit sub-metric row
        t = QTimer(self)
        t.timeout.connect(self._tick)
        t.start(28)

    # called by MainWindow's live-update timer
    def refresh_from_metrics(self):
        snap = _metrics.snapshot()
        self._snap  = snap
        self._level = snap.get("threat_lvl", "nominal")
        self._value = snap.get("threat_pct", 0.0)

    def set_alert(self, level: str, pct: float | None = None):
        """Manual override — keeps backward-compat with existing set_alert() API."""
        self._level = level
        if pct is not None:
            self._value = max(0.0, min(100.0, pct))
        # if pct is None we let live data drive _value next tick

    def _tick(self):
        self._anim_val += (self._value - self._anim_val) * 0.10
        self._phase    += 0.07
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()
        v    = self._anim_val

        col = {
            "nominal":  C.ALERT_NOM,
            "caution":  C.ALERT_CAU,
            "critical": C.ALERT_CRI,
        }.get(self._level, C.ALERT_NOM)

        # ── Background card ───────────────────────────────────────
        cut = 5
        path = QPainterPath()
        path.moveTo(cut,1); path.lineTo(W-1,1)
        path.lineTo(W-1,H-cut); path.lineTo(W-cut,H-1)
        path.lineTo(1,H-1); path.lineTo(1,cut)
        path.closeSubpath()
        bg = QLinearGradient(0, 0, W, 0)
        bg.setColorAt(0, qcol(C.PANEL3))
        bg.setColorAt(1, qcol(C.VOID))
        p.fillPath(path, QBrush(bg))

        # ── Pulse on critical ─────────────────────────────────────
        pulse_a = int(80 + 60 * math.sin(self._phase)) if self._level == "critical" else 80

        # ── Header row: THREAT LEVEL label + level badge ──────────
        p.setFont(QFont("Courier New", 7, QFont.Weight.Bold))
        p.setPen(QPen(qcol(col, 160), 1))
        p.drawText(QRectF(9, 3, W - 80, 14),
                   Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                   "THREAT LEVEL")
        lbl_map = {"nominal": "NOMINAL", "caution": "CAUTION", "critical": "⚠ CRITICAL"}
        p.setPen(QPen(qcol(col, pulse_a), 1))
        p.setFont(QFont("Courier New", 8, QFont.Weight.Bold))
        p.drawText(QRectF(0, 3, W - 8, 14),
                   Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                   lbl_map.get(self._level, ""))

        # ── Sub-metric row (CPU · RAM · NET · DISK · CONNS · SUS) ─
        snap = self._snap
        cpu   = snap.get("cpu",        0.0)
        mem   = snap.get("mem",        0.0)
        net   = snap.get("net",        0.0)
        disk  = snap.get("disk",       0.0)
        conns = snap.get("open_conns", 0)
        sus   = snap.get("sus_count",  0)

        def _mini_col(val: float, warn=60, crit=80) -> str:
            if val >= crit: return C.ALERT_CRI
            if val >= warn: return C.ALERT_CAU
            return C.TEXT_DIM

        metrics_row = [
            (f"CPU {cpu:.0f}%",    _mini_col(cpu)),
            (f"RAM {mem:.0f}%",    _mini_col(mem)),
            (f"NET {net:.1f}M",    _mini_col(min(100, net * 10), 40, 70)),
            (f"DSK {disk:.0f}%",   _mini_col(disk, 80, 95)),
            (f"CON {conns}",       _mini_col(min(100, conns * 2), 40, 80)),
            (f"SUS {sus}",         C.ALERT_CRI if sus > 0 else C.TEXT_DIM),
        ]
        p.setFont(QFont("Courier New", 6))
        col_w = (W - 14) / len(metrics_row)
        for i, (lbl, mc) in enumerate(metrics_row):
            rx = 7 + i * col_w
            p.setPen(QPen(qcol(mc, 190), 1))
            p.drawText(QRectF(rx, 17, col_w - 2, 11),
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, lbl)

        # ── Main segmented bar ────────────────────────────────────
        bx, by, bw_t, bh = 7, H - 14, W - 14, 6
        n_segs = 25
        seg_w  = (bw_t - (n_segs - 1)) / n_segs
        fill   = int(v / 100 * n_segs)
        for s in range(n_segs):
            sx = bx + s * (seg_w + 1)
            if s < fill:
                bright = 0.4 + 0.6 * (s / max(1, fill))
                bc2 = QColor(qcol(col)); bc2.setAlphaF(bright)
                gc2 = QColor(qcol(col)); gc2.setAlpha(int(40 * bright))
                p.setBrush(QBrush(gc2)); p.setPen(Qt.PenStyle.NoPen)
                p.drawRect(QRectF(sx - 1, by - 1, seg_w + 2, bh + 2))
                p.setBrush(QBrush(bc2))
                p.drawRect(QRectF(sx, by, seg_w, bh))
            else:
                p.setBrush(QBrush(qcol(C.BAR_BG)))
                p.setPen(QPen(qcol(C.BORDER, 40), 0.3))
                p.drawRect(QRectF(sx, by, seg_w, bh))

        # ── Percentage label ──────────────────────────────────────
        p.setFont(QFont("Courier New", 8, QFont.Weight.Bold))
        p.setPen(QPen(qcol(col, pulse_a), 1))
        p.drawText(QRectF(0, by - 13, W - 7, 12),
                   Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                   f"{v:.0f}%")

        # ── Border & corner cuts ──────────────────────────────────
        p.strokePath(path, QPen(qcol(col, 60), 0.7))
        p.setPen(QPen(qcol(col, 120), 1.0))
        p.drawLine(QPointF(cut, 1), QPointF(1, cut))
        p.drawLine(QPointF(W - cut, H - 1), QPointF(W - 1, H - cut))


# ─────────────────────────────────────────────────────────────────
#  NEW: MISSION TIMER
# ─────────────────────────────────────────────────────────────────
class MissionTimer(QWidget):
    """Elapsed time widget with lap/split capability."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._start   = time.time()
        self._laps:  list[float] = []
        self._lap_t: float | None = None
        self.setFixedHeight(48)
        t = QTimer(self); t.timeout.connect(self.update); t.start(500)

    def lap(self):
        """Record a lap split."""
        now = time.time()
        elapsed = now - self._start
        self._laps.append(elapsed)
        self._lap_t = elapsed

    def reset(self):
        self._start = time.time()
        self._laps.clear()
        self._lap_t = None

    def _fmt(self, secs: float) -> str:
        h = int(secs // 3600)
        m = int((secs % 3600) // 60)
        s = int(secs % 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H   = self.width(), self.height()
        elapsed = time.time() - self._start

        cut = 5
        path = QPainterPath()
        path.moveTo(cut,1); path.lineTo(W-1,1)
        path.lineTo(W-1,H-cut); path.lineTo(W-cut,H-1)
        path.lineTo(1,H-1); path.lineTo(1,cut)
        path.closeSubpath()
        bg = QLinearGradient(0,0,W,0)
        bg.setColorAt(0, qcol(C.PANEL2)); bg.setColorAt(1, qcol(C.VOID))
        p.fillPath(path, QBrush(bg))

        # Accent stripe
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(qcol(C.ACC, 90)))
        p.drawRect(QRectF(2,4,2,H-8))

        # Label
        p.setFont(QFont("Courier New", 7, QFont.Weight.Bold))
        p.setPen(QPen(qcol(C.TEXT_DIM), 1))
        p.drawText(QRectF(9,3,100,14),
                   Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, "MISSION TIMER")

        # Main time
        p.setFont(QFont("Courier New", 13, QFont.Weight.Bold))
        p.setPen(QPen(qcol(C.ACC), 1))
        p.drawText(QRectF(0,2,W-8,H//2+2),
                   Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                   self._fmt(elapsed))

        # Last lap
        if self._lap_t is not None:
            p.setFont(QFont("Courier New", 7))
            p.setPen(QPen(qcol(C.TEXT_MED), 1))
            p.drawText(QRectF(9, H//2, W-16, H//2-2),
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                       f"LAP #{len(self._laps)}  {self._fmt(self._lap_t)}")

        p.strokePath(path, QPen(qcol(C.ACC, 60), 0.7))
        p.setPen(QPen(qcol(C.ACC, 100), 0.8))
        p.drawLine(QPointF(cut,1), QPointF(1,cut))
        p.drawLine(QPointF(W-cut,H-1), QPointF(W-1,H-cut))


# ─────────────────────────────────────────────────────────────────
#  NEW: CONVERSATION PANEL — threaded chat bubbles
# ─────────────────────────────────────────────────────────────────
class ConversationPanel(QScrollArea):
    """
    Replaces the flat LogWidget with proper chat bubbles.
    Supports:  add_user(txt), add_jarvis(txt), add_sys(txt), add_err(txt), clear()
    Thread-safe via signals.
    """
    _add_sig = pyqtSignal(str, str)   # (role, text)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setStyleSheet(f"""
            QScrollArea {{
                background: {C.PANEL}; border: 1px solid {C.BORDER_A};
                border-left: 2px solid {C.PRI_DIM};
            }}
            QScrollBar:vertical {{
                background: {C.VOID}; width: 3px; border: none;
            }}
            QScrollBar::handle:vertical {{
                background: {C.PRI_DIM}; border-radius: 1px; min-height: 16px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
        """)
        self._container = QWidget()
        self._container.setStyleSheet(f"background: {C.PANEL};")
        self._layout = QVBoxLayout(self._container)
        self._layout.setContentsMargins(6, 6, 6, 6)
        self._layout.setSpacing(5)
        self._layout.addStretch()
        self.setWidget(self._container)

        self._add_sig.connect(self._do_add)

    # ── Public thread-safe API ───────────────────────────────────

    def add_user(self, txt: str):
        self._add_sig.emit("user", txt)

    def add_jarvis(self, txt: str):
        self._add_sig.emit("jarvis", txt)

    def add_sys(self, txt: str):
        self._add_sig.emit("sys", txt)

    def add_err(self, txt: str):
        self._add_sig.emit("err", txt)

    def add_file(self, txt: str):
        self._add_sig.emit("file", txt)

    # Legacy compatibility — auto-route by prefix
    def append_log(self, text: str):
        tl = text.lower()
        if   tl.startswith("you:"):    self.add_user(text[4:].strip())
        elif tl.startswith("jarvis:"): self.add_jarvis(text[7:].strip())
        elif tl.startswith("file:"):   self.add_file(text[5:].strip())
        elif "err" in tl[:8]:          self.add_err(text)
        else:                          self.add_sys(text)

    def clear(self):
        self._add_sig.emit("__clear__", "")

    # ── Internal ─────────────────────────────────────────────────

    def _do_add(self, role: str, text: str):
        if role == "__clear__":
            # Remove all bubble widgets
            while self._layout.count() > 1:
                item = self._layout.takeAt(0)
                if item and item.widget():
                    item.widget().deleteLater()
            return

        bubble = self._make_bubble(role, text)
        # Insert before the stretch
        self._layout.insertWidget(self._layout.count() - 1, bubble)
        QTimer.singleShot(30, self._scroll_bottom)

    def _scroll_bottom(self):
        sb = self.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _make_bubble(self, role: str, text: str) -> QWidget:
        cfg = {
            "user":   (C.WHITE,     C.PRI_GHO,  C.PRI_DIM,  "YOU",    Qt.AlignmentFlag.AlignRight),
            "jarvis": (C.PRI_GLOW,  C.PANEL3,   C.PRI_DIM,  "JARVIS", Qt.AlignmentFlag.AlignLeft),
            "sys":    (C.AMBER2,    C.PANEL2,   C.BORDER_B, "SYS",    Qt.AlignmentFlag.AlignLeft),
            "err":    (C.RED,       C.RED_G,    C.RED_D,    "ERR",    Qt.AlignmentFlag.AlignLeft),
            "file":   (C.GREEN,     C.GREEN_G,  C.GREEN_D,  "FILE",   Qt.AlignmentFlag.AlignLeft),
        }.get(role, (C.TEXT, C.PANEL2, C.BORDER_A, role.upper(), Qt.AlignmentFlag.AlignLeft))

        fg, bg, border, tag, align = cfg

        outer = QWidget()
        outer.setStyleSheet("background: transparent;")
        row = QHBoxLayout(outer)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)

        w = QWidget()
        w.setStyleSheet(f"""
            background: {bg};
            border: 1px solid {border};
            border-radius: 0px;
            border-left: 2px solid {fg};
        """)
        inner = QVBoxLayout(w)
        inner.setContentsMargins(8, 4, 8, 4)
        inner.setSpacing(1)

        # Tag label
        tag_lbl = QLabel(tag)
        tag_lbl.setFont(QFont("Courier New", 7, QFont.Weight.Bold))
        tag_lbl.setStyleSheet(f"color: {fg}; background: transparent; border: none;")
        inner.addWidget(tag_lbl)

        # Text label (word-wrapped)
        txt_lbl = QLabel(text)
        txt_lbl.setFont(QFont("Courier New", 9))
        txt_lbl.setStyleSheet(f"color: {fg}; background: transparent; border: none;")
        txt_lbl.setWordWrap(True)
        inner.addWidget(txt_lbl)

        if align == Qt.AlignmentFlag.AlignRight:
            row.addStretch()
            row.addWidget(w)
            w.setMaximumWidth(int(self.width() * 0.88))
        else:
            row.addWidget(w)
            w.setMaximumWidth(int(self.width() * 0.88))
            row.addStretch()

        return outer


# ─────────────────────────────────────────────────────────────────
#  FLASH OVERLAY — full-screen ephemeral message
# ─────────────────────────────────────────────────────────────────
class FlashOverlay(QWidget):
    """Shows a large centred message that fades out over `ms` milliseconds."""
    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._text   = ""
        self._alpha  = 0
        self._col    = C.PRI_GLOW
        self._tmr    = QTimer(self)
        self._tmr.timeout.connect(self._fade)
        self.hide()

    def flash(self, text: str, ms: int = 1800, color: str = C.PRI_GLOW):
        self._text  = text
        self._col   = color
        self._alpha = 240
        self._step  = max(4, int(240 / (ms / 28)))
        self.raise_()
        self.resize(self.parent().size())   # type: ignore[union-attr]
        self.show()
        self._tmr.start(28)
        self.update()

    def _fade(self):
        self._alpha = max(0, self._alpha - self._step)
        self.update()
        if self._alpha == 0:
            self._tmr.stop()
            self.hide()

    def paintEvent(self, _):
        if self._alpha == 0:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()
        # Dim overlay
        p.fillRect(self.rect(), QColor(0, 0, 0, min(120, self._alpha // 2)))
        # Glow halo behind text
        cx, cy = W/2, H/2
        rg = QRadialGradient(QPointF(cx, cy), 260)
        rg.setColorAt(0.0, qcol(self._col, self._alpha // 3))
        rg.setColorAt(1.0, QColor(0, 0, 0, 0))
        p.fillRect(self.rect(), QBrush(rg))
        # Text
        p.setFont(QFont("Courier New", 22, QFont.Weight.Bold))
        p.setPen(QPen(qcol(self._col, self._alpha), 1))
        p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self._text)


# ─────────────────────────────────────────────────────────────────
#  NODE INDICATOR
# ─────────────────────────────────────────────────────────────────
class NodeIndicator(QWidget):
    def __init__(self, color: str = C.GREEN, parent=None):
        super().__init__(parent)
        self.setFixedSize(14, 14)
        self._color = color
        self._phase = random.uniform(0, math.pi * 2)
        t = QTimer(self); t.timeout.connect(self._step); t.start(35)

    def _step(self):
        self._phase += 0.09
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        cx, cy = self.width()/2, self.height()/2
        pulse  = 0.5 + 0.5 * math.sin(self._phase)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(qcol(self._color, int(40 * pulse))))
        p.drawEllipse(QPointF(cx, cy), 6.5, 6.5)
        p.setBrush(QBrush(qcol(self._color, 230)))
        p.drawEllipse(QPointF(cx, cy), 3.0, 3.0)
        p.setBrush(QBrush(qcol(C.WHITE, 140)))
        p.drawEllipse(QPointF(cx-0.8, cy-0.8), 1.0, 1.0)


# ─────────────────────────────────────────────────────────────────
#  FILE DROP ZONE
# ─────────────────────────────────────────────────────────────────
_FILE_ICONS = {
    "image":   ("🖼", C.PRI),     "video":  ("🎬", C.AMBER),
    "audio":   ("🎵", C.VIOLET),  "pdf":    ("📄", C.RED),
    "word":    ("📝", "#4488ff"), "excel":  ("📊", C.GREEN),
    "code":    ("💻", C.AMBER2),  "archive":("📦", "#ff8844"),
    "pptx":   ("📊", "#ff6622"), "text":   ("📃", "#aaaaaa"),
    "data":   ("🔧", C.TEXT),    "unknown":("📎", "#888888"),
}
_EXT_TO_CAT = {
    **dict.fromkeys(["jpg","jpeg","png","gif","webp","bmp","tiff","svg","ico"], "image"),
    **dict.fromkeys(["mp4","avi","mov","mkv","wmv","flv","webm","m4v"],         "video"),
    **dict.fromkeys(["mp3","wav","ogg","m4a","aac","flac","wma","opus"],        "audio"),
    **dict.fromkeys(["pdf"],                                                      "pdf"),
    **dict.fromkeys(["doc","docx"],                                               "word"),
    **dict.fromkeys(["xls","xlsx","ods"],                                         "excel"),
    **dict.fromkeys(["ppt","pptx"],                                               "pptx"),
    **dict.fromkeys(["py","js","ts","jsx","tsx","html","css","java","c","cpp",
                     "cs","go","rs","rb","php","swift","kt","sh","sql","lua"],   "code"),
    **dict.fromkeys(["zip","rar","tar","gz","7z","bz2","xz"],                   "archive"),
    **dict.fromkeys(["txt","md","rst","log"],                                     "text"),
    **dict.fromkeys(["csv","tsv","json","xml"],                                   "data"),
}

def _file_category(path: Path) -> str:
    return _EXT_TO_CAT.get(path.suffix.lower().lstrip("."), "unknown")

def _fmt_size(size: int) -> str:
    for unit, div in [("GB", 1024**3), ("MB", 1024**2), ("KB", 1024)]:
        if size >= div: return f"{size/div:.1f} {unit}"
    return f"{size} B"


class FileDropZone(QWidget):
    file_selected = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(90)
        self._current_file: str | None = None
        self._hovering    = False
        self._drag_over   = False
        self._dash_offset = 0.0
        self._pulse       = 0.0
        t = QTimer(self); t.timeout.connect(self._animate); t.start(28)
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0)
        self._canvas = _DropCanvas(self); lay.addWidget(self._canvas)

    def _animate(self):
        self._dash_offset = (self._dash_offset + 0.8) % 28
        self._pulse = (self._pulse + 0.055) % (math.pi * 2)
        self._canvas.update()

    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().hasUrls():
            e.acceptProposedAction(); self._drag_over = True; self._canvas.update()

    def dragLeaveEvent(self, e):
        self._drag_over = False; self._canvas.update()

    def dropEvent(self, e: QDropEvent):
        self._drag_over = False
        urls = e.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if Path(path).is_file(): self._set_file(path)
        self._canvas.update()

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton: self._browse()

    def enterEvent(self, e): self._hovering = True;  self._canvas.update()
    def leaveEvent(self, e): self._hovering = False; self._canvas.update()

    def current_file(self) -> str | None: return self._current_file

    def clear_file(self):
        self._current_file = None; self._canvas.update()

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Data Injection — Select File", str(Path.home()),
            "All Formats (*.*);;"
            "Images (*.jpg *.jpeg *.png *.gif *.webp *.bmp *.svg);;"
            "Documents (*.pdf *.docx *.txt *.md *.pptx);;"
            "Data (*.csv *.xlsx *.json *.xml);;"
            "Code (*.py *.js *.ts *.html *.css *.java *.cpp *.go);;"
            "Audio (*.mp3 *.wav *.ogg *.m4a *.aac *.flac);;"
            "Video (*.mp4 *.avi *.mov *.mkv *.wmv *.webm);;"
            "Archives (*.zip *.rar *.tar *.gz *.7z)",
        )
        if path: self._set_file(path)

    def _set_file(self, path: str):
        self._current_file = path; self._canvas.update()
        self.file_selected.emit(path)


class _DropCanvas(QWidget):
    def __init__(self, zone: FileDropZone):
        super().__init__(zone); self._z = zone

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        z = self._z; W, H = self.width(), self.height()
        pad, cut = 4, 8

        path = QPainterPath()
        path.moveTo(pad+cut, pad); path.lineTo(W-pad, pad)
        path.lineTo(W-pad, H-pad-cut); path.lineTo(W-pad-cut, H-pad)
        path.lineTo(pad, H-pad); path.lineTo(pad, pad+cut)
        path.closeSubpath()

        if z._drag_over:
            grad = QLinearGradient(0,0,0,H)
            grad.setColorAt(0, qcol(C.PRI_DEEP)); grad.setColorAt(1, qcol(C.PRI_GHO))
        elif z._hovering:
            grad = QLinearGradient(0,0,0,H)
            grad.setColorAt(0, qcol(C.PANEL3)); grad.setColorAt(1, qcol(C.PANEL))
        else:
            grad = QLinearGradient(0,0,0,H)
            grad.setColorAt(0, qcol(C.PANEL)); grad.setColorAt(1, qcol(C.VOID))
        p.setBrush(QBrush(grad)); p.setPen(Qt.PenStyle.NoPen); p.drawPath(path)

        if z._current_file:
            pen = QPen(qcol(C.GREEN, 200), 1.5)
        elif z._drag_over:
            pen = QPen(qcol(C.PRI_GLOW, int(200+55*math.sin(z._pulse))), 2.0)
        elif z._hovering:
            pen = QPen(qcol(C.PRI, int(150+80*math.sin(z._pulse))), 1.5, Qt.PenStyle.DashLine)
            pen.setDashOffset(z._dash_offset)
        else:
            pen = QPen(qcol(C.BORDER_A, 100), 1.0, Qt.PenStyle.DashLine)
            pen.setDashOffset(z._dash_offset)
        p.setPen(pen); p.setBrush(Qt.BrushStyle.NoBrush); p.drawPath(path)

        bc2 = qcol(C.PRI if not z._current_file else C.GREEN, 180)
        p.setPen(QPen(bc2, 1.5))
        p.drawLine(QPointF(pad+cut, pad), QPointF(pad, pad+cut))
        p.drawLine(QPointF(W-pad-cut, H-pad), QPointF(W-pad, H-pad-cut))

        if z._current_file:   self._paint_file(p, W, H)
        elif z._drag_over:    self._paint_drag_over(p, W, H)
        else:                 self._paint_idle(p, W, H, z._hovering)

    def _paint_idle(self, p, W, H, hover):
        cx, cy = W/2, H/2
        col = qcol(C.PRI if hover else C.PRI_DIM)
        p.setPen(QPen(col, 1.8)); p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawLine(QPointF(cx, cy-18), QPointF(cx, cy+4))
        p.drawLine(QPointF(cx-9, cy-10), QPointF(cx, cy-18))
        p.drawLine(QPointF(cx+9, cy-10), QPointF(cx, cy-18))
        p.drawLine(QPointF(cx-14, cy+4), QPointF(cx+14, cy+4))
        p.setPen(QPen(qcol(C.PRI, 60 if not hover else 100), 0.8))
        p.drawEllipse(QPointF(cx, cy-7), 13+2*math.sin(self._z._pulse*2),
                      13+2*math.sin(self._z._pulse*2))
        p.setFont(QFont("Courier New", 7, QFont.Weight.Bold))
        p.setPen(QPen(qcol(C.TEXT_BRIGHT if hover else C.TEXT_DIM), 1))
        p.drawText(QRectF(0, cy+10, W, 16), Qt.AlignmentFlag.AlignCenter, "INJECT DATA  ·  CLICK TO BROWSE")
        p.setFont(QFont("Courier New", 6))
        p.setPen(QPen(qcol(C.BORDER_B, 150), 1))
        p.drawText(QRectF(0, cy+26, W, 12), Qt.AlignmentFlag.AlignCenter,
                   "IMG  ·  VIDEO  ·  AUDIO  ·  PDF  ·  CODE  ·  DATA")

    def _paint_drag_over(self, p, W, H):
        cx, cy = W/2, H/2
        p.setFont(QFont("Courier New", 18))
        p.setPen(QPen(qcol(C.PRI_GLOW), 1))
        p.drawText(QRectF(0, cy-28, W, 34), Qt.AlignmentFlag.AlignCenter, "⬇")
        p.setFont(QFont("Courier New", 8, QFont.Weight.Bold))
        p.setPen(QPen(qcol(C.PRI_GLOW), 1))
        p.drawText(QRectF(0, cy+10, W, 16), Qt.AlignmentFlag.AlignCenter, "RELEASE TO INJECT")

    def _paint_file(self, p, W, H):
        path = Path(self._z._current_file)
        cat  = _file_category(path)
        icon, ic = _FILE_ICONS.get(cat, _FILE_ICONS["unknown"])
        size_str  = _fmt_size(path.stat().st_size)
        ext_str   = path.suffix.upper().lstrip(".") or "FILE"
        bx, bw2   = 10, 55
        p.setFont(QFont("Segoe UI Emoji", 20) if _OS == "Windows" else QFont("Arial", 20))
        p.setPen(QPen(qcol(ic), 1))
        p.drawText(QRectF(bx, 0, bw2, H), Qt.AlignmentFlag.AlignCenter, icon)
        tx = bx + bw2 + 8; tw = W - tx - 40
        p.setFont(QFont("Courier New", 8, QFont.Weight.Bold))
        p.setPen(QPen(qcol(C.WHITE), 1))
        name = path.name if len(path.name) <= 38 else path.name[:35]+"..."
        p.drawText(QRectF(tx, H*.15, tw, 16), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, name)
        p.setFont(QFont("Courier New", 7))
        p.setPen(QPen(qcol(C.TEXT_MED), 1))
        p.drawText(QRectF(tx, H*.15+18, tw, 14), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                   f"{ext_str}  ·  {size_str}")
        par = str(path.parent); par = "…"+par[-48:] if len(par) > 50 else par
        p.setFont(QFont("Courier New", 6)); p.setPen(QPen(qcol(C.BORDER_B), 1))
        p.drawText(QRectF(tx, H*.15+32, tw, 12), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, par)
        p.setFont(QFont("Courier New", 10, QFont.Weight.Bold))
        p.setPen(QPen(qcol(C.GREEN, 200), 1))
        p.drawText(QRectF(W-36, 0, 28, H), Qt.AlignmentFlag.AlignCenter, "✓")


# ─────────────────────────────────────────────────────────────────
#  SETUP OVERLAY
# ─────────────────────────────────────────────────────────────────
class SetupOverlay(QWidget):
    done = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(f"""
            SetupOverlay {{
                background: rgba(0,0,0,252);
                border: 1px solid {C.PRI_DIM};
            }}
        """)
        detected = {"darwin": "mac", "windows": "windows"}.get(_OS.lower(), "linux")
        self._sel_os = detected

        lay = QVBoxLayout(self); lay.setContentsMargins(40,30,40,30); lay.setSpacing(10)

        def _lbl(txt, sz=9, bold=False, color=C.PRI, align=Qt.AlignmentFlag.AlignCenter):
            w = QLabel(txt); w.setAlignment(align)
            w.setFont(QFont("Courier New", sz, QFont.Weight.Bold if bold else QFont.Weight.Normal))
            w.setStyleSheet(f"color: {color}; background: transparent;"); return w

        hdr_row = QHBoxLayout(); hdr_row.setSpacing(10); hdr_row.addStretch()
        hdr_row.addWidget(NodeIndicator(C.PRI_GLOW))
        hdr_lbl = QLabel("IRON PROTOCOL · INIT SEQUENCE")
        hdr_lbl.setFont(QFont("Courier New", 13, QFont.Weight.Bold))
        hdr_lbl.setStyleSheet(f"color:{C.PRI_GLOW}; background:transparent; padding:6px 0; letter-spacing:4px;")
        hdr_row.addWidget(hdr_lbl); hdr_row.addWidget(NodeIndicator(C.PRI_GLOW))
        hdr_row.addStretch(); lay.addLayout(hdr_row)

        lay.addWidget(_lbl("Configure J.A.R.V.I.S before activation.", 8, color=C.TEXT_DIM))
        lay.addSpacing(4)

        def _sep():
            s = QFrame(); s.setFrameShape(QFrame.Shape.HLine)
            s.setStyleSheet(f"color:{C.BORDER_B};"); return s

        lay.addWidget(_sep()); lay.addSpacing(4)
        lay.addWidget(_lbl("GEMINI API KEY", 8, True, C.TEXT_MED, Qt.AlignmentFlag.AlignLeft))

        self._key_input = QLineEdit()
        self._key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._key_input.setPlaceholderText("AIza…")
        self._key_input.setFont(QFont("Courier New", 10))
        self._key_input.setFixedHeight(40)
        self._key_input.setStyleSheet(f"""
            QLineEdit {{
                background:{C.PANEL2}; color:{C.TEXT};
                border:1px solid {C.BORDER_A}; border-radius:0px; padding:4px 14px;
            }}
            QLineEdit:focus {{ border:1px solid {C.PRI}; background:{C.PRI_GHO}; }}
        """)
        lay.addWidget(self._key_input)
        lay.addSpacing(10); lay.addWidget(_sep()); lay.addSpacing(4)

        lay.addWidget(_lbl("OPERATING SYSTEM", 8, True, C.TEXT_MED, Qt.AlignmentFlag.AlignLeft))
        det_name = {"windows":"Windows","mac":"macOS","linux":"Linux"}[detected]
        lay.addWidget(_lbl(f"AUTO-DETECTED: {det_name}", 7, color=C.AMBER2, align=Qt.AlignmentFlag.AlignLeft))

        os_row = QHBoxLayout(); os_row.setSpacing(8)
        self._os_btns: dict[str, QPushButton] = {}
        for key, label in [("windows","⊞  WINDOWS"),("mac","  macOS"),("linux","🐧  LINUX")]:
            btn = QPushButton(label)
            btn.setFont(QFont("Courier New", 8, QFont.Weight.Bold))
            btn.setFixedHeight(36); btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _, k=key: self._sel(k))
            os_row.addWidget(btn); self._os_btns[key] = btn
        lay.addLayout(os_row); self._sel(detected); lay.addSpacing(12)

        init_btn = QPushButton("◈  ACTIVATE J.A.R.V.I.S  ◈")
        init_btn.setFont(QFont("Courier New", 11, QFont.Weight.Bold))
        init_btn.setFixedHeight(46); init_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        init_btn.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {C.PRI_GHO}, stop:0.5 {C.PRI_DEEP}, stop:1 {C.PRI_GHO});
                color:{C.PRI_GLOW}; border:1px solid {C.PRI};
                border-radius:0px; letter-spacing:5px;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {C.PRI_DIM}, stop:0.5 {C.BORDER_B}, stop:1 {C.PRI_DIM});
                color:{C.WHITE}; border:1px solid {C.PRI_GLOW};
            }}
        """)
        init_btn.clicked.connect(self._submit)
        lay.addWidget(init_btn)

    def _sel(self, key: str):
        self._sel_os = key
        pal = {
            "windows": (C.PRI,    C.PRI_GHO,  C.PRI),
            "mac":     (C.AMBER2, C.AMBER_G,   C.AMBER),
            "linux":   (C.GREEN,  C.GREEN_G,   C.GREEN_D),
        }
        for k, btn in self._os_btns.items():
            fg, bg, border = pal[k]
            if k == key:
                btn.setStyleSheet(f"QPushButton {{ background:{bg}; color:{fg}; border:1px solid {border}; border-radius:0px; font-weight:bold; }}")
            else:
                btn.setStyleSheet(f"QPushButton {{ background:{C.PANEL2}; color:{C.TEXT_DIM}; border:1px solid {C.BORDER}; border-radius:0px; }} QPushButton:hover {{ color:{C.TEXT}; border:1px solid {C.BORDER_B}; }}")

    def _submit(self):
        key = self._key_input.text().strip()
        if not key:
            self._key_input.setStyleSheet(self._key_input.styleSheet() + f" QLineEdit {{ border:1px solid {C.RED}; }}")
            return
        self.done.emit(key, self._sel_os)


# ─────────────────────────────────────────────────────────────────
#  HEADER SCAN BAR
# ─────────────────────────────────────────────────────────────────
class HeaderScanBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(2)
        self._pos = 0.0; self._pos2 = 500.0
        t = QTimer(self); t.timeout.connect(self._step); t.start(14)

    def _step(self):
        self._pos  = (self._pos  + 3.5) % (self.width() + 300)
        self._pos2 = (self._pos2 + 2.1) % (self.width() + 300)
        self.update()

    def paintEvent(self, _):
        p = QPainter(self); W = self.width()
        p.fillRect(self.rect(), qcol(C.BORDER_A, 60))
        for cx_s, span, c1, c2, alpha in [
            (self._pos-120,  200, C.PRI,  C.PRI_GLOW, 240),
            (self._pos2-120, 140, C.ACC,  C.ACC2,     130),
        ]:
            g = QLinearGradient(cx_s-span/2, 0, cx_s+span/2, 0)
            g.setColorAt(0.0, qcol(c1, 0))
            g.setColorAt(0.5, qcol(c2, alpha))
            g.setColorAt(1.0, qcol(c1, 0))
            p.fillRect(QRectF(max(0, cx_s-span/2), 0, span, 2), QBrush(g))


# ─────────────────────────────────────────────────────────────────
#  RESIZE GRIP STRIP — frameless window corner resize
# ─────────────────────────────────────────────────────────────────
class ResizeGrip(QWidget):
    """Bottom-right corner resize grip for the frameless window."""
    def __init__(self, win: QMainWindow):
        super().__init__(win)
        self._win = win
        self._drag_start_pos  = None
        self._drag_start_size = None
        self.setFixedSize(18, 18)
        self.setCursor(Qt.CursorShape.SizeFDiagCursor)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._drag_start_pos  = e.globalPosition().toPoint()
            self._drag_start_size = self._win.size()

    def mouseMoveEvent(self, e):
        if self._drag_start_pos and self._drag_start_size:
            delta = e.globalPosition().toPoint() - self._drag_start_pos
            new_w = max(_MIN_W, self._drag_start_size.width()  + delta.x())
            new_h = max(_MIN_H, self._drag_start_size.height() + delta.y())
            self._win.resize(new_w, new_h)

    def mouseReleaseEvent(self, e):
        self._drag_start_pos = self._drag_start_size = None

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()
        col = qcol(C.PRI_DIM, 180)
        p.setPen(QPen(col, 1.2))
        for i in range(3):
            off = 4 + i * 5
            p.drawLine(QPointF(off, H-2), QPointF(W-2, off))


# ─────────────────────────────────────────────────────────────────
#  WEATHER WIDGET  — live data via Open-Meteo (no API key)
# ─────────────────────────────────────────────────────────────────
def _wmo_icon(code: int) -> str:
    """Map WMO weather code → emoji icon."""
    if code == 0:                         return "☀"
    if code in (1, 2):                    return "⛅"
    if code == 3:                         return "☁"
    if code in (45, 48):                  return "🌫"
    if code in (51, 53, 55, 61, 63, 65):  return "🌧"
    if code in (71, 73, 75, 77):          return "❄"
    if code in (80, 81, 82):              return "🌧"
    if code in (95, 96, 99):              return "⛈"
    return "☁"


class WeatherWidget(QWidget):
    """
    Holographic weather panel — pulls LIVE 3-day forecast from
    Open-Meteo (free, no API key).  Falls back to placeholder until
    data arrives.  Refreshes every 30 minutes.
    """
    # Vijayawada, India — change lat/lon to your city
    _LAT  = 16.5062
    _LON  = 80.6480

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(72)
        self._phase = 0.0
        # Each day: (icon_str, temp_str, label_str)
        self._days: list[tuple[str, str, str]] = [
            ("⋯", "--°", "TODAY"),
            ("⋯", "--°", "TOMRW"),
            ("⋯", "--°", " D+2 "),
        ]
        self._fetching = False
        self._fetch_weather()

        anim_t = QTimer(self); anim_t.timeout.connect(self._tick); anim_t.start(60)
        refresh_t = QTimer(self); refresh_t.timeout.connect(self._fetch_weather)
        refresh_t.start(30 * 60 * 1000)   # refresh every 30 min

    def _tick(self):
        self._phase += 0.04
        self.update()

    def _fetch_weather(self):
        if self._fetching:
            return
        self._fetching = True
        threading.Thread(target=self._do_fetch, daemon=True).start()

    def _do_fetch(self):
        try:
            url = (
                f"https://api.open-meteo.com/v1/forecast"
                f"?latitude={self._LAT}&longitude={self._LON}"
                f"&daily=weather_code,temperature_2m_max"
                f"&forecast_days=3&timezone=auto"
            )
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            codes  = data["daily"]["weather_code"]
            maxTs  = data["daily"]["temperature_2m_max"]
            labels = ["TODAY", "TOMRW", " D+2 "]
            days = []
            for i in range(min(3, len(codes))):
                icon = _wmo_icon(codes[i])
                temp = f"{maxTs[i]:.0f}°"
                days.append((icon, temp, labels[i]))
            # pad if fewer than 3 days returned
            while len(days) < 3:
                days.append(("⋯", "--°", labels[len(days)]))
            self._days = days
        except Exception:
            pass   # keep current placeholder on failure
        finally:
            self._fetching = False
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()
        pulse = 0.5 + 0.5 * math.sin(self._phase)

        # Background
        bg = QLinearGradient(0, 0, W, 0)
        bg.setColorAt(0, qcol(C.PANEL2, 200))
        bg.setColorAt(1, qcol(C.PANEL3, 160))
        p.fillRect(self.rect(), QBrush(bg))

        # Border
        p.setPen(QPen(qcol(C.PRI_DIM, 100), 1))
        p.drawRect(QRectF(0, 0, W-1, H-1))
        p.setPen(QPen(qcol(C.PRI, int(60 + 40*pulse)), 1))
        p.drawLine(QPointF(0, 0), QPointF(W, 0))

        # WEATHER INTEL header
        p.setFont(QFont("Courier New", 6, QFont.Weight.Bold))
        p.setPen(QPen(qcol(C.PRI_DIM), 1))
        p.drawText(QRectF(8, 2, 120, 12), Qt.AlignmentFlag.AlignLeft, "WEATHER INTEL")

        # Fetching indicator (blink)
        if self._fetching:
            p.setFont(QFont("Courier New", 5))
            p.setPen(QPen(qcol(C.AMBER, int(100 + 100*pulse)), 1))
            p.drawText(QRectF(W - 60, 2, 56, 12),
                       Qt.AlignmentFlag.AlignRight, "FETCHING…")

        # Three weather cells
        cell_w = (W - 16) / 3
        for i, (ico, temp, label) in enumerate(self._days):
            cx_c = 8 + i * cell_w + cell_w / 2

            # Icon
            p.setFont(QFont("Segoe UI Emoji" if _OS == "Windows" else "Arial", 14))
            p.setPen(QPen(qcol(C.PRI, 200), 1))
            p.drawText(QRectF(cx_c - cell_w/2, 10, cell_w, 24),
                       Qt.AlignmentFlag.AlignCenter, ico)

            # Temp
            p.setFont(QFont("Courier New", 9, QFont.Weight.Bold))
            p.setPen(QPen(qcol(C.PRI_GLOW if i == 0 else C.TEXT_BRIGHT), 1))
            p.drawText(QRectF(cx_c - cell_w/2, 34, cell_w, 16),
                       Qt.AlignmentFlag.AlignCenter, temp)

            # Day label
            p.setFont(QFont("Courier New", 6))
            p.setPen(QPen(qcol(C.TEXT_DIM), 1))
            p.drawText(QRectF(cx_c - cell_w/2, 50, cell_w, 12),
                       Qt.AlignmentFlag.AlignCenter, label)

            # Divider
            if i < 2:
                p.setPen(QPen(qcol(C.BORDER_B, 80), 1))
                p.drawLine(QPointF(8 + (i+1)*cell_w, 14),
                           QPointF(8 + (i+1)*cell_w, H-14))


# ─────────────────────────────────────────────────────────────────
#  NEWS / NOTIFICATIONS PANEL
# ─────────────────────────────────────────────────────────────────
class NewsPanel(QWidget):
    """Scrolling intelligence feed — matches the top-right HUD panel."""
    _FEED = [
        ("REZA TORIES", [
            ("⚠", C.AMBER2,  "Anomalous quantum fluctuation detected in sector 7-G. Monitoring."),
            ("◈", C.PRI,     "Arc reactor efficiency at 103.2% — within acceptable variance."),
        ]),
        ("MICRO COAST", [
            ("●", C.GREEN,   "Satellite link established. Telemetry stream nominal."),
            ("●", C.GREEN,   "Stark satellite uplink maintains 47Mbaud — channel clear."),
        ]),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._phase = 0.0
        t = QTimer(self); t.timeout.connect(self._tick); t.start(60)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # Header
        hdr = QWidget()
        hdr.setFixedHeight(20)
        hdr.setStyleSheet(f"background:{C.PANEL3}; border-bottom:1px solid {C.BORDER_B};")
        hr = QHBoxLayout(hdr); hr.setContentsMargins(8, 0, 8, 0)
        nd = NodeIndicator(C.PRI); nd.setFixedSize(10, 10); hr.addWidget(nd)
        hl = QLabel("MISSION LOGS"); hl.setFont(QFont("Courier New", 7, QFont.Weight.Bold))
        hl.setStyleSheet(f"color:{C.PRI}; background:transparent; letter-spacing:2px;")
        hr.addWidget(hl); hr.addStretch()
        self._status_dot = NodeIndicator(C.GREEN); self._status_dot.setFixedSize(10, 10)
        hr.addWidget(self._status_dot)
        lay.addWidget(hdr)

        # Scroll content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet(f"""
            QScrollArea {{ background:{C.PANEL2}; border:none; }}
            QScrollBar:vertical {{ background:{C.VOID}; width:3px; border:none; }}
            QScrollBar::handle:vertical {{ background:{C.PRI_DIM}; min-height:12px; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height:0; }}
        """)
        cont = QWidget(); cont.setStyleSheet(f"background:{C.PANEL2};")
        vl = QVBoxLayout(cont); vl.setContentsMargins(8, 6, 8, 6); vl.setSpacing(8)

        for cat_name, items in self._FEED:
            cat_lbl = QLabel(f"▸ {cat_name}")
            cat_lbl.setFont(QFont("Courier New", 7, QFont.Weight.Bold))
            cat_lbl.setStyleSheet(f"color:{C.AMBER2}; background:transparent; letter-spacing:1px;")
            vl.addWidget(cat_lbl)
            for sym, col, msg in items:
                row = QHBoxLayout(); row.setSpacing(6); row.setContentsMargins(4, 0, 0, 0)
                sym_l = QLabel(sym); sym_l.setFont(QFont("Courier New", 8))
                sym_l.setStyleSheet(f"color:{col}; background:transparent;")
                sym_l.setFixedWidth(14); row.addWidget(sym_l)
                txt_l = QLabel(msg); txt_l.setFont(QFont("Courier New", 7))
                txt_l.setStyleSheet(f"color:{C.TEXT}; background:transparent;")
                txt_l.setWordWrap(True); row.addWidget(txt_l, 1)
                vl.addLayout(row)

        vl.addStretch()
        scroll.setWidget(cont)
        lay.addWidget(scroll, 1)

    def _tick(self):
        self._phase += 0.05
        self.update()



# ─────────────────────────────────────────────────────────────────
#  MUSIC PLAYER WIDGET
# ─────────────────────────────────────────────────────────────────
class MusicPlayer(QWidget):
    """Compact now-playing widget — bottom-left corner, matches reference image."""

    _TRACKS = [
        ("PASS FOR ME",  "STARK PLAYLIST",  "3:42"),
        ("IRON MAN",     "AC/DC",           "5:46"),
        ("JOCASTA",      "SYNTHWAVE MIX",   "4:18"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(80)
        self._track_idx = 0
        self._progress  = 0.32   # 0–1
        self._playing   = True
        self._phase     = 0.0
        self._eq        = [random.uniform(0.1, 1.0) for _ in range(18)]
        t = QTimer(self); t.timeout.connect(self._tick); t.start(60)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.setStyleSheet(f"background:{C.PANEL2}; border:1px solid {C.BORDER_A}; border-left:2px solid {C.VIOLET_D};")

    def _tick(self):
        self._phase += 0.06
        if self._playing:
            self._progress = min(1.0, self._progress + 0.0003)
            if self._progress >= 1.0:
                self._progress = 0.0
                self._track_idx = (self._track_idx + 1) % len(self._TRACKS)
            for i in range(len(self._eq)):
                tgt = random.uniform(0.1, 1.0)
                self._eq[i] = self._eq[i] * 0.85 + tgt * 0.15
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()
        track, artist, dur = self._TRACKS[self._track_idx]

        # BG
        bg = QLinearGradient(0, 0, W, 0)
        bg.setColorAt(0, qcol(C.PANEL2)); bg.setColorAt(1, qcol(C.VOID))
        p.fillRect(self.rect(), QBrush(bg))

        # Left accent
        p.fillRect(QRectF(0, 0, 2, H), QBrush(qcol(C.VIOLET, 160)))

        # Music note / album art placeholder
        p.setFont(QFont("Segoe UI Emoji" if _OS == "Windows" else "Arial", 22))
        p.setPen(QPen(qcol(C.VIOLET, 200), 1))
        p.drawText(QRectF(6, 0, 40, H), Qt.AlignmentFlag.AlignCenter, "♫")

        # Track info
        p.setFont(QFont("Courier New", 8, QFont.Weight.Bold))
        p.setPen(QPen(qcol(C.WHITE), 1))
        p.drawText(QRectF(50, 6, W-60, 14), Qt.AlignmentFlag.AlignLeft, track)
        p.setFont(QFont("Courier New", 7))
        p.setPen(QPen(qcol(C.TEXT_DIM), 1))
        p.drawText(QRectF(50, 20, W-60, 12), Qt.AlignmentFlag.AlignLeft, artist)

        # Progress bar
        pb_y = 36; pb_h = 3; pb_x = 50; pb_w = W - 60
        p.setBrush(QBrush(qcol(C.PANEL3))); p.setPen(Qt.PenStyle.NoPen)
        p.drawRect(QRectF(pb_x, pb_y, pb_w, pb_h))
        pg = QLinearGradient(pb_x, 0, pb_x + pb_w, 0)
        pg.setColorAt(0, qcol(C.VIOLET)); pg.setColorAt(1, qcol(C.PRI))
        p.setBrush(QBrush(pg))
        p.drawRect(QRectF(pb_x, pb_y, pb_w * self._progress, pb_h))

        # EQ bars
        eq_x = 50; eq_y = 44; eq_w = W - 60; bar_w = eq_w / len(self._eq)
        for i, v in enumerate(self._eq):
            h_eq = max(2, int(v * 22)) if self._playing else 2
            alp  = int(80 + 120 * v)
            p.setBrush(QBrush(qcol(C.VIOLET if i % 2 == 0 else C.PRI, alp)))
            p.drawRect(QRectF(eq_x + i*bar_w, eq_y + 22 - h_eq, bar_w - 1, h_eq))

        # Duration
        elapsed_s = int(self._progress * 222)
        p.setFont(QFont("Courier New", 6))
        p.setPen(QPen(qcol(C.TEXT_DIM), 1))
        p.drawText(QRectF(pb_x, pb_y + 6, pb_w, 10), Qt.AlignmentFlag.AlignRight,
                   f"{elapsed_s//60}:{elapsed_s%60:02d} / {dur}")

        # Playback symbol
        sym = "▶" if self._playing else "⏸"
        p.setFont(QFont("Courier New", 10))
        p.setPen(QPen(qcol(C.VIOLET_D if not self._playing else C.VIOLET, 220), 1))
        p.drawText(QRectF(W-22, 0, 20, H//2), Qt.AlignmentFlag.AlignCenter, sym)

    def mousePressEvent(self, e):
        self._playing = not self._playing


# ─────────────────────────────────────────────────────────────────
#  DATA MATRIX TABLE
# ─────────────────────────────────────────────────────────────────
class DataMatrix(QWidget):
    """Scrolling live data matrix — bottom-right corner like the reference image."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(130)
        self._rows  = 6
        self._cols  = 7
        self._cells = [[random.randint(0, 99) for _ in range(self._cols)]
                       for _ in range(self._rows)]
        self._highlight = set()
        self._phase = 0.0
        t = QTimer(self); t.timeout.connect(self._tick); t.start(400)
        t2 = QTimer(self); t2.timeout.connect(self.update); t2.start(60)

    def _tick(self):
        self._phase += 0.15
        # Update random cells
        for _ in range(4):
            r = random.randrange(self._rows)
            c = random.randrange(self._cols)
            self._cells[r][c] = random.randint(0, 99)
            self._highlight.add((r, c))
        # Decay highlights
        to_rm = set()
        for k in list(self._highlight):
            if random.random() > 0.6:
                to_rm.add(k)
        self._highlight -= to_rm
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()

        bg = QLinearGradient(0, 0, 0, H)
        bg.setColorAt(0, qcol(C.PANEL2, 200))
        bg.setColorAt(1, qcol(C.VOID,   200))
        p.fillRect(self.rect(), QBrush(bg))

        # Header
        p.setFont(QFont("Courier New", 6, QFont.Weight.Bold))
        p.setPen(QPen(qcol(C.ACC_DIM), 1))
        hdrs = ["SYS", "NET", "CPU", "MEM", "I/O", "QTM", "SEC"]
        cw = (W - 8) / self._cols
        for j, h_txt in enumerate(hdrs):
            p.drawText(QRectF(4 + j*cw, 2, cw, 12),
                       Qt.AlignmentFlag.AlignCenter, h_txt)

        # Grid
        row_h = (H - 18) / self._rows
        for i in range(self._rows):
            for j in range(self._cols):
                rx = 4 + j * cw; ry = 16 + i * row_h
                v  = self._cells[i][j]
                highlighted = (i, j) in self._highlight
                if highlighted:
                    col = C.PRI_GLOW if v > 50 else C.ACC2
                    alp = 240
                    p.setBrush(QBrush(qcol(C.PRI_GHO, 100)))
                    p.setPen(Qt.PenStyle.NoPen)
                    p.drawRect(QRectF(rx+1, ry+1, cw-2, row_h-2))
                else:
                    col = C.TEXT_MED if v > 70 else C.TEXT_DIM
                    alp = 160
                p.setFont(QFont("Courier New", 7, QFont.Weight.Bold if highlighted else QFont.Weight.Normal))
                p.setPen(QPen(qcol(col, alp), 1))
                p.drawText(QRectF(rx, ry, cw, row_h),
                           Qt.AlignmentFlag.AlignCenter, f"{v:02d}")

        # Border
        p.setPen(QPen(qcol(C.BORDER_B, 100), 1))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRect(QRectF(0, 0, W-1, H-1))
        p.setPen(QPen(qcol(C.ACC, 80), 1))
        p.drawLine(QPointF(0, 0), QPointF(W, 0))


# ─────────────────────────────────────────────────────────────────
#  ASSIST STATUS BAR  (bottom of HUD area, matches "ASSIST MODE ONLINE")
# ─────────────────────────────────────────────────────────────────
class AssistStatusBar(QWidget):
    """Blinking status label shown below the arc reactor: 'ASSIST MODE ONLINE / AWAITING COMMAND'."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(28)
        self._blink  = True
        self._tick_n = 0
        self._phase  = 0.0
        t = QTimer(self); t.timeout.connect(self._tick); t.start(28)

    def _tick(self):
        self._tick_n = (self._tick_n + 1) % 40
        if self._tick_n == 0:
            self._blink = not self._blink
        self._phase += 0.04
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()
        pulse = 0.5 + 0.5 * math.sin(self._phase)

        bg = QLinearGradient(0, 0, W, 0)
        bg.setColorAt(0, qcol(C.VOID)); bg.setColorAt(0.5, qcol(C.PANEL2)); bg.setColorAt(1, qcol(C.VOID))
        p.fillRect(self.rect(), QBrush(bg))

        # Scan line effect
        p.setPen(QPen(qcol(C.PRI, int(30 + 20*pulse)), 1))
        p.drawLine(QPointF(0, H//2), QPointF(W, H//2))

        # Status text — top row
        p.setFont(QFont("Courier New", 10, QFont.Weight.Bold))
        txt_a = int(200 + 55 * pulse)
        p.setPen(QPen(qcol(C.PRI, txt_a), 1))
        # Glow
        for dx, dy in [(-1,-1),(1,-1),(-1,1),(1,1),(0,-2),(0,2)]:
            p.setPen(QPen(qcol(C.PRI, 18), 1))
            p.drawText(QRectF(dx, dy, W, H), Qt.AlignmentFlag.AlignCenter, "ASSIST MODE ONLINE")
        p.setPen(QPen(qcol(C.PRI, txt_a), 1))
        p.drawText(QRectF(0, 0, W, H), Qt.AlignmentFlag.AlignCenter, "ASSIST MODE ONLINE")


class AwaitingBar(QWidget):
    """Bottom sub-status: 'AWAITING COMMAND' with animated brackets."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(22)
        self._phase = 0.0
        t = QTimer(self); t.timeout.connect(self._tick); t.start(28)

    def _tick(self):
        self._phase += 0.035
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()
        pulse = 0.5 + 0.5 * math.sin(self._phase)

        bg = QLinearGradient(0, 0, W, 0)
        bg.setColorAt(0, qcol(C.VOID)); bg.setColorAt(0.5, qcol(C.PANEL3, 80)); bg.setColorAt(1, qcol(C.VOID))
        p.fillRect(self.rect(), QBrush(bg))

        p.setFont(QFont("Courier New", 8, QFont.Weight.Bold))
        alp = int(100 + 100 * pulse)
        p.setPen(QPen(qcol(C.TEXT_DIM, alp), 1))
        p.drawText(QRectF(0, 0, W, H), Qt.AlignmentFlag.AlignCenter, "AWAITING COMMAND")


# ─────────────────────────────────────────────────────────────────
#  MAIN WINDOW
# ─────────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    _log_sig   = pyqtSignal(str)
    _state_sig = pyqtSignal(str)
    _flash_sig = pyqtSignal(str, int, str)   # text, ms, color
    _alert_sig = pyqtSignal(str, float)       # level, pct

    def __init__(self, face_path: str):
        super().__init__()
        self.setWindowTitle("J.A.R.V.I.S — IRON PROTOCOL · NEXUS EDITION")
        self.setMinimumSize(_MIN_W, _MIN_H)
        self.resize(_DEFAULT_W, _DEFAULT_H)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self._drag_pos = None

        screen = QApplication.primaryScreen().availableGeometry()
        self.move((screen.width()-_DEFAULT_W)//2, (screen.height()-_DEFAULT_H)//2)

        self.on_text_command   = None
        self._muted            = False
        self._current_file: str | None = None

        central = QWidget(); central.setObjectName("central")
        central.setStyleSheet(f"QWidget#central {{ background:{C.BG}; }}")
        self.setCentralWidget(central)

        root = QVBoxLayout(central)
        root.setContentsMargins(0,0,0,0); root.setSpacing(0)
        root.addWidget(self._build_header())
        root.addWidget(HeaderScanBar())

        body = QHBoxLayout(); body.setContentsMargins(0,0,0,0); body.setSpacing(0)
        self._left_panel = self._build_left_panel()
        body.addWidget(self._left_panel, stretch=0)

        # Centre column: arc reactor HUD + status bars
        centre_col = QVBoxLayout(); centre_col.setContentsMargins(0,0,0,0); centre_col.setSpacing(0)
        self.hud = HudCanvas(face_path)
        self.hud.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        centre_col.addWidget(self.hud, stretch=1)
        self._assist_bar = AssistStatusBar()
        centre_col.addWidget(self._assist_bar)
        self._await_bar = AwaitingBar()
        centre_col.addWidget(self._await_bar)
        body.addLayout(centre_col, stretch=5)

        self._right_panel = self._build_right_panel()
        body.addWidget(self._right_panel, stretch=0)
        root.addLayout(body, stretch=1)
        root.addWidget(self._build_footer())

        # Flash overlay (sits above everything)
        self._flash = FlashOverlay(central)
        self._flash.resize(central.size())

        # Resize grip
        self._grip = ResizeGrip(self)

        self._clock_tmr = QTimer(self)
        self._clock_tmr.timeout.connect(self._tick_clock); self._clock_tmr.start(1000)
        self._tick_clock()
        self._metric_tmr = QTimer(self)
        self._metric_tmr.timeout.connect(self._update_metrics); self._metric_tmr.start(2000)
        self._update_metrics()

        self._log_sig.connect(self._log.append_log)
        self._state_sig.connect(self._apply_state)
        self._flash_sig.connect(self._flash.flash)
        self._alert_sig.connect(self._do_set_alert)

        self._overlay: SetupOverlay | None = None
        self._ready = self._check_config()
        if not self._ready: self._show_setup()

        # Shortcuts
        for key, fn in [
            ("F4",     self._toggle_mute),
            ("F11",    self._toggle_fullscreen),
            ("Ctrl+Q", self.close),
            ("Ctrl+W", self._clear_file),
            ("Ctrl+L", self._log.clear),   # clear chat
        ]:
            sc = QShortcut(QKeySequence(key), self); sc.activated.connect(fn)

    # ── WINDOW BEHAVIOUR ─────────────────────────────────────────

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = e.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if e.buttons() == Qt.MouseButton.LeftButton and self._drag_pos is not None:
            self.move(e.globalPosition().toPoint() - self._drag_pos)

    def mouseReleaseEvent(self, e):
        self._drag_pos = None

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._overlay and self._overlay.isVisible():
            ow, oh = 520, 460; cw = self.centralWidget()
            self._overlay.setGeometry((cw.width()-ow)//2, (cw.height()-oh)//2, ow, oh)
        # Reposition grip
        self._grip.move(self.width()-18, self.height()-18)
        # Resize flash overlay
        if hasattr(self, "_flash"):
            self._flash.resize(self.centralWidget().size())
        # Invalidate scanline cache on resize
        _ScanlineCache.invalidate()

    def _toggle_fullscreen(self):
        self.showNormal() if self.isFullScreen() else self.showFullScreen()

    # ── METRICS ──────────────────────────────────────────────────

    def _update_metrics(self):
        snap = _metrics.snapshot()
        cpu = snap["cpu"]; self._bar_cpu.set_value(cpu, f"{cpu:.0f}%")
        mem = snap["mem"]; self._bar_mem.set_value(mem, f"{mem:.0f}%")

        def _fmt_net(mbps: float) -> str:
            if mbps < 0.001:    return "0 KB/s"
            if mbps < 1.0:      return f"{mbps * 1024:.0f} KB/s"
            if mbps < 1000.0:   return f"{mbps:.2f} MB/s"
            return f"{mbps/1024:.2f} GB/s"

        dl = snap.get("net_dl", 0.0)
        ul = snap.get("net_ul", 0.0)
        self._bar_dl.set_value_raw(dl, _fmt_net(dl))
        self._bar_ul.set_value_raw(ul, _fmt_net(ul))

        try:
            elapsed = time.time() - psutil.boot_time()
            h, m = int(elapsed//3600), int((elapsed%3600)//60)
            self._uptime_lbl.setText(f"UPTIME  {h:02d}:{m:02d}")
        except Exception:
            self._uptime_lbl.setText("UPTIME  --:--")
        try:
            self._proc_lbl.setText(f"PROC  {len(psutil.pids())}")
        except Exception:
            self._proc_lbl.setText("PROC  --")

        # ── Live threat meter ─────────────────────────────────────
        self._threat_meter.refresh_from_metrics()

        # Auto-sync alert badge in header with threat level
        lvl = snap.get("threat_lvl", "nominal")
        pct = snap.get("threat_pct", 0.0)
        self._do_set_alert(lvl, pct)

    # ── HEADER ──────────────────────────────────────────────────

    def _build_header(self) -> QWidget:
        w = QWidget(); w.setFixedHeight(72)
        w.setStyleSheet(f"""
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 {C.VOID}, stop:0.1 {C.PANEL2}, stop:0.5 #020e12,
                stop:0.9 {C.PANEL2}, stop:1 {C.VOID});
            border-bottom: 1px solid {C.BORDER_B};
        """)
        lay = QHBoxLayout(w); lay.setContentsMargins(24,0,24,0); lay.setSpacing(0)

        def _badge(txt, color=C.TEXT_DIM, size=8):
            l = QLabel(txt); l.setFont(QFont("Courier New", size))
            l.setStyleSheet(f"color:{color}; background:transparent;"); return l

        # LEFT — welcome + status
        left = QVBoxLayout(); left.setSpacing(2)
        welcome = QLabel(f"WELCOME BACK,  {_USER_NAME}")
        welcome.setFont(QFont("Courier New", 13, QFont.Weight.Bold))
        welcome.setStyleSheet(f"color:{C.PRI_GLOW}; background:transparent; letter-spacing:3px;")
        left.addWidget(welcome)

        alert_row = QHBoxLayout(); alert_row.setSpacing(8)
        self._alert_badge = QLabel("ALERT  NOMINAL")
        self._alert_badge.setFont(QFont("Courier New", 7, QFont.Weight.Bold))
        self._alert_badge.setStyleSheet(f"""
            color:{C.ALERT_NOM}; background:{C.GREEN_G};
            border:1px solid {C.GREEN_D}; padding:2px 8px; letter-spacing:2px;
        """)
        alert_row.addWidget(self._alert_badge)
        alert_row.addStretch()
        left.addLayout(alert_row)
        lay.addLayout(left)

        node_row = QHBoxLayout(); node_row.setSpacing(6); node_row.setContentsMargins(16,0,16,0)
        for col_n, lbl_n in [(C.GREEN,"AI"),(C.PRI,"NET"),(C.ACC,"SYS")]:
            nd = NodeIndicator(col_n)
            lw = QLabel(lbl_n); lw.setFont(QFont("Courier New", 6))
            lw.setStyleSheet(f"color:{col_n}; background:transparent;")
            node_row.addWidget(nd); node_row.addWidget(lw); node_row.addSpacing(4)
        lay.addLayout(node_row); lay.addStretch()

        mid = QVBoxLayout(); mid.setSpacing(3)
        title = QLabel("J.A.R.V.I.S"); title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Courier New", 24, QFont.Weight.Bold))
        title.setStyleSheet(f"color:{C.PRI}; background:transparent; letter-spacing:18px;")
        mid.addWidget(title)
        sub = QLabel("IRON PROTOCOL  ·  NEXUS INTELLIGENCE SYSTEM  ·  ONLINE")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter); sub.setFont(QFont("Courier New", 6))
        sub.setStyleSheet(f"color:{C.TEXT_DIM}; background:transparent; letter-spacing:5px;")
        mid.addWidget(sub)
        lay.addLayout(mid); lay.addStretch()

        right_col = QVBoxLayout(); right_col.setSpacing(2)
        self._clock_lbl = QLabel("00:00:00")
        self._clock_lbl.setFont(QFont("Courier New", 22, QFont.Weight.Bold))
        self._clock_lbl.setStyleSheet(f"color:{C.PRI}; background:transparent;")
        self._clock_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
        right_col.addWidget(self._clock_lbl)
        self._date_lbl = QLabel("")
        self._date_lbl.setFont(QFont("Courier New", 7))
        self._date_lbl.setStyleSheet(f"color:{C.TEXT_DIM}; background:transparent;")
        self._date_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
        right_col.addWidget(self._date_lbl)
        lay.addLayout(right_col)
        return w

    def _tick_clock(self):
        self._clock_lbl.setText(time.strftime("%H:%M:%S"))
        self._date_lbl.setText(time.strftime("%a %d %b %Y"))

    # ── LEFT PANEL ───────────────────────────────────────────────

    def _build_left_panel(self) -> QWidget:
        w = QWidget(); w.setFixedWidth(_LEFT_W)
        w.setStyleSheet(f"""
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 {C.VOID}, stop:1 {C.PANEL2});
            border-right: 1px solid {C.BORDER_A};
        """)
        lay = QVBoxLayout(w); lay.setContentsMargins(10,12,10,12); lay.setSpacing(6)

        # ── Weather widget ────────────────────────────────────────
        self._weather = WeatherWidget()
        lay.addWidget(self._weather)

        sep0 = QFrame(); sep0.setFrameShape(QFrame.Shape.HLine)
        sep0.setStyleSheet(f"color:{C.BORDER_B};"); lay.addWidget(sep0)

        # ── System telemetry header ───────────────────────────────
        hdr_row = QHBoxLayout(); hdr_row.setSpacing(6)
        hdr_nd = NodeIndicator(C.PRI); hdr_nd.setFixedSize(10,10); hdr_row.addWidget(hdr_nd)
        hdr = QLabel("SYSTEM TELEMETRY"); hdr.setFont(QFont("Courier New",7,QFont.Weight.Bold))
        hdr.setStyleSheet(f"color:{C.PRI}; background:transparent; letter-spacing:2px;")
        hdr_row.addWidget(hdr); hdr_row.addStretch(); lay.addLayout(hdr_row)

        self._bar_cpu = MetricBar("CPU",     C.PRI)
        self._bar_mem = MetricBar("MEMORY",  C.VIOLET)
        self._bar_dl  = MetricBar("NET ↓ DL", C.GREEN)
        self._bar_dl.enable_autoscale()
        self._bar_ul  = MetricBar("NET ↑ UL", C.AMBER)
        self._bar_ul.enable_autoscale()
        for bar in [self._bar_cpu, self._bar_mem, self._bar_dl, self._bar_ul]:
            lay.addWidget(bar)

        lay.addSpacing(2)

        # Mission timer + Threat meter
        self._mission_timer = MissionTimer()
        lay.addWidget(self._mission_timer)
        self._threat_meter = ThreatMeter()
        self._threat_meter.set_alert("nominal")
        lay.addWidget(self._threat_meter)

        # ── Info panel ───────────────────────────────────────────
        info_panel = QWidget()
        info_panel.setStyleSheet(f"""
            background:{C.PANEL2}; border:1px solid {C.BORDER_A};
            border-left:2px solid {C.PRI_DIM};
        """)
        ip_lay = QVBoxLayout(info_panel); ip_lay.setContentsMargins(10,6,10,6); ip_lay.setSpacing(4)
        self._uptime_lbl = QLabel("UPTIME  --:--")
        self._uptime_lbl.setFont(QFont("Courier New",8,QFont.Weight.Bold))
        self._uptime_lbl.setStyleSheet(f"color:{C.GREEN}; background:transparent; border:none;")
        ip_lay.addWidget(self._uptime_lbl)
        self._proc_lbl = QLabel("PROC  --")
        self._proc_lbl.setFont(QFont("Courier New",8))
        self._proc_lbl.setStyleSheet(f"color:{C.TEXT_MED}; background:transparent; border:none;")
        ip_lay.addWidget(self._proc_lbl)
        os_name = {"Windows":"WIN-64","Darwin":"macOS","Linux":"LINUX"}.get(_OS, _OS.upper())
        os_lbl = QLabel(f"OS  {os_name}"); os_lbl.setFont(QFont("Courier New",8))
        os_lbl.setStyleSheet(f"color:{C.AMBER2}; background:transparent; border:none;")
        ip_lay.addWidget(os_lbl)
        lay.addWidget(info_panel)

        lay.addStretch(0)

        for txt, col, bg_col, border_c in [
            ("AI CORE  ONLINE",  C.GREEN,    C.GREEN_G,  C.GREEN_D),
            ("NETWORK  SECURE",  C.PRI,      C.PRI_GHO,  C.PRI_DIM),
            ("PROTOCOL  ACTIVE", C.TEXT_DIM, C.PANEL2,   C.BORDER_A),
        ]:
            row = QHBoxLayout(); row.setSpacing(6)
            nd2 = NodeIndicator(col); nd2.setFixedSize(10,10); row.addWidget(nd2)
            lbl2 = QLabel(txt); lbl2.setFont(QFont("Courier New",7,QFont.Weight.Bold))
            lbl2.setAlignment(Qt.AlignmentFlag.AlignVCenter)
            lbl2.setStyleSheet(f"""
                color:{col}; background:{bg_col};
                border:1px solid {border_c}; border-radius:0px;
                padding:5px 8px; letter-spacing:1px;
            """)
            row.addWidget(lbl2, stretch=1); lay.addLayout(row)
        return w

    def _build_right_panel(self) -> QWidget:
        w = QWidget(); w.setFixedWidth(_RIGHT_W)
        w.setStyleSheet(f"""
            background: qlineargradient(x1:1,y1:0,x2:0,y2:0,
                stop:0 {C.VOID}, stop:1 {C.PANEL2});
            border-left: 1px solid {C.BORDER_A};
        """)
        lay = QVBoxLayout(w); lay.setContentsMargins(10,8,10,8); lay.setSpacing(5)

        def _sec(txt, color=C.TEXT_MED, node_col=C.PRI):
            row = QHBoxLayout(); row.setSpacing(6)
            nd3 = NodeIndicator(node_col); nd3.setFixedSize(10,10); row.addWidget(nd3)
            l = QLabel(txt); l.setFont(QFont("Courier New",7,QFont.Weight.Bold))
            l.setStyleSheet(f"color:{color}; background:transparent; letter-spacing:2px;")
            row.addWidget(l); row.addStretch()
            c2 = QWidget()
            c2.setStyleSheet(f"border-bottom:1px solid {C.BORDER}; padding-bottom:3px; background:transparent;")
            c2.setLayout(row); return c2

        # News / mission logs panel
        lay.addWidget(_sec("MISSION LOGS", C.TEXT_MED, C.ACC))
        self._news = NewsPanel()
        self._news.setFixedHeight(160)
        lay.addWidget(self._news)

        # Last login quick actions
        lay.addWidget(_sec("LAST LOGIN  ·  QUICK ACCESS", C.TEXT_MED, C.VIOLET))
        btn_row = QHBoxLayout(); btn_row.setSpacing(4)
        for icon, lbl, col in [
            ("◈", "MISSION",  C.PRI),
            ("⬡", "SYSTEMS",  C.GREEN),
            ("◉", "MONITOR",  C.ACC),
            ("⚙", "SETTINGS", C.TEXT_DIM),
            ("✦", "ARCHIVE",  C.VIOLET),
        ]:
            b = QPushButton(f"{icon}\n{lbl}")
            b.setFixedSize(62, 48)
            b.setFont(QFont("Courier New", 6, QFont.Weight.Bold))
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setStyleSheet(f"""
                QPushButton {{
                    background:{C.PANEL3}; color:{col};
                    border:1px solid {C.BORDER_B}; border-radius:0px;
                    letter-spacing:1px;
                }}
                QPushButton:hover {{
                    background:{C.PANEL2}; color:{C.WHITE};
                    border:1px solid {col};
                }}
            """)
            btn_row.addWidget(b)
        lay.addLayout(btn_row)

        # Data matrix
        lay.addWidget(_sec("LIVE DATA MATRIX", C.TEXT_MED, C.ACC))
        self._data_matrix = DataMatrix()
        lay.addWidget(self._data_matrix)

        lay.addSpacing(2)
        lay.addWidget(_sec("CONVERSATION LOG", C.TEXT_MED, C.GREEN))
        self._log = ConversationPanel()
        lay.addWidget(self._log, stretch=1)

        lay.addSpacing(2)
        lay.addWidget(_sec("DATA INJECTION", C.TEXT_MED, C.ACC))
        self._drop_zone = FileDropZone()
        self._drop_zone.file_selected.connect(self._on_file_selected)
        lay.addWidget(self._drop_zone)

        self._file_hint = QLabel("No file loaded  ·  Drop or click above  [Ctrl+W clear]")
        self._file_hint.setFont(QFont("Courier New",7))
        self._file_hint.setStyleSheet(f"color:{C.TEXT_DIM}; background:transparent;")
        self._file_hint.setWordWrap(True)
        lay.addWidget(self._file_hint)

        lay.addSpacing(2)
        lay.addWidget(_sec("COMMAND INPUT", C.TEXT_MED, C.PRI))
        lay.addLayout(self._build_input_row())

        self._mute_btn = QPushButton("◉  ONLINE · LISTENING")
        self._mute_btn.setFixedHeight(36)
        self._mute_btn.setFont(QFont("Courier New",8,QFont.Weight.Bold))
        self._mute_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._mute_btn.clicked.connect(self._toggle_mute)
        self._style_mute_btn(); lay.addWidget(self._mute_btn)

        fs_btn = QPushButton("⛶  FULLSCREEN [F11]   ·   CLOSE [Ctrl+Q]   ·   CLEAR LOG [Ctrl+L]")
        fs_btn.setFixedHeight(26); fs_btn.setFont(QFont("Courier New",7))
        fs_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        fs_btn.setStyleSheet(f"""
            QPushButton {{ background:transparent; color:{C.TEXT_DIM};
                border:1px solid {C.BORDER}; border-radius:0px; }}
            QPushButton:hover {{ color:{C.PRI}; border:1px solid {C.PRI_DIM}; }}
        """)
        fs_btn.clicked.connect(self._toggle_fullscreen); lay.addWidget(fs_btn)
        return w

    def _build_input_row(self) -> QHBoxLayout:
        row = QHBoxLayout(); row.setSpacing(6)
        self._input = QLineEdit()
        self._input.setPlaceholderText("Enter command…")
        self._input.setFont(QFont("Courier New",9))
        self._input.setFixedHeight(38)
        self._input.setStyleSheet(f"""
            QLineEdit {{
                background:{C.PANEL2}; color:{C.PRI};
                border:1px solid {C.BORDER_A};
                border-bottom:1px solid {C.PRI_DIM};
                border-radius:0px; padding:4px 14px;
                font-family:'Courier New'; font-size:10px; letter-spacing:1px;
            }}
            QLineEdit:focus {{
                border:1px solid {C.PRI};
                border-bottom:2px solid {C.PRI};
                background:{C.PRI_GHO};
            }}
        """)
        self._input.returnPressed.connect(self._send)
        row.addWidget(self._input)
        send = QPushButton("▶"); send.setFixedSize(38,38)
        send.setFont(QFont("Courier New",14,QFont.Weight.Bold))
        send.setCursor(Qt.CursorShape.PointingHandCursor)
        send.setStyleSheet(f"""
            QPushButton {{ background:{C.PRI_GHO}; color:{C.PRI};
                border:1px solid {C.PRI_DIM}; border-bottom:2px solid {C.PRI}; border-radius:0px; }}
            QPushButton:hover {{ background:{C.PRI_DEEP}; color:{C.WHITE};
                border:1px solid {C.PRI}; border-bottom:2px solid {C.PRI_GLOW}; }}
        """)
        send.clicked.connect(self._send); row.addWidget(send)
        return row

    # ── FOOTER ──────────────────────────────────────────────────

    def _build_footer(self) -> QWidget:
        w = QWidget(); w.setFixedHeight(24)
        w.setStyleSheet(f"""
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 {C.VOID}, stop:0.5 #020d10, stop:1 {C.VOID});
            border-top: 1px solid {C.BORDER_B};
        """)
        lay = QHBoxLayout(w); lay.setContentsMargins(18,0,18,0)

        def _fl(txt, color=C.TEXT_DIM):
            l = QLabel(txt); l.setFont(QFont("Courier New",7))
            l.setStyleSheet(f"color:{color}; background:transparent;"); return l

        lay.addWidget(_fl("[F4] MIC  ·  [F11] FULLSCREEN  ·  [Ctrl+Q] CLOSE  ·  [Ctrl+W] CLEAR FILE  ·  [Ctrl+L] CLEAR LOG"))
        lay.addStretch()
        lay.addWidget(_fl("J.A.R.V.I.S  ·  IRON PROTOCOL  ·  NEXUS EDITION  ·  CLASSIFIED", C.BORDER_B))
        lay.addStretch()
        lay.addWidget(_fl("ONLINE", C.PRI_DIM))
        return w

    # ── INTERNAL ─────────────────────────────────────────────────

    def _on_file_selected(self, path: str):
        self._current_file = path
        p2   = Path(path)
        cat  = _file_category(p2)
        icon, _ = _FILE_ICONS.get(cat, _FILE_ICONS["unknown"])
        size = _fmt_size(p2.stat().st_size)
        self._file_hint.setText(f"{icon}  {p2.name}  ·  {size}  ·  Ready  [Ctrl+W to clear]")
        self._log.add_file(f"{p2.name} ({size}) loaded")
        if self.on_text_command:
            msg = (
                f"[FILE_UPLOADED] path={path} | name={p2.name} | "
                f"type={p2.suffix.lstrip('.')} | size={size} | "
                f"Briefly tell the user you can see the file '{p2.name}' "
                f"({size}) has been uploaded and ask what they'd like to do with it."
            )
            threading.Thread(target=self.on_text_command, args=(msg,), daemon=True).start()

    def _clear_file(self):
        self._current_file = None
        self._drop_zone.clear_file()
        self._file_hint.setText("No file loaded  ·  Drop or click above  [Ctrl+W clear]")
        self._log.add_sys("File cleared.")

    def _toggle_mute(self):
        self._muted = not self._muted
        self.hud.muted = self._muted
        self._style_mute_btn()
        if self._muted:
            self._apply_state("MUTED")
            self._log.add_sys("Microphone disabled.")
        else:
            self._apply_state("LISTENING")
            self._log.add_sys("Microphone active.")

    def _style_mute_btn(self):
        if self._muted:
            self._mute_btn.setText("⊘  OFFLINE · MUTED")
            self._mute_btn.setStyleSheet(f"""
                QPushButton {{ background:{C.RED_G}; color:{C.MUTED_C};
                    border:1px solid {C.RED_D}; border-radius:0px;
                    font-family:'Courier New'; font-size:8px; font-weight:bold; letter-spacing:2px; }}
            """)
        else:
            self._mute_btn.setText("◉  ONLINE · LISTENING")
            self._mute_btn.setStyleSheet(f"""
                QPushButton {{ background:{C.GREEN_G}; color:{C.GREEN};
                    border:1px solid {C.GREEN_D}; border-radius:0px;
                    font-family:'Courier New'; font-size:8px; font-weight:bold; letter-spacing:2px; }}
                QPushButton:hover {{ background:#001e12; border:1px solid {C.GREEN}; }}
            """)

    def _send(self):
        txt = self._input.text().strip()
        if not txt: return
        self._input.clear()
        self._log.add_user(txt)
        if self.on_text_command:
            threading.Thread(target=self.on_text_command, args=(txt,), daemon=True).start()

    def _apply_state(self, state: str):
        self.hud.state    = state
        self.hud.speaking = (state == "SPEAKING")

    def _do_set_alert(self, level: str, pct: float):
        self._threat_meter.set_alert(level, pct if pct >= 0 else None)
        col_map = {
            "nominal":  (C.ALERT_NOM, C.GREEN_G,  C.GREEN_D),
            "caution":  (C.ALERT_CAU, C.AMBER_G,  C.AMBER_D),
            "critical": (C.ALERT_CRI, C.RED_G,    C.RED_D),
        }
        col, bg, border = col_map.get(level, col_map["nominal"])
        self.hud.alert_col = col
        lbl_txt = {"nominal": "ALERT  NOMINAL", "caution": "ALERT  CAUTION",
                   "critical": "⚠  CRITICAL  ⚠"}.get(level, "ALERT  NOMINAL")
        if hasattr(self, "_alert_badge"):
            self._alert_badge.setText(lbl_txt)
            self._alert_badge.setStyleSheet(f"""
                color:{col}; background:{bg};
                border:1px solid {border}; padding:2px 8px; letter-spacing:2px;
            """)

    def _check_config(self) -> bool:
        if not API_FILE.exists(): return False
        try:
            d = json.loads(API_FILE.read_text(encoding="utf-8"))
            return bool(d.get("gemini_api_key")) and bool(d.get("os_system"))
        except Exception:
            return False

    def _show_setup(self):
        ov = SetupOverlay(self.centralWidget())
        cw = self.centralWidget(); ow, oh = 520, 460
        ov.setGeometry((cw.width()-ow)//2, (cw.height()-oh)//2, ow, oh)
        ov.done.connect(self._on_setup_done); ov.show()
        self._overlay = ov

    def _on_setup_done(self, key: str, os_name: str):
        os.makedirs(CONFIG_DIR, exist_ok=True)
        API_FILE.write_text(
            json.dumps({"gemini_api_key": key, "os_system": os_name}, indent=4),
            encoding="utf-8",
        )
        self._ready = True
        if self._overlay: self._overlay.hide(); self._overlay = None
        self._apply_state("LISTENING")
        self._log.add_sys(f"J.A.R.V.I.S online. OS={os_name.upper()}. IRON PROTOCOL ACTIVE.")


# ─────────────────────────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────────────────────────
class _RootShim:
    def __init__(self, app: QApplication):
        self._app = app
    def mainloop(self):
        self._app.exec()
    def protocol(self, *_):
        pass


class JarvisUI:
    """
    Full public API — all previous methods preserved, new ones added.

    New methods:
        set_alert(level, pct=None)   — 'nominal' | 'caution' | 'critical'
        flash_message(txt, ms=1800)  — full-screen flash overlay
        clear_chat()                 — wipe conversation panel
        lap_timer()                  — record mission timer lap
        reset_timer()                — reset mission timer
        write_user(txt)              — add a user bubble directly
        write_jarvis(txt)            — add a JARVIS bubble directly
        write_sys(txt)               — add a system bubble
    """
    def __init__(self, face_path: str, size=None):
        self._app = QApplication.instance() or QApplication(sys.argv)
        self._app.setStyle("Fusion")
        self._win = MainWindow(face_path)
        self._win.show()
        self.root = _RootShim(self._app)

    # ── State / voice ────────────────────────────────────────────

    @property
    def muted(self) -> bool:
        return self._win._muted

    @muted.setter
    def muted(self, v: bool):
        if v != self._win._muted:
            self._win._toggle_mute()

    def set_state(self, state: str):
        self._win._state_sig.emit(state)

    def start_speaking(self):
        self.set_state("SPEAKING")

    def stop_speaking(self):
        if not self.muted:
            self.set_state("LISTENING")

    # ── File ─────────────────────────────────────────────────────

    @property
    def current_file(self) -> str | None:
        return self._win._drop_zone.current_file()

    # ── Command callback ─────────────────────────────────────────

    @property
    def on_text_command(self):
        return self._win.on_text_command

    @on_text_command.setter
    def on_text_command(self, cb):
        self._win.on_text_command = cb

    # ── Logging / chat ───────────────────────────────────────────

    def write_log(self, text: str):
        """Legacy: auto-routes by prefix. Use write_jarvis/write_user for clarity."""
        self._win._log_sig.emit(text)

    def write_user(self, text: str):
        self._win._log.add_user(text)

    def write_jarvis(self, text: str):
        self._win._log.add_jarvis(text)

    def write_sys(self, text: str):
        self._win._log.add_sys(text)

    def clear_chat(self):
        self._win._log.clear()

    # ── Alert / threat ───────────────────────────────────────────

    def set_alert(self, level: str, pct: float = -1.0):
        """
        level: 'nominal' | 'caution' | 'critical'
        pct:   0–100 override; omit for auto (18 / 55 / 91)
        """
        self._win._alert_sig.emit(level, pct)

    # ── Flash overlay ─────────────────────────────────────────────

    def flash_message(self, text: str, ms: int = 1800, color: str = C.PRI_GLOW):
        self._win._flash_sig.emit(text, ms, color)

    # ── Mission timer ─────────────────────────────────────────────

    def lap_timer(self):
        self._win._mission_timer.lap()

    def reset_timer(self):
        self._win._mission_timer.reset()

    # ── Startup gate ─────────────────────────────────────────────

    def wait_for_api_key(self):
        while not self._win._ready:
            time.sleep(0.1)