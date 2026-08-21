#!/usr/bin/env python3
"""GasChanger field diagnostics GUI over an OpenOCD RTT TCP server."""

from __future__ import annotations

import argparse
import codecs
import csv
import glob
import hashlib
import json
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter.scrolledtext import ScrolledText

from rtt_terminal import (
    DEFAULT_PUBLIC_KEY,
    DEFAULT_SYMBOL_CACHE,
    create_analyzer,
)


DEFAULT_SYMBOL_URL = (
    "https://raw.githubusercontent.com/kaohunt/"
    "GasChanger-Field-Diagnostics/main/symbols"
)
ADMIN_HASH_PREFIX = b"GasChanger-Rev3-RTT-Admin-v1:"
PROMPT = "GasChanger> "
TOKEN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)")
EVENT_RE = re.compile(
    r"event tick=(\d+) code=(\d+) name=([A-Z_]+) "
    r"arg0=(0x[0-9A-Fa-f]+) arg1=(0x[0-9A-Fa-f]+)"
)

EVENT_DETAILS = {
    "BOOT": ("Controller boot", "arg0=reset flags, arg1=boot counter"),
    "ALARM_CHANGE": ("Alarm bitmap changed", "arg0=previous bitmap, arg1=new bitmap"),
    "VALVE_REQUEST": ("3-way valve direction requested", "arg0=direction, arg1=request reason"),
    "VALVE_OUTPUT": ("Valve drive output changed", "arg0=direction, arg1=output/power state"),
    "VALVE_FEEDBACK": ("Physical OPEN feedback changed", "arg0=previous/direction, arg1=new/port state"),
    "CHECK_SET": ("Valve CHECK fault asserted", "No valid single-side OPEN feedback was confirmed in time"),
    "CHECK_CLEAR": ("Valve CHECK fault cleared", "A valid physical OPEN feedback was confirmed"),
    "SWITCH_BEGIN": ("Automatic switching event began", "arg0/arg1 contain switching state and event masks"),
    "SWITCH_DONE": ("Automatic switching event completed", "arg0/arg1 contain completion/result masks"),
    "WIFI_LINK": ("Wi-Fi link state changed", "arg0=previous state, arg1=new state"),
    "ETH_LINK": ("Ethernet PHY link changed", "arg0=previous link, arg1=new link"),
    "ADC_VALID_CHANGE": ("Pressure ADC validity changed", "Bit mask: bit0=LEFT, bit1=RIGHT, bit2=OUT; arg0=old, arg1=new"),
    "ADC_READY": ("ADC startup alarm suppression ended", "arg0=elapsed ms, arg1=stable sample count"),
    "GPIO_HEALTH": ("GPIO expander health changed", "arg0=0 fault/1 recovered, arg1=diagnostic counter"),
    "GPIO_RECOVERY": ("GPIO expander recovery completed", "arg0=result, arg1=reinitialization count"),
    "RS485_ERROR": ("RS485 UART line error latched", "arg0=USART error flags, arg1=error count"),
    "RS485_RECOVERY": ("RS485 line returned to normal", "arg0=previous USART flags, arg1=clear count"),
    "ETH_INIT": ("Ethernet initialization attempt completed", "arg0=1 success/0 failure; arg1=DHCP or failure reason"),
}

EVENT_CATEGORIES = ("all", "system", "alarm", "valve", "wifi", "ethernet", "adc", "gpio", "rs485")


def _convert_scalar(value: str) -> object:
    if value.startswith("0x"):
        try:
            return int(value, 16)
        except ValueError:
            return value
    try:
        return int(value)
    except ValueError:
        return value


def parse_key_values(line: str) -> dict[str, object]:
    """Parse the stable key=value wire format emitted by DebugConsole.c."""
    parsed: dict[str, object] = {}
    for match in TOKEN_RE.finditer(line):
        key, raw = match.groups()
        if raw.startswith("[") and raw.endswith("]"):
            parsed[key] = [_convert_scalar(item) for item in raw[1:-1].split(",")]
        else:
            parsed[key] = _convert_scalar(raw)
    return parsed


def line_namespace(line: str) -> str:
    stripped = line.strip()
    if not stripped:
        return ""
    first = stripped.split(None, 1)[0]
    if "=" in first:
        first_key = first.split("=", 1)[0]
        first = {
            "uptime_ms": "status",
            "requested": "valve",
            "free": "heap",
            "hwm_words": "tasks",
            "rx_chars": "stats",
            "diagnostic_magic": "version",
            "fw_product": "firmware",
            "source_id": "firmware_source",
        }.get(first_key, first_key)
    return first.rstrip(":")


class TelemetryStore:
    """Thread-safe latest-value store with flattened array metrics."""

    def __init__(self) -> None:
        self._values: dict[str, object] = {}
        self._updated: dict[str, float] = {}
        self._lock = threading.Lock()

    def update_line(self, line: str, now: Optional[float] = None) -> list[str]:
        namespace = line_namespace(line)
        values = parse_key_values(line)
        if not namespace or not values:
            return []
        timestamp = time.time() if now is None else now
        changed: list[str] = []
        with self._lock:
            for key, value in values.items():
                base = f"{namespace}.{key}"
                self._values[base] = value
                self._updated[base] = timestamp
                changed.append(base)
                if isinstance(value, list):
                    for index, item in enumerate(value):
                        path = f"{base}[{index}]"
                        self._values[path] = item
                        self._updated[path] = timestamp
                        changed.append(path)
        return changed

    def get(self, path: str, default: object = "-") -> object:
        with self._lock:
            return self._values.get(path, default)

    def updated(self, path: str) -> float:
        with self._lock:
            return self._updated.get(path, 0.0)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return dict(self._values)


@dataclass(frozen=True)
class WatchDefinition:
    label: str
    path: str
    unit: str = ""
    divisor: float = 1.0


DEFAULT_WATCHES = (
    WatchDefinition("Left pressure", "sensor.pressure_tenths[0]", "kgf/cm²", 10.0),
    WatchDefinition("Right pressure", "sensor.pressure_tenths[1]", "kgf/cm²", 10.0),
    WatchDefinition("Outlet pressure", "sensor.pressure_tenths[2]", "kgf/cm²", 10.0),
    WatchDefinition("Left ADC", "sensor.dma_raw[0]"),
    WatchDefinition("Right ADC", "sensor.dma_raw[1]"),
    WatchDefinition("Outlet ADC", "sensor.dma_raw[2]"),
    WatchDefinition("Alarm bitmap", "status.alarm"),
    WatchDefinition("Valve CHECK", "status.check"),
    WatchDefinition("Free heap", "rtos.heap_free", "bytes"),
    WatchDefinition("Minimum heap", "rtos.heap_min", "bytes"),
    WatchDefinition("Task stall bitmap", "rtos.stall"),
    WatchDefinition("GPIO I2C errors", "io_i2c.error"),
    WatchDefinition("SET key", "io_inputs.enter"),
    WatchDefinition("MENU key", "io_inputs.menu"),
    WatchDefinition("UP key", "io_inputs.up"),
    WatchDefinition("DOWN key", "io_inputs.down"),
    WatchDefinition("RS485 frames", "rs485.frames"),
    WatchDefinition("RS485 CRC errors", "rs485.crc_bad"),
    WatchDefinition("Wi-Fi link", "wifi.link"),
    WatchDefinition("Ethernet PHY", "ethernet.phy"),
)


class RttSession:
    """Reconnectable, serialized command stream for the single RTT channel."""

    def __init__(
        self,
        host: str,
        port: int,
        event_queue: queue.Queue[tuple[str, object]],
        analyzer: object = None,
        log_path: Optional[Path] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.events = event_queue
        self.analyzer = analyzer
        self.log_path = log_path
        self.commands: queue.Queue[str] = queue.Queue()
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.connection: Optional[socket.socket] = None
        self._log = None
        self._send_lock = threading.Lock()
        self._log_line_buffer = ""
        self._secret_log_suppressed = False

    def start(self) -> None:
        if self.thread is not None and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="rtt-gui-session", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        connection = self.connection
        if connection is not None:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass
        if self.thread is not None:
            self.thread.join(timeout=2.0)

    def send(self, command: str) -> None:
        command = command.strip()
        if command:
            self.commands.put(command)

    def send_immediate(self, command: str) -> bool:
        connection = self.connection
        if connection is None:
            return False
        try:
            with self._send_lock:
                connection.sendall(command.strip().encode("utf-8") + b"\n")
            return True
        except OSError:
            return False

    def _emit(self, kind: str, payload: object) -> None:
        self.events.put((kind, payload))

    def _open_log(self) -> None:
        if self.log_path is not None and self._log is None:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log = self.log_path.open("ab")

    def _close_log(self) -> None:
        if self._log is not None:
            self._log.close()
            self._log = None

    def _write_log(self, text: str) -> None:
        """Write RTT text while never persisting Admin-only credentials."""
        if self._log is None:
            return
        self._log_line_buffer += text
        lines = self._log_line_buffer.splitlines(keepends=True)
        if lines and not lines[-1].endswith(("\n", "\r")):
            self._log_line_buffer = lines.pop()
        else:
            self._log_line_buffer = ""
        output: list[str] = []
        for line in lines:
            stripped = line.strip()
            marker = stripped
            if marker.startswith(PROMPT.strip()):
                marker = marker[len(PROMPT.strip()):].strip()
            if marker == "secrets_begin":
                self._secret_log_suppressed = True
                output.append("[ADMIN CREDENTIAL RESPONSE REDACTED]\r\n")
            elif marker == "secrets_end":
                self._secret_log_suppressed = False
            elif not self._secret_log_suppressed:
                output.append(line)
        if output:
            self._log.write("".join(output).encode("utf-8", errors="replace"))
            self._log.flush()

    def _run(self) -> None:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        retry = 0.5
        self._open_log()
        try:
            while not self.stop_event.is_set():
                try:
                    self.connection = socket.create_connection(
                        (self.host, self.port), timeout=2.0
                    )
                    self.connection.settimeout(0.1)
                    retry = 0.5
                    self._emit("connection", True)
                    with self._send_lock:
                        self.connection.sendall(b"version\nping\n")
                    while not self.stop_event.is_set():
                        while True:
                            try:
                                command = self.commands.get_nowait()
                            except queue.Empty:
                                break
                            with self._send_lock:
                                self.connection.sendall(command.encode("utf-8") + b"\n")
                        try:
                            data = self.connection.recv(4096)
                        except socket.timeout:
                            continue
                        if not data:
                            raise ConnectionError("RTT server closed the connection")
                        text = decoder.decode(data)
                        self._write_log(text)
                        self._emit("text", text)
                        if self.analyzer is not None:
                            for message in self.analyzer.feed(text):
                                self._emit("analysis", message)
                except (ConnectionError, OSError) as error:
                    self._emit("connection", False)
                    self._emit("notice", f"RTT reconnect pending: {error}")
                    if self.connection is not None:
                        try:
                            self.connection.close()
                        except OSError:
                            pass
                    self.connection = None
                    self.stop_event.wait(retry)
                    retry = min(retry * 2.0, 5.0)
        finally:
            self._close_log()
            self._emit("connection", False)


class OpenOcdManager:
    def __init__(self, tool_directory: Path) -> None:
        self.tool_directory = tool_directory
        self.process: Optional[subprocess.Popen[str]] = None
        self.stdout_path: Optional[Path] = None
        self.stderr_path: Optional[Path] = None

    @staticmethod
    def locate() -> tuple[Path, Path]:
        binaries = sorted(
            glob.glob(
                "C:/ST/STM32CubeIDE_*/STM32CubeIDE/plugins/"
                "com.st.stm32cube.ide.mcu.externaltools.openocd.win32_*/"
                "tools/bin/openocd.exe"
            ),
            key=os.path.getmtime,
            reverse=True,
        )
        scripts = sorted(
            glob.glob(
                "C:/ST/STM32CubeIDE_*/STM32CubeIDE/plugins/"
                "com.st.stm32cube.ide.mcu.debug.openocd_*/resources/"
                "openocd/st_scripts"
            ),
            key=os.path.getmtime,
            reverse=True,
        )
        if not binaries or not scripts:
            raise FileNotFoundError("STM32CubeIDE OpenOCD was not found under C:\\ST")
        return Path(binaries[0]), Path(scripts[0])

    def start(self) -> None:
        if self.process is not None and self.process.poll() is None:
            return
        binary, scripts = self.locate()
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        log_dir = Path(os.environ.get("TEMP", str(self.tool_directory)))
        self.stdout_path = log_dir / f"gaschanger-openocd-{stamp}.out.log"
        self.stderr_path = log_dir / f"gaschanger-openocd-{stamp}.err.log"
        stdout_file = self.stdout_path.open("w", encoding="utf-8")
        stderr_file = self.stderr_path.open("w", encoding="utf-8")
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        self.process = subprocess.Popen(
            [str(binary), "-s", str(scripts), "-f", str(self.tool_directory / "gaschanger_rtt.cfg")],
            stdout=stdout_file,
            stderr=stderr_file,
            text=True,
            creationflags=flags,
        )
        stdout_file.close()
        stderr_file.close()

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None


class LiveChart(ttk.Frame):
    COLORS = ("#58a6ff", "#3fb950", "#f0883e", "#d2a8ff", "#f85149", "#8b949e")

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.canvas = tk.Canvas(self, bg="#0d1117", highlightthickness=0, height=260)
        self.canvas.pack(fill="both", expand=True)
        self.series: dict[str, deque[tuple[float, float]]] = {}
        self.canvas.bind("<Configure>", lambda _event: self.redraw())

    def add(self, name: str, value: float, timestamp: float) -> None:
        points = self.series.setdefault(name, deque(maxlen=180))
        points.append((timestamp, value))
        self.redraw()

    def clear(self) -> None:
        self.series.clear()
        self.redraw()

    def redraw(self) -> None:
        canvas = self.canvas
        canvas.delete("all")
        width = max(canvas.winfo_width(), 200)
        height = max(canvas.winfo_height(), 120)
        left, top, right, bottom = 54, 18, width - 16, height - 34
        canvas.create_rectangle(left, top, right, bottom, outline="#30363d")
        all_points = [point for points in self.series.values() for point in points]
        if not all_points:
            canvas.create_text(width / 2, height / 2, text="Select numeric watches", fill="#8b949e")
            return
        t_min = min(point[0] for point in all_points)
        t_max = max(point[0] for point in all_points)
        v_min = min(point[1] for point in all_points)
        v_max = max(point[1] for point in all_points)
        if t_max <= t_min:
            t_max = t_min + 1.0
        if v_max <= v_min:
            v_max = v_min + 1.0
        pad = (v_max - v_min) * 0.08
        v_min -= pad
        v_max += pad
        canvas.create_text(left - 6, top, text=f"{v_max:.1f}", anchor="e", fill="#8b949e")
        canvas.create_text(left - 6, bottom, text=f"{v_min:.1f}", anchor="e", fill="#8b949e")
        for index, (name, points) in enumerate(self.series.items()):
            coordinates: list[float] = []
            for timestamp, value in points:
                x = left + (timestamp - t_min) / (t_max - t_min) * (right - left)
                y = bottom - (value - v_min) / (v_max - v_min) * (bottom - top)
                coordinates.extend((x, y))
            color = self.COLORS[index % len(self.COLORS)]
            if len(coordinates) >= 4:
                canvas.create_line(*coordinates, fill=color, width=2, smooth=False)
            canvas.create_text(left + index * 150, height - 15, text=name, anchor="w", fill=color)


class GasChangerGui(tk.Tk):
    SLOW_POLL_COMMANDS = (
        "wifi detail", "ethernet", "rtos", "io", "rs485", "watchdog",
        "config all", "fault", "stats", "admin status",
    )

    def __init__(self, args: argparse.Namespace) -> None:
        super().__init__()
        self.title("GasChanger RTT Field Console")
        self.geometry("1280x820")
        self.minsize(980, 650)
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.tool_directory = Path(__file__).resolve().parent
        self.telemetry = TelemetryStore()
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.session: Optional[RttSession] = None
        self.openocd = OpenOcdManager(self.tool_directory)
        self.connected = False
        self.raw_buffer = ""
        self.prompt_probe = ""
        self.secret_wire_buffer = ""
        self.secret_capture_active = False
        self.secret_payload: dict[str, object] = {}
        self.history: list[str] = []
        self.history_index = 0
        self.last_fast_poll = 0.0
        self.last_slow_poll = 0.0
        self.poll_index = 0
        self.poll_interval = tk.DoubleVar(value=max(0.2, args.poll_interval))
        self.slow_poll_interval = tk.DoubleVar(value=1.0)
        self.effective_fast_interval = max(0.2, args.poll_interval)
        self.last_output_drops = 0
        self.command_pending = False
        self.boot_time_anchor: Optional[float] = None
        self.boot_anchors: dict[int, float] = {}
        self.event_response_boot = 0
        self.event_records: list[dict[str, object]] = []
        self.event_record_by_iid: dict[str, dict[str, object]] = {}
        self.fault_records: list[dict[str, object]] = []
        self.last_fault_identity: tuple[object, ...] | None = None
        self.host = tk.StringVar(value=args.host)
        self.port = tk.IntVar(value=args.port)
        self.connection_text = tk.StringVar(value="Disconnected")
        self.auto_poll = tk.BooleanVar(value=True)
        self.log_path = tk.StringVar(value=str(args.log or self._default_log_path()))
        self.watch_enabled: dict[str, tk.BooleanVar] = {}
        self.watch_rows: dict[str, str] = {}
        self.watch_history: dict[str, deque[tuple[float, float]]] = {}
        self._configure_style()
        self._build_ui()
        analyzer = create_analyzer(
            args.elf, args.symbols, args.symbol_cache, args.symbol_url, args.public_key
        )
        self.analyzer = analyzer
        self.after(60, self._drain_events)
        self.after(250, self._poll_tick)
        if not args.smoke_test:
            self.after(350, lambda: self.connect(start_openocd=not args.no_openocd))

    @staticmethod
    def _default_log_path() -> Path:
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "GasChanger" / "logs"
        return base / f"rtt-{datetime.now():%Y%m%d-%H%M%S}.log"

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Status.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("CardValue.TLabel", font=("Segoe UI", 19, "bold"))
        style.configure("CardTitle.TLabel", foreground="#57606a")
        style.configure("Danger.TButton", foreground="#a40e26")

    def _build_ui(self) -> None:
        top = ttk.Frame(self, padding=(10, 8))
        top.pack(fill="x")
        ttk.Label(top, text="GasChanger", font=("Segoe UI", 16, "bold")).pack(side="left")
        self.status_dot = tk.Canvas(top, width=16, height=16, highlightthickness=0)
        self.status_dot.pack(side="left", padx=(18, 4))
        self._set_connection(False)
        ttk.Label(top, textvariable=self.connection_text, style="Status.TLabel").pack(side="left")
        ttk.Button(top, text="Connect", command=self.connect).pack(side="right")
        ttk.Button(top, text="Disconnect", command=self.disconnect).pack(side="right", padx=6)
        ttk.Button(top, text="Snapshot", command=lambda: self.send_command("snapshot")).pack(side="right")

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        self.dashboard_tab = ttk.Frame(self.tabs, padding=10)
        self.watch_tab = ttk.Frame(self.tabs, padding=10)
        self.events_tab = ttk.Frame(self.tabs, padding=10)
        self.console_tab = ttk.Frame(self.tabs, padding=8)
        self.control_tab = ttk.Frame(self.tabs, padding=10)
        self.settings_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.dashboard_tab, text="Dashboard")
        self.tabs.add(self.watch_tab, text="Live Watch")
        self.tabs.add(self.events_tab, text="Events / Fault")
        self.tabs.add(self.console_tab, text="Console")
        self.tabs.add(self.control_tab, text="Admin Controls")
        self.tabs.add(self.settings_tab, text="Settings")
        self._build_dashboard()
        self._build_watch()
        self._build_events()
        self._build_console()
        self._build_controls()
        self._build_settings()

    def _build_dashboard(self) -> None:
        cards = ttk.Frame(self.dashboard_tab)
        cards.pack(fill="x")
        self.card_vars: dict[str, tk.StringVar] = {}
        definitions = (
            ("Service", "service"), ("Valve", "valve"), ("Alarm", "alarm"),
            ("Left pressure", "left"), ("Right pressure", "right"), ("Outlet", "out"),
            ("Left gas", "left_gas"), ("Right gas", "right_gas"),
            ("Left ECO", "left_eco"), ("Right ECO", "right_eco"),
            ("Wi-Fi", "wifi"), ("Ethernet", "ethernet"),
        )
        for index, (title, key) in enumerate(definitions):
            frame = ttk.LabelFrame(cards, text=title, padding=10)
            frame.grid(row=index // 6, column=index % 6, sticky="nsew", padx=4, pady=4)
            cards.columnconfigure(index % 6, weight=1)
            variable = tk.StringVar(value="-")
            self.card_vars[key] = variable
            ttk.Label(frame, textvariable=variable, style="CardValue.TLabel").pack()
        body = ttk.Panedwindow(self.dashboard_tab, orient="horizontal")
        body.pack(fill="both", expand=True, pady=(10, 0))
        health_frame = ttk.LabelFrame(body, text="Subsystem health", padding=6)
        detail_frame = ttk.LabelFrame(body, text="Latest telemetry", padding=6)
        body.add(health_frame, weight=1)
        body.add(detail_frame, weight=2)
        self.health_tree = ttk.Treeview(health_frame, columns=("name", "state", "detail"), show="headings")
        self.health_tree.heading("name", text="Subsystem")
        self.health_tree.heading("state", text="State")
        self.health_tree.heading("detail", text="Detail")
        self.health_tree.column("name", width=130)
        self.health_tree.column("state", width=90, anchor="center")
        self.health_tree.column("detail", width=230)
        self.health_tree.pack(fill="both", expand=True)
        self.detail_tree = ttk.Treeview(detail_frame, columns=("value", "updated"), show="tree headings")
        self.detail_tree.heading("#0", text="Variable")
        self.detail_tree.heading("value", text="Value")
        self.detail_tree.heading("updated", text="Updated")
        self.detail_tree.column("#0", width=300)
        self.detail_tree.column("value", width=240)
        self.detail_tree.column("updated", width=100)
        self.detail_tree.pack(fill="both", expand=True)

    def _build_watch(self) -> None:
        toolbar = ttk.Frame(self.watch_tab)
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Button(toolbar, text="Clear chart", command=self._clear_watch_chart).pack(side="right")
        ttk.Button(toolbar, text="Export CSV", command=self._export_watch_csv).pack(side="right", padx=6)
        left = ttk.Frame(self.watch_tab)
        left.pack(side="left", fill="y")
        columns = ("enabled", "value", "unit", "age")
        self.watch_tree = ttk.Treeview(left, columns=columns, show="tree headings", height=18)
        self.watch_tree.heading("#0", text="Variable")
        self.watch_tree.heading("enabled", text="Plot")
        self.watch_tree.heading("value", text="Value")
        self.watch_tree.heading("unit", text="Unit")
        self.watch_tree.heading("age", text="Age")
        self.watch_tree.column("#0", width=170)
        self.watch_tree.column("enabled", width=45, anchor="center")
        self.watch_tree.column("value", width=110, anchor="e")
        self.watch_tree.column("unit", width=80)
        self.watch_tree.column("age", width=70, anchor="e")
        self.watch_tree.pack(fill="both", expand=True)
        self.watch_tree.bind("<Double-1>", self._toggle_watch)
        for index, definition in enumerate(DEFAULT_WATCHES):
            item = self.watch_tree.insert("", "end", text=definition.label, values=("●" if index < 3 else "", "-", definition.unit, "-"))
            self.watch_rows[definition.path] = item
            self.watch_enabled[definition.path] = tk.BooleanVar(value=index < 3)
            self.watch_history[definition.path] = deque(maxlen=180)
        chart_frame = ttk.LabelFrame(self.watch_tab, text="Last 180 samples", padding=5)
        chart_frame.pack(side="left", fill="both", expand=True, padx=(10, 0))
        self.chart = LiveChart(chart_frame)
        self.chart.pack(fill="both", expand=True)

    def _build_events(self) -> None:
        toolbar = ttk.Frame(self.events_tab)
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Label(toolbar, text="Category").pack(side="left")
        self.event_category = tk.StringVar(value="all")
        ttk.Combobox(toolbar, textvariable=self.event_category, values=EVENT_CATEGORIES,
                     state="readonly", width=12).pack(side="left", padx=6)
        ttk.Button(toolbar, text="Refresh 32", command=self._refresh_events).pack(side="left")
        ttk.Button(toolbar, text="Read fault", command=lambda: self.send_command("fault")).pack(side="left", padx=6)
        ttk.Button(toolbar, text="Read version", command=lambda: self.send_command("version")).pack(side="left")
        ttk.Button(toolbar, text="Clear view", command=self._clear_events_faults).pack(side="right")
        ttk.Button(toolbar, text="Export", command=self._export_events_faults).pack(side="right", padx=6)
        event_pane = ttk.Panedwindow(self.events_tab, orient="horizontal")
        event_pane.pack(fill="both", expand=True)
        event_list = ttk.Frame(event_pane)
        event_detail = ttk.LabelFrame(event_pane, text="Selected event meaning", padding=6)
        event_pane.add(event_list, weight=3)
        event_pane.add(event_detail, weight=2)
        columns = ("pc_time", "category", "name", "summary", "tick", "seq")
        self.event_tree = ttk.Treeview(event_list, columns=columns, show="headings", height=13)
        headings = {"pc_time": "PC TIME", "category": "CATEGORY", "name": "EVENT",
                    "summary": "SUMMARY", "tick": "DEVICE ms", "seq": "SEQ"}
        for column in columns:
            self.event_tree.heading(column, text=headings[column])
        self.event_tree.column("pc_time", width=175)
        self.event_tree.column("category", width=90)
        self.event_tree.column("name", width=160)
        self.event_tree.column("summary", width=260)
        self.event_tree.column("tick", width=90, anchor="e")
        self.event_tree.column("seq", width=65, anchor="e")
        self.event_tree.pack(fill="both", expand=True)
        self.event_tree.bind("<<TreeviewSelect>>", self._show_event_detail)
        self.event_detail_text = ScrolledText(event_detail, width=38, height=12,
                                              font=("Segoe UI", 10), wrap="word")
        self.event_detail_text.pack(fill="both", expand=True)
        fault_frame = ttk.LabelFrame(self.events_tab, text="Fault analysis", padding=5)
        fault_frame.pack(fill="both", expand=True, pady=(10, 0))
        self.fault_text = ScrolledText(fault_frame, height=9, font=("Consolas", 10), wrap="word")
        self.fault_text.pack(fill="both", expand=True)

    def _build_console(self) -> None:
        command_frame = ttk.Frame(self.console_tab)
        command_frame.pack(fill="x", pady=(0, 7))
        ttk.Label(command_frame, text="Command", style="Status.TLabel").pack(side="left")
        self.command_entry = ttk.Entry(command_frame)
        self.command_entry.pack(side="left", fill="x", expand=True, padx=6)
        self.command_entry.bind("<Return>", lambda _event: self._send_console())
        self.command_entry.bind("<Up>", lambda _event: self._history(-1))
        self.command_entry.bind("<Down>", lambda _event: self._history(1))
        ttk.Button(command_frame, text="Send ↵", command=self._send_console).pack(side="left")
        ttk.Button(command_frame, text="Clear console", command=lambda: self.console.delete("1.0", "end")).pack(side="left", padx=(6, 0))
        self.console = ScrolledText(self.console_tab, bg="#0d1117", fg="#c9d1d9", insertbackground="white", font=("Consolas", 10), wrap="word")
        self.console.pack(fill="both", expand=True)

    def _build_controls(self) -> None:
        warning = ttk.Label(
            self.control_tab,
            text="Dangerous controls are enforced by firmware Admin authentication. "
                 "Confirm the gas line is safe before operating the valve.",
            foreground="#a40e26",
            wraplength=900,
        )
        warning.pack(fill="x", pady=(0, 10))
        login = ttk.LabelFrame(self.control_tab, text="Admin session", padding=10)
        login.pack(fill="x")
        self.admin_password = tk.StringVar()
        self.admin_state = tk.StringVar(value="Locked")
        ttk.Label(login, text="Password").pack(side="left")
        password_entry = ttk.Entry(login, textvariable=self.admin_password, show="●", width=30)
        password_entry.pack(side="left", padx=8)
        password_entry.bind("<Return>", lambda _event: self._admin_login())
        ttk.Button(login, text="Unlock", command=self._admin_login).pack(side="left")
        ttk.Button(login, text="Lock", command=lambda: self.send_command("admin logout")).pack(side="left", padx=6)
        ttk.Button(login, text="View network credentials",
                   command=lambda: self.send_command("config secrets")).pack(side="left", padx=6)
        ttk.Label(login, textvariable=self.admin_state, style="Status.TLabel").pack(side="right")
        actions = ttk.LabelFrame(self.control_tab, text="Board operations", padding=12)
        actions.pack(fill="x", pady=12)
        ttk.Button(actions, text="Valve → LEFT", style="Danger.TButton", command=lambda: self._confirm_control("control valve left confirm", "Move the 3-way valve to LEFT?" )).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        ttk.Button(actions, text="Valve → RIGHT", style="Danger.TButton", command=lambda: self._confirm_control("control valve right confirm", "Move the 3-way valve to RIGHT?" )).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(actions, text="Buzzer test", command=lambda: self._confirm_control("control buzzer 1000 confirm", "Sound the buzzer for 1 second?" )).grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        ttk.Button(actions, text="Panel lamp test", command=lambda: self._confirm_control("control lamps 2000 confirm", "Run the panel lamp test for 2 seconds?" )).grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(actions, text="Send Wi-Fi status", command=lambda: self._confirm_control("control send wifi confirm", "Send one Wi-Fi status packet?" )).grid(row=2, column=0, padx=5, pady=5, sticky="ew")
        ttk.Button(actions, text="Send Ethernet status", command=lambda: self._confirm_control("control send ethernet confirm", "Send one Ethernet status packet?" )).grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(actions, text="Reboot MCU", style="Danger.TButton", command=lambda: self._confirm_control("control reboot confirm", "Reboot the controller now?", phrase="REBOOT" )).grid(row=3, column=0, columnspan=2, padx=5, pady=(18, 5), sticky="ew")
        actions.columnconfigure(0, weight=1)
        actions.columnconfigure(1, weight=1)
        ttk.Label(
            self.control_tab,
            text="Configuration/EEPROM values are intentionally view-only in this release. "
                 "They remain editable through the validated front-panel menu so field diagnostics cannot silently alter calibration.",
            wraplength=900,
        ).pack(fill="x")

    def _build_settings(self) -> None:
        connection = ttk.LabelFrame(self.settings_tab, text="RTT connection", padding=10)
        connection.pack(fill="x")
        ttk.Label(connection, text="Host").grid(row=0, column=0, sticky="w")
        ttk.Entry(connection, textvariable=self.host, width=18).grid(row=0, column=1, padx=6)
        ttk.Label(connection, text="Port").grid(row=0, column=2, sticky="w")
        ttk.Entry(connection, textvariable=self.port, width=8).grid(row=0, column=3, padx=6)
        ttk.Label(connection, text="Telemetry interval (s)").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Spinbox(connection, from_=0.2, to=2.0, increment=0.1, textvariable=self.poll_interval, width=8).grid(row=1, column=1, sticky="w", padx=6, pady=(8, 0))
        ttk.Label(connection, text="Diagnostic interval (s)").grid(row=1, column=2, sticky="w", pady=(8, 0))
        ttk.Spinbox(connection, from_=0.5, to=10.0, increment=0.5, textvariable=self.slow_poll_interval, width=8).grid(row=1, column=3, sticky="w", padx=6, pady=(8, 0))
        ttk.Checkbutton(connection, text="Automatic polling", variable=self.auto_poll).grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))
        logging = ttk.LabelFrame(self.settings_tab, text="Session logging", padding=10)
        logging.pack(fill="x", pady=10)
        ttk.Entry(logging, textvariable=self.log_path).pack(side="left", fill="x", expand=True)
        ttk.Button(logging, text="Browse", command=self._browse_log).pack(side="left", padx=(6, 0))
        info = ttk.LabelFrame(self.settings_tab, text="Connection policy", padding=10)
        info.pack(fill="both", expand=True)
        ttk.Label(
            info,
            text="• OpenOCD hot-attaches through SWD without reset, halt, flash or program commands.\n"
                 "• The GUI reconnects after a board reboot and verifies fault symbols against the exact Build ID.\n"
                 "• Fast compact telemetry and slower diagnostics are polled separately; RTT drop reports automatically reduce the fast rate.\n"
                 "• Closing the GUI terminates only the OpenOCD process started by this GUI.",
            justify="left",
        ).pack(anchor="nw")

    def connect(self, start_openocd: bool = True) -> None:
        self.disconnect()
        if start_openocd:
            try:
                self.openocd.start()
            except (OSError, ValueError) as error:
                self._append_notice(f"OpenOCD start failed: {error}")
        log_path = Path(self.log_path.get()) if self.log_path.get().strip() else None
        self.session = RttSession(
            self.host.get(), int(self.port.get()), self.events, self.analyzer, log_path
        )
        self.session.start()

    def disconnect(self) -> None:
        if self.session is not None:
            self.session.send_immediate("admin logout")
            self.session.stop()
            self.session = None
        self.command_pending = False
        self.secret_capture_active = False
        self.secret_payload = {}
        self.admin_state.set("Locked")
        self._set_connection(False)

    def send_command(self, command: str, show_outbound: bool = True) -> None:
        if self.session is None:
            self._append_notice("Not connected")
            return
        if show_outbound:
            self._append_console(f"\n> {command}\n", "outbound")
        self.command_pending = True
        self.session.send(command)

    def _set_connection(self, connected: bool) -> None:
        self.connected = connected
        self.connection_text.set("Connected" if connected else "Disconnected")
        self.status_dot.delete("all")
        color = "#2da44e" if connected else "#cf222e"
        self.status_dot.create_oval(2, 2, 14, 14, fill=color, outline=color)

    def _append_console(self, text: str, tag: Optional[str] = None) -> None:
        if tag == "analysis":
            self.console.tag_configure("analysis", foreground="#58a6ff")
        elif tag == "notice":
            self.console.tag_configure("notice", foreground="#f0883e")
        elif tag == "outbound":
            self.console.tag_configure("outbound", foreground="#8b949e")
        self.console.insert("end", text, tag or "")
        self.console.see("end")

    def _append_notice(self, text: str) -> None:
        self._append_console(f"\n[GUI] {text}\n", "notice")

    def _drain_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "connection":
                    self._set_connection(bool(payload))
                    if payload:
                        self.send_command("snapshot", show_outbound=False)
                elif kind == "text":
                    self._process_text(str(payload))
                elif kind == "analysis":
                    message = str(payload)
                    self._append_console(f"\n{message}\n", "analysis")
                    self.fault_text.insert("end", message + "\n")
                    self.fault_text.see("end")
                elif kind == "notice":
                    self._append_notice(str(payload))
        except queue.Empty:
            pass
        self._refresh_dashboard()
        self._refresh_watch()
        self.after(60, self._drain_events)

    @staticmethod
    def _decode_hex_text(value: object) -> str:
        try:
            return bytes.fromhex(str(value)).decode("utf-8", errors="replace")
        except ValueError:
            return "<invalid encoding>"

    def _filter_secret_response(self, text: str) -> str:
        """Capture credentials for a modal and keep them out of the console."""
        self.secret_wire_buffer += text
        lines = self.secret_wire_buffer.splitlines(keepends=True)
        if lines and not lines[-1].endswith(("\n", "\r")):
            self.secret_wire_buffer = lines.pop()
        else:
            self.secret_wire_buffer = ""
        visible: list[str] = []
        for line in lines:
            clean = line.strip()
            if clean.startswith(PROMPT):
                clean = clean[len(PROMPT):].strip()
            if clean == "secrets_begin":
                self.secret_capture_active = True
                self.secret_payload = {}
            elif clean == "secrets_end":
                self.secret_capture_active = False
                station = self.secret_payload.get("secret_station", {})
                softap = self.secret_payload.get("secret_softap", {})
                messagebox.showinfo(
                    "Network credentials (Admin)",
                    "Station SSID: " + self._decode_hex_text(station.get("ssid_hex", "")) +
                    "\nStation password: " + self._decode_hex_text(station.get("password_hex", "")) +
                    "\n\nSoftAP SSID: " + self._decode_hex_text(softap.get("ssid_hex", "")) +
                    "\nSoftAP password: " + self._decode_hex_text(softap.get("password_hex", "")) +
                    "\n\nThis response was not written to the console or session log.",
                )
                self.secret_payload = {}
            elif self.secret_capture_active:
                namespace = line_namespace(clean)
                if namespace.startswith("secret_"):
                    self.secret_payload[namespace] = {
                        key: raw for key, raw in TOKEN_RE.findall(clean)
                    }
            else:
                visible.append(line)
        return "".join(visible)

    def _update_boot_anchor(self, device_now_ms: object, boot: object = None) -> None:
        if not isinstance(device_now_ms, (int, float)):
            return
        candidate = time.time() - float(device_now_ms) / 1000.0
        if self.boot_time_anchor is None or abs(candidate - self.boot_time_anchor) > 2.0:
            self.boot_time_anchor = candidate
        else:
            self.boot_time_anchor = self.boot_time_anchor * 0.9 + candidate * 0.1

        if isinstance(boot, int):
            self.boot_anchors[boot] = self.boot_time_anchor

    def _pc_time_for_tick(self, tick: int, boot: Optional[int] = None) -> str:
        anchor = self.boot_anchors.get(boot, self.boot_time_anchor) if boot is not None else self.boot_time_anchor
        if anchor is None:
            return datetime.now().astimezone().isoformat(timespec="milliseconds")
        return datetime.fromtimestamp(anchor + tick / 1000.0).astimezone().isoformat(timespec="milliseconds")

    def _add_event_line(self, line: str, match: re.Match[str]) -> None:
        tick_text, code_text, name, arg0, arg1 = match.groups()
        fields = parse_key_values(line)
        tick = int(tick_text)
        sequence = int(fields.get("seq", 0))
        category = str(fields.get("category", "UNKNOWN"))
        identity = (f"event-{self.event_response_boot}-{sequence}" if sequence else
                    f"event-{self.event_response_boot}-{tick_text}-{code_text}-{arg0}-{arg1}")
        if self.event_tree.exists(identity):
            return
        title, argument_help = EVENT_DETAILS.get(name, ("Firmware diagnostic event", "See firmware release notes for argument semantics"))
        record = {
            "pc_time": self._pc_time_for_tick(tick, self.event_response_boot),
            "pc_time_basis": "device tick synchronized to PC",
            "device_tick_ms": tick,
            "boot": self.event_response_boot, "sequence": sequence,
            "code": int(code_text), "category": category,
            "name": name, "summary": title, "argument0": arg0, "argument1": arg1,
            "meaning": argument_help,
        }
        self.event_records.append(record)
        self.event_record_by_iid[identity] = record
        self.event_tree.insert("", 0, iid=identity, values=(record["pc_time"], category,
            name, title, tick, sequence))

    def _process_text(self, text: str) -> None:
        prompt_stream = self.prompt_probe + text
        if PROMPT in prompt_stream:
            self.command_pending = False
        self.prompt_probe = prompt_stream[-(len(PROMPT) - 1):]
        text = self._filter_secret_response(text)
        if not text:
            return
        self._append_console(text)
        self.raw_buffer += text.replace(PROMPT, "")
        lines = self.raw_buffer.splitlines(keepends=True)
        if lines and not lines[-1].endswith(("\n", "\r")):
            self.raw_buffer = lines.pop()
        else:
            self.raw_buffer = ""
        for raw in lines:
            line = raw.strip()
            if not line:
                continue
            self.telemetry.update_line(line)
            values = parse_key_values(line)
            if line.startswith("telemetry "):
                self._update_boot_anchor(values.get("now_ms"), values.get("boot"))
                pressure = [values.get("left_pressure_tenths"),
                            values.get("right_pressure_tenths"),
                            values.get("out_pressure_tenths")]
                adc = [values.get("left_adc"), values.get("right_adc"), values.get("out_adc")]
                if all(isinstance(item, int) for item in pressure + adc):
                    self.telemetry.update_line(
                        f"sensor pressure_tenths=[{pressure[0]},{pressure[1]},{pressure[2]}] "
                        f"dma_raw=[{adc[0]},{adc[1]},{adc[2]}]"
                    )
            elif line.startswith("events "):
                self._update_boot_anchor(values.get("device_now_ms"), values.get("boot"))
                if isinstance(values.get("boot"), int):
                    self.event_response_boot = int(values["boot"])
            event_match = EVENT_RE.search(line)
            if event_match:
                self._add_event_line(line, event_match)
            if line.startswith("fault "):
                fault_boot = values.get("fault_boot")
                snapshot_tick = values.get("fault_snapshot_tick")
                if isinstance(fault_boot, int) and isinstance(snapshot_tick, int) and fault_boot in self.boot_anchors:
                    fault_pc_time = self._pc_time_for_tick(snapshot_tick, fault_boot)
                    time_basis = "fault tick synchronized while PC was connected"
                else:
                    fault_pc_time = datetime.now().astimezone().isoformat(timespec="milliseconds")
                    time_basis = "PC observation time (fault boot was not synchronized)"
                record = {"pc_time": fault_pc_time, "pc_time_basis": time_basis,
                          "data": values, "raw": line}
                fault_identity = (values.get("fault_boot"), values.get("count"),
                                  values.get("type"), values.get("fault_build_id"))
                if fault_identity != self.last_fault_identity:
                    self.last_fault_identity = fault_identity
                    self.fault_records.append(record)
                    self.fault_text.insert("end", f"[{record['pc_time']}] ({record['pc_time_basis']})\n")
                    self.fault_text.insert("end", line + "\n")
                    self.fault_text.see("end")
            if line.startswith("OK admin unlocked"):
                self.admin_state.set("Unlocked (5 min)")
                self.admin_password.set("")
            elif line.startswith("OK admin locked") or line.startswith("ERR admin"):
                self.admin_state.set("Locked")
            elif line.startswith("admin "):
                locked = parse_key_values(line).get("locked", 1)
                self.admin_state.set("Locked" if locked else "Unlocked")

    def _poll_tick(self) -> None:
        now = time.monotonic()
        drops = self.telemetry.get("stats.output_drops", 0)
        if isinstance(drops, int) and drops > self.last_output_drops:
            self.effective_fast_interval = min(max(self.effective_fast_interval * 1.5, 0.3), 2.0)
            self._append_notice(
                f"RTT output drops increased ({self.last_output_drops} → {drops}); "
                f"telemetry interval backed off to {self.effective_fast_interval:.2f}s"
            )
            self.last_output_drops = drops
        requested_fast = max(0.2, self.poll_interval.get())
        if drops == self.last_output_drops and self.effective_fast_interval > requested_fast:
            self.effective_fast_interval = max(requested_fast, self.effective_fast_interval - 0.01)
        if self.connected and self.auto_poll.get() and not self.command_pending:
            if now - self.last_slow_poll >= max(0.5, self.slow_poll_interval.get()):
                self.send_command(self.SLOW_POLL_COMMANDS[self.poll_index], show_outbound=False)
                self.poll_index = (self.poll_index + 1) % len(self.SLOW_POLL_COMMANDS)
                self.last_slow_poll = now
            elif now - self.last_fast_poll >= self.effective_fast_interval:
                self.send_command("telemetry", show_outbound=False)
                self.last_fast_poll = now
        self.after(100, self._poll_tick)

    def _refresh_dashboard(self) -> None:
        get = self.telemetry.get
        service = get("telemetry.service", get("status.service"))
        self.card_vars["service"].set(str(service))
        self.card_vars["valve"].set(f"{get('valve.output')} / {get('valve.feedback')}")
        alarm = get("telemetry.alarm", get("status.alarm"))
        self.card_vars["alarm"].set(f"0x{alarm:08X}" if isinstance(alarm, int) else str(alarm))
        for key, index in (("left", 0), ("right", 1), ("out", 2)):
            fast_path = {0: "telemetry.left_pressure_tenths",
                         1: "telemetry.right_pressure_tenths",
                         2: "telemetry.out_pressure_tenths"}[index]
            value = get(fast_path, get(f"sensor.pressure_tenths[{index}]"))
            self.card_vars[key].set(f"{value / 10.0:.1f}" if isinstance(value, (int, float)) else str(value))
        self.card_vars["left_gas"].set(str(get("telemetry.left_gas")))
        self.card_vars["right_gas"].set(str(get("telemetry.right_gas")))
        for side in ("left", "right"):
            seconds = get(f"telemetry_eco.{side}_remaining_s")
            if isinstance(seconds, int):
                eco_text = f"{seconds // 60:02d}:{seconds % 60:02d}"
            else:
                eco_text = str(seconds)
            self.card_vars[f"{side}_eco"].set(eco_text)
        self.card_vars["wifi"].set("UP" if get("wifi.link", 0) == 1 else "DOWN")
        self.card_vars["ethernet"].set("UP" if get("ethernet.phy", 0) == 1 else "DOWN")
        health = (
            ("Valve feedback", "CHECK" if get("status.check", 0) else "OK", f"service={get('status.service')}, check={get('status.check')}"),
            ("Pressure ADC", "OK" if get("status.sensor_ready", 0) else "STARTING", f"raw={get('sensor.dma_raw')}"),
            ("Wi-Fi", "UP" if get("wifi.link", 0) else "DOWN", f"configured={get('wifi.configured')}, connecting={get('wifi.connecting')}"),
            ("Ethernet", "UP" if get("ethernet.phy", 0) else "DOWN", f"ip={get('ethernet.ip')}"),
            ("RS485", "OK", f"frames={get('rs485.frames')}, crc_bad={get('rs485.crc_bad')}"),
            ("RTOS", "OK" if get("status.task_stall", 0) == 0 else "STALL", f"stall={get('status.task_stall')}"),
        )
        for item in self.health_tree.get_children():
            self.health_tree.delete(item)
        for name, state, detail in health:
            self.health_tree.insert("", "end", values=(name, state, detail))
        snapshot = self.telemetry.snapshot()
        for item in self.detail_tree.get_children():
            self.detail_tree.delete(item)
        for path in sorted(snapshot):
            value = snapshot[path]
            if "[" in path:
                continue
            age = time.time() - self.telemetry.updated(path)
            self.detail_tree.insert("", "end", text=path, values=(str(value), f"{age:.1f}s"))

    @staticmethod
    def _display_watch(definition: WatchDefinition, raw: object) -> str:
        if isinstance(raw, (int, float)):
            value = raw / definition.divisor
            return f"{value:.1f}" if definition.divisor != 1.0 else str(raw)
        return str(raw)

    def _refresh_watch(self) -> None:
        timestamp = time.time()
        for definition in DEFAULT_WATCHES:
            raw = self.telemetry.get(definition.path)
            updated = self.telemetry.updated(definition.path)
            age = timestamp - updated if updated else 0.0
            enabled = self.watch_enabled[definition.path].get()
            item = self.watch_rows[definition.path]
            self.watch_tree.item(item, values=("●" if enabled else "", self._display_watch(definition, raw), definition.unit, f"{age:.1f}s" if updated else "-"))
            if enabled and isinstance(raw, (int, float)) and updated:
                history = self.watch_history[definition.path]
                value = float(raw) / definition.divisor
                if not history or history[-1][0] != updated:
                    history.append((updated, value))
                    self.chart.add(definition.label, value, updated)

    def _toggle_watch(self, event: tk.Event) -> None:
        item = self.watch_tree.identify_row(event.y)
        for path, row in self.watch_rows.items():
            if row == item:
                self.watch_enabled[path].set(not self.watch_enabled[path].get())
                if not self.watch_enabled[path].get():
                    self.chart.series.pop(next(d.label for d in DEFAULT_WATCHES if d.path == path), None)
                    self.chart.redraw()
                break

    def _clear_watch_chart(self) -> None:
        for history in self.watch_history.values():
            history.clear()
        self.chart.clear()

    def _export_watch_csv(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with Path(path).open("w", newline="", encoding="utf-8-sig") as output:
            writer = csv.writer(output)
            writer.writerow(("timestamp", "variable", "path", "value", "unit"))
            for definition in DEFAULT_WATCHES:
                for timestamp, value in self.watch_history[definition.path]:
                    writer.writerow((datetime.fromtimestamp(timestamp).isoformat(), definition.label, definition.path, value, definition.unit))

    def _refresh_events(self) -> None:
        self.send_command(f"events {self.event_category.get()} 32")

    def _show_event_detail(self, _event: object = None) -> None:
        selection = self.event_tree.selection()
        if not selection:
            return
        record = self.event_record_by_iid.get(selection[0])
        if record is None:
            return
        detail = (
            f"PC time: {record['pc_time']}\n"
            f"Category: {record['category']}\n"
            f"Boot: {record['boot']}\n"
            f"Event: {record['name']} (code {record['code']})\n"
            f"Device tick: {record['device_tick_ms']} ms\n"
            f"Sequence: {record['sequence']}\n\n"
            f"Meaning\n{record['summary']}\n\n"
            f"Arguments\n{record['meaning']}\n"
            f"arg0={record['argument0']}\narg1={record['argument1']}"
        )
        self.event_detail_text.delete("1.0", "end")
        self.event_detail_text.insert("1.0", detail)

    def _clear_events_faults(self) -> None:
        if not messagebox.askyesno(
            "Clear diagnostic view",
            "Clear events and faults shown on this PC?\n\n"
            "The retained records inside the controller will not be erased.",
        ):
            return
        for item in self.event_tree.get_children():
            self.event_tree.delete(item)
        self.event_records.clear()
        self.event_record_by_iid.clear()
        self.fault_records.clear()
        self.last_fault_identity = None
        self.event_detail_text.delete("1.0", "end")
        self.fault_text.delete("1.0", "end")

    def _export_events_faults(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv")],
        )
        if not path:
            return
        output_path = Path(path)
        if output_path.suffix.lower() == ".csv":
            with output_path.open("w", newline="", encoding="utf-8-sig") as output:
                writer = csv.writer(output)
                writer.writerow(("record_type", "pc_time", "boot", "category", "name", "summary",
                                 "device_tick_ms", "sequence", "arg0", "arg1", "details"))
                for event in self.event_records:
                    writer.writerow(("event", event["pc_time"], event["boot"], event["category"], event["name"],
                                     event["summary"], event["device_tick_ms"], event["sequence"],
                                     event["argument0"], event["argument1"], event["meaning"]))
                for fault in self.fault_records:
                    writer.writerow(("fault", fault["pc_time"], fault["data"].get("boot", ""), "FAULT", "FAULT", fault["raw"],
                                     fault["data"].get("fault_snapshot_tick", ""), "", "", "", fault["pc_time_basis"]))
        else:
            payload = {"exported_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                       "events": self.event_records, "faults": self.fault_records}
            output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        self._append_notice(f"Diagnostics exported: {output_path}")

    def _send_console(self) -> None:
        command = self.command_entry.get().strip()
        self.command_entry.delete(0, "end")
        if not command:
            return
        if command.startswith("admin login "):
            messagebox.showwarning("Protected input", "Use the password field on Admin Controls so the password is not shown or logged.")
            return
        self.history.append(command)
        self.history_index = len(self.history)
        self.send_command(command)

    def _history(self, delta: int) -> str:
        if not self.history:
            return "break"
        self.history_index = min(max(self.history_index + delta, 0), len(self.history))
        value = self.history[self.history_index] if self.history_index < len(self.history) else ""
        self.command_entry.delete(0, "end")
        self.command_entry.insert(0, value)
        return "break"

    def _admin_login(self) -> None:
        password = self.admin_password.get()
        if not password:
            messagebox.showwarning("Admin", "Enter the Admin password.")
            return
        credential = hashlib.sha256(ADMIN_HASH_PREFIX + password.encode("utf-8")).hexdigest()
        self.send_command(f"admin login {credential}", show_outbound=False)
        password = ""
        credential = ""
        self._append_notice("Admin authentication sent (password hidden from GUI log)")

    def _confirm_control(self, command: str, prompt: str, phrase: Optional[str] = None) -> None:
        if phrase is not None:
            entered = simpledialog.askstring("Confirm operation", f"{prompt}\n\nType {phrase} to continue:")
            if entered != phrase:
                return
        elif not messagebox.askyesno("Confirm operation", prompt, icon="warning"):
            return
        self.send_command(command)

    def _browse_log(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("Log", "*.log"), ("All", "*.*")])
        if path:
            self.log_path.set(path)

    def _close(self) -> None:
        self.disconnect()
        self.openocd.stop()
        self.destroy()


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GasChanger RTT GUI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9090)
    parser.add_argument("--poll-interval", type=float, default=0.25)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--elf", type=Path)
    parser.add_argument("--symbols", type=Path)
    parser.add_argument("--symbol-cache", type=Path, default=DEFAULT_SYMBOL_CACHE)
    parser.add_argument("--symbol-url", default=os.environ.get("GASCHANGER_SYMBOL_URL", DEFAULT_SYMBOL_URL))
    parser.add_argument("--public-key", type=Path, default=DEFAULT_PUBLIC_KEY)
    parser.add_argument("--no-openocd", action="store_true", help="Connect to an already running RTT TCP server")
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    if args.elf is not None and args.symbols is not None:
        print("--elf and --symbols are mutually exclusive", file=sys.stderr)
        return 2
    app = GasChangerGui(args)
    if args.smoke_test:
        app.withdraw()
        app.after(100, app.destroy)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
