import sys
import re
import ntpath
import logging
from collections import defaultdict, deque, namedtuple
from datetime import datetime
from difflib import SequenceMatcher

import os
import psutil
from PySide6.QtCore import Qt, QTimer, QThread, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QTextEdit, QPlainTextEdit
)

APP_NAME = "Shadow Trace"
SAMPLE_INTERVAL_MS = 2000
SHUTDOWN_WAIT_MS = 8000

# ---- CPU ------------------------------------------------------------------
# All CPU numbers in this app are "% of TOTAL CPU capacity" (all logical cores),
# the same scale Task Manager uses. 100% = every core fully busy.
CPU_COUNT = psutil.cpu_count() or 1
CPU_HIGH_THRESHOLD = 80.0   # % of total capacity
CPU_HIGH_SAMPLES = 3        # consecutive samples above the threshold

# ---- Memory ---------------------------------------------------------------
MEMORY_HIGH_PERCENT = 20.0  # % of total physical RAM

# ---- Alerts ---------------------------------------------------------------
MAX_ALERTS = 500            # bounded history kept in memory / shown on screen
ALERT_MIN_SCORE = 25        # lower-scored findings are shown in the table only

# ---- Risk scoring (indicators are separate from their weights) -------------
INDICATOR_WEIGHTS = {
    "CORE_NAME_WRONG_PATH": 50,
    "LOOKALIKE_NAME": 30,
    "USER_WRITABLE_PATH": 30,
    "DOUBLE_EXTENSION": 25,
    "SUSTAINED_CPU": 25,
    "HIGH_MEMORY": 15,
    "APPDATA_ROAMING_PATH": 15,
    "PATH_UNAVAILABLE": 5,
}
RISK_LEVELS = ((80, "CRITICAL"), (50, "HIGH"), (25, "MEDIUM"), (0, "LOW"))
Indicator = namedtuple("Indicator", "code label")

logging.basicConfig(
    filename="shadow_trace.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

# ---- Process detection data ------------------------------------------------
WINDOWS_CORE_NAMES = {
    "svchost.exe", "lsass.exe", "services.exe", "winlogon.exe",
    "csrss.exe", "smss.exe", "wininit.exe", "spoolsv.exe",
}
# Processes that legitimately have no readable executable path.
NO_PATH_EXPECTED = {
    "system idle process", "system", "registry", "memory compression",
    "secure system", "vmmem", "vmmemwsl",
}
WINDIR = os.environ.get("WINDIR", r"C:\Windows")
SYSTEM32 = ntpath.normcase(ntpath.normpath(ntpath.join(WINDIR, "System32")))

TEMP_MARKERS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\",
                "\\downloads\\", "\\users\\public\\")
ROAMING_MARKERS = ("\\appdata\\roaming\\",)
DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|zip|rar)\.(exe|scr|com)$"
)


def human_bytes(value):
    value = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _is_under(path, folder):
    return path.startswith(folder.rstrip("\\") + "\\")


def _lookalike_of(basename):
    """Return the core name this resembles (but is not), else None."""
    if basename in WINDOWS_CORE_NAMES or len(basename) < 8:
        return None
    for core in WINDOWS_CORE_NAMES:
        if SequenceMatcher(None, basename, core).ratio() >= 0.88:
            return core
    return None


def process_indicators(name, exe):
    """Static (path/name based) indicators. These are hints, not malware verdicts."""
    found = []
    basename = (name or "").lower()
    path = ntpath.normcase(ntpath.normpath(exe)) if exe else ""
    padded = path + "\\" if path else ""

    if path:
        if any(m in padded for m in TEMP_MARKERS):
            found.append(Indicator("USER_WRITABLE_PATH",
                                   "Runs from a temp/downloads/public folder"))
        elif any(m in padded for m in ROAMING_MARKERS):
            found.append(Indicator("APPDATA_ROAMING_PATH",
                                   "Runs from AppData\\Roaming (common for malware, but also many legit apps)"))

        if basename in WINDOWS_CORE_NAMES and not _is_under(path, SYSTEM32):
            found.append(Indicator("CORE_NAME_WRONG_PATH",
                                   f"Windows core-process name '{basename}' outside System32"))
    elif basename not in NO_PATH_EXPECTED:
        found.append(Indicator("PATH_UNAVAILABLE",
                               "Executable path unavailable (may be access-restricted)"))

    lookalike = _lookalike_of(basename)
    if lookalike:
        found.append(Indicator("LOOKALIKE_NAME",
                               f"Name '{basename}' closely resembles '{lookalike}'"))

    if DOUBLE_EXT_RE.search(basename):
        found.append(Indicator("DOUBLE_EXTENSION",
                               "Document-style double extension (e.g. file.pdf.exe)"))
    return found


def evaluate_risk(indicators):
    """Turn indicators into (score, level, [(weight, label), ...])."""
    breakdown = [(INDICATOR_WEIGHTS.get(i.code, 0), i.label) for i in indicators]
    score = min(sum(w for w, _ in breakdown), 100)
    level = next(name for floor, name in RISK_LEVELS if score >= floor)
    return score, level, breakdown


def format_breakdown(breakdown, indent="  "):
    if not breakdown:
        return f"{indent}(no indicators)"
    return "\n".join(f"{indent}+{w:<3} {label}" for w, label in breakdown)


class ProcessScannerThread(QThread):
    """Background scanner. Reuses psutil.Process objects so cpu_percent is accurate.
    Checks for an interruption request so the app can shut down cleanly."""
    scan_finished = Signal(list)

    def __init__(self, procs_cache, static_cache, parent=None):
        super().__init__(parent)
        self.procs_cache = procs_cache    # pid -> psutil.Process
        self.static_cache = static_cache  # pid -> (name, exe, ppid, create_time, indicators)

    def run(self):
        rows = []
        try:
            total_ram = psutil.virtual_memory().total or 1
            current = {}
            for p in psutil.process_iter():
                if self.isInterruptionRequested():
                    return
                cached = self.procs_cache.get(p.pid)
                if cached is not None and cached == p:   # same process (pid not reused)
                    current[p.pid] = cached
                else:
                    current[p.pid] = p
                    self.static_cache.pop(p.pid, None)

            self.procs_cache.clear()
            self.procs_cache.update(current)
            for pid in list(self.static_cache):
                if pid not in current:
                    del self.static_cache[pid]

            for pid, proc in current.items():
                if self.isInterruptionRequested():
                    return
                try:
                    with proc.oneshot():
                        static = self.static_cache.get(pid)
                        if static is None:
                            name = proc.name() or "(unknown)"
                            try:
                                exe = proc.exe() or ""
                            except (psutil.AccessDenied, OSError):
                                exe = ""
                            static = (name, exe, proc.ppid(), proc.create_time(),
                                      tuple(process_indicators(name, exe)))
                            self.static_cache[pid] = static
                        name, exe, ppid, create_time, static_ind = static
                        rss = proc.memory_info().rss
                        # share of TOTAL CPU capacity (psutil reports per-core scale)
                        cpu = min(proc.cpu_percent(None) / CPU_COUNT, 100.0)

                    rows.append({
                        "pid": pid, "name": name, "cpu": cpu, "rss": rss,
                        "ram_percent": (rss / total_ram) * 100,
                        "exe": exe, "indicators": list(static_ind),
                        "ppid": ppid, "create_time": create_time,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied,
                        psutil.ZombieProcess, OSError):
                    continue
                except Exception:
                    logging.exception("process read failed")
        except Exception:
            logging.exception("scan thread failed")
        if not self.isInterruptionRequested():
            self.scan_finished.emit(rows)


class ShadowTrace(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Shadow Trace — Windows Endpoint Monitor")
        self.resize(1250, 760)

        self.cpu_streak = defaultdict(int)       # (pid, create_time) -> consecutive high samples
        self.active_codes = {}                   # (pid, create_time) -> set of indicator codes now active
        self.alert_history = deque(maxlen=MAX_ALERTS)
        self.alert_total = 0
        self.last_process_snapshot = {}
        self.scanner_thread = None
        self.procs_cache = {}
        self.static_cache = {}
        self._closing = False

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        heading = QHBoxLayout()
        title = QLabel("Shadow Trace")
        title.setStyleSheet("font-size: 24px; font-weight: 700;")
        self.status_label = QLabel("Starting monitor…")
        self.status_label.setStyleSheet("color: #64748b;")
        self.refresh_button = QPushButton("Scan now")
        self.refresh_button.clicked.connect(self.scan)
        heading.addWidget(title)
        heading.addStretch()
        heading.addWidget(self.status_label)
        heading.addWidget(self.refresh_button)
        layout.addLayout(heading)

        info = QLabel(
            f"Alerts-only mode · Samples every {SAMPLE_INTERVAL_MS // 1000} seconds · "
            f"CPU % = share of total CPU capacity ({CPU_COUNT} logical cores) · "
            "Heuristics are indicators, not proof of malware"
        )
        info.setWordWrap(True)
        info.setStyleSheet("padding: 10px; background: #172033; color: #e2e8f0; border-radius: 6px;")
        layout.addWidget(info)

        self.summary_label = QLabel("Processes: —    Alerts: —")
        self.summary_label.setStyleSheet("font-size: 14px; font-weight: 600;")
        layout.addWidget(self.summary_label)

        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter, 1)

        process_panel = QWidget()
        process_layout = QVBoxLayout(process_panel)
        process_layout.setContentsMargins(0, 0, 0, 0)
        process_layout.addWidget(QLabel("Running processes"))
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["PID", "Process", "CPU % (total)", "RAM", "RAM %", "Risk", "Executable path"]
        )
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(False)  # rows are pre-sorted by risk score
        self.table.verticalHeader().setVisible(False)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        for col, w in ((0, 70), (1, 200), (2, 100), (3, 90), (4, 70), (5, 110)):
            self.table.setColumnWidth(col, w)
        self.table.itemSelectionChanged.connect(self.show_selected_process)
        process_layout.addWidget(self.table)
        splitter.addWidget(process_panel)

        # Bottom: alert history (left) + selected-process details (right)
        bottom = QSplitter(Qt.Orientation.Horizontal)

        alert_panel = QWidget()
        alert_layout = QVBoxLayout(alert_panel)
        alert_layout.setContentsMargins(0, 0, 0, 0)
        alert_layout.addWidget(QLabel(f"Alert history (newest first, last {MAX_ALERTS})"))
        self.alert_view = QPlainTextEdit()
        self.alert_view.setReadOnly(True)
        self.alert_view.setPlaceholderText("No alerts yet.")
        alert_layout.addWidget(self.alert_view)
        bottom.addWidget(alert_panel)

        details_panel = QWidget()
        details_layout = QVBoxLayout(details_panel)
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.addWidget(QLabel("Process details"))
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a process to see its indicators and score breakdown.")
        details_layout.addWidget(self.details)
        bottom.addWidget(details_panel)

        bottom.setSizes([620, 620])
        splitter.addWidget(bottom)
        splitter.setSizes([470, 220])

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.scan)
        self.timer.start(SAMPLE_INTERVAL_MS)
        QTimer.singleShot(300, self.scan)

    # ---- scanning ----------------------------------------------------------
    def scan(self):
        if self._closing:
            return
        if self.scanner_thread is not None and self.scanner_thread.isRunning():
            return
        self.status_label.setText("Scanning...")
        thread = ProcessScannerThread(self.procs_cache, self.static_cache, self)
        thread.scan_finished.connect(self.handle_scan_results)
        thread.finished.connect(self._on_thread_finished)
        self.scanner_thread = thread
        thread.start()

    def _on_thread_finished(self):
        thread = self.sender()
        if thread is self.scanner_thread:
            self.scanner_thread = None
        if thread is not None:
            thread.deleteLater()

    def handle_scan_results(self, raw_rows):
        if self._closing:
            return
        try:
            live_keys = set()
            new_alerts = []
            processed_rows = []

            for data in raw_rows:
                pid = data["pid"]
                cpu = data["cpu"]
                ram_percent = data["ram_percent"]
                indicators = list(data["indicators"])
                key = (pid, data["create_time"])
                live_keys.add(key)

                # dynamic indicators
                if cpu >= CPU_HIGH_THRESHOLD:
                    self.cpu_streak[key] += 1
                else:
                    self.cpu_streak[key] = 0
                if self.cpu_streak[key] >= CPU_HIGH_SAMPLES:
                    indicators.append(Indicator(
                        "SUSTAINED_CPU",
                        f"Sustained high CPU ({CPU_HIGH_THRESHOLD:.0f}%+ of total capacity "
                        f"for {self.cpu_streak[key]} samples)"))
                if ram_percent >= MEMORY_HIGH_PERCENT:
                    indicators.append(Indicator(
                        "HIGH_MEMORY",
                        f"High memory use ({ram_percent:.1f}% of physical RAM)"))

                score, risk, breakdown = evaluate_risk(indicators)

                processed_rows.append({
                    "pid": pid, "name": data["name"], "cpu": cpu, "rss": data["rss"],
                    "ram_percent": ram_percent, "risk": risk, "score": score,
                    "breakdown": breakdown, "exe": data["exe"], "ppid": data["ppid"],
                })

                # Alert only when an indicator becomes newly active for this process.
                # Dedup keys on indicator CODES (not text), so changing CPU numbers
                # don't re-trigger; a cleared indicator can alert again if it returns.
                codes = {i.code for i in indicators}
                newly_active = codes - self.active_codes.get(key, set())
                self.active_codes[key] = codes
                if newly_active and score >= ALERT_MIN_SCORE:
                    new_alerts.append((risk, score, pid, data["name"], data["exe"], breakdown))

            # prune state of processes that no longer exist
            self.cpu_streak = defaultdict(int, {
                k: v for k, v in self.cpu_streak.items() if k in live_keys})
            self.active_codes = {k: v for k, v in self.active_codes.items() if k in live_keys}

            processed_rows.sort(key=lambda r: (r["score"], r["cpu"], r["ram_percent"]), reverse=True)
            self.update_table(processed_rows)
            self.last_process_snapshot = {r["pid"]: r for r in processed_rows}

            for risk, score, pid, name, exe, breakdown in new_alerts:
                self.record_alert(risk, score, pid, name, exe, breakdown)
            if new_alerts:
                self.alert_view.setPlainText("\n\n".join(reversed(self.alert_history)))

            self.summary_label.setText(
                f"Processes: {len(processed_rows)}    Alerts this session: {self.alert_total}"
            )
            self.status_label.setText(f"Last scan: {datetime.now().strftime('%H:%M:%S')}")
        except Exception as exc:
            logging.exception("Scan processing failed")
            self.status_label.setText(f"Scan error: {exc}")

    def record_alert(self, risk, score, pid, name, exe, breakdown):
        message = (
            f"[{datetime.now().strftime('%H:%M:%S')}] [{risk}] PID {pid} — {name} (score {score}/100)\n"
            f"  Path: {exe or 'Unavailable'}\n"
            f"{format_breakdown(breakdown)}"
        )
        self.alert_history.append(message)   # deque drops the oldest beyond MAX_ALERTS
        self.alert_total += 1
        logging.warning(message.replace("\n", " | "))

    # ---- UI ----------------------------------------------------------------
    def update_table(self, rows):
        selected_pid = None
        current_row = self.table.currentRow()
        if current_row >= 0 and self.table.item(current_row, 0):
            try:
                selected_pid = int(self.table.item(current_row, 0).text())
            except ValueError:
                pass

        colors = {"CRITICAL": "#fecaca", "HIGH": "#fed7aa", "MEDIUM": "#fef08a"}

        self.table.blockSignals(True)
        self.table.setUpdatesEnabled(False)
        try:
            self.table.setRowCount(len(rows))
            reselect = -1
            for row_index, data in enumerate(rows):
                values = [
                    str(data["pid"]), data["name"], f'{data["cpu"]:.1f}',
                    human_bytes(data["rss"]), f'{data["ram_percent"]:.1f}%',
                    f'{data["risk"]} ({data["score"]})', data["exe"] or "(unavailable)"
                ]
                tooltip = format_breakdown(data["breakdown"], indent="") if data["breakdown"] else ""
                for col, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    if col == 5:
                        color = colors.get(data["risk"])
                        if color:
                            item.setBackground(QColor(color))
                            item.setForeground(QColor("#111827"))
                        if tooltip:
                            item.setToolTip(tooltip)
                    self.table.setItem(row_index, col, item)
                if data["pid"] == selected_pid:
                    reselect = row_index
            if reselect >= 0:
                self.table.selectRow(reselect)
        finally:
            self.table.setUpdatesEnabled(True)
            self.table.blockSignals(False)

    def show_selected_process(self):
        row = self.table.currentRow()
        if row < 0 or not self.table.item(row, 0):
            return
        try:
            pid = int(self.table.item(row, 0).text())
        except ValueError:
            return
        data = self.last_process_snapshot.get(pid)
        if not data:
            return
        self.details.setPlainText(
            f'Process: {data["name"]}\nPID: {pid}\nParent PID: {data["ppid"]}\n'
            f'CPU: {data["cpu"]:.1f}% of total capacity\n'
            f'RAM: {human_bytes(data["rss"])} ({data["ram_percent"]:.1f}%)\n'
            f'Executable: {data["exe"] or "Unavailable"}\n\n'
            f'Risk: {data["risk"]} — score {data["score"]}/100\n'
            "Score breakdown:\n" + format_breakdown(data["breakdown"]) +
            "\n\nInterpretation: these are heuristic signals only, not proof of malware. "
            "Verify file origin, digital signature, parent process, and endpoint "
            "security results before drawing a conclusion."
        )

    # ---- shutdown ----------------------------------------------------------
    def closeEvent(self, event):
        self._closing = True
        self.timer.stop()
        thread = self.scanner_thread
        if thread is not None and thread.isRunning():
            thread.requestInterruption()
            if not thread.wait(SHUTDOWN_WAIT_MS):
                # Never destroy a running QThread: hide the window and quit
                # only once the thread has really finished.
                logging.warning("Scanner thread still running at shutdown; deferring exit")
                thread.finished.connect(QApplication.instance().quit)
                self.hide()
                event.ignore()
                return
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = ShadowTrace()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()