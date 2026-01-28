"""Main GUI window (PySide6).

The GUI follows the user's specification:
- Network CIDR input + Calculate (ipaddress validation)
- Start/Stop scan with multithreaded subprocess pings
- Options: fqdn / arp / vendor / show only alive
- Search across all table columns
- Save/Load to SQLite (1-N)
- Right-click a row -> Re-scan (single IP)
"""

from __future__ import annotations

import datetime as _dt
import threading
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import QObject, Signal, Qt
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QSpinBox, QCheckBox, QFileDialog, QTableView, QHeaderView,
    QMenu, QInputDialog
)

from lib.i18n import I18N
from lib.netcalc import parse_network, NetInfo
from lib.scanner import ScannerEngine, HostResult
from lib import db as dbmod

from .models import HostTableModel, HostProxyModel, COL_IP


class ScanWorker(QObject):
    host = Signal(object)          # HostResult
    progress = Signal(int, int)    # done, total
    state = Signal(str)            # state text
    finished = Signal()
    stopped = Signal()

    def __init__(self, engine: ScannerEngine, ips: List[str]):
        super().__init__()
        self.engine = engine
        self.ips = ips

    def run(self) -> None:
        def on_host(res: HostResult):
            self.host.emit(res)

        def on_progress(done: int, total: int):
            self.progress.emit(done, total)

        def on_state(s: str):
            self.state.emit(s)

        self.engine.scan_many(self.ips, on_host=on_host, on_progress=on_progress, on_state=on_state)

        if self.engine.is_stopped():
            self.stopped.emit()
        else:
            self.finished.emit()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.base_dir = Path(__file__).resolve().parents[1]
        self.i18n = I18N(self.base_dir)

        self.setWindowTitle(self.i18n.tr("app_title"))
        self.resize(1100, 650)

        self.net_info: Optional[NetInfo] = None
        self.engine: Optional[ScannerEngine] = None
        self.worker: Optional[ScanWorker] = None
        self.worker_thread: Optional[threading.Thread] = None

        self.scan_running = False
        self.scan_started_at = ""
        self.scan_ended_at = ""

        self._build_ui()
        self._connect_signals()

        # Default: sorting enabled with numeric IP sort
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.AscendingOrder)

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        main = QVBoxLayout(root)

        # Row A: Title
        row_a = QHBoxLayout()
        row_a.addWidget(QLabel(self.i18n.tr("title")))
        self.title_edit = QLineEdit()
        row_a.addWidget(self.title_edit, 1)
        main.addLayout(row_a)

        # Row B: Network + Calculate
        row_b = QHBoxLayout()
        row_b.addWidget(QLabel(self.i18n.tr("ethernet")))
        row_b.addWidget(QLabel(self.i18n.tr("network")))
        self.net_edit = QLineEdit()
        self.net_edit.setPlaceholderText("192.168.1.0/24")
        row_b.addWidget(self.net_edit, 1)
        self.calc_btn = QPushButton(self.i18n.tr("calculate"))
        row_b.addWidget(self.calc_btn)
        main.addLayout(row_b)

        # Row C: Net info
        row_c = QHBoxLayout()
        self.net_info_edit = QLineEdit()
        self.net_info_edit.setReadOnly(True)
        row_c.addWidget(self.net_info_edit, 1)
        main.addLayout(row_c)

        # Row D/E/F: Start/Stop + times + params
        row_def = QHBoxLayout()
        self.start_btn = QPushButton(self.i18n.tr("start"))
        self.stop_btn = QPushButton(self.i18n.tr("stop"))
        self.stop_btn.setEnabled(False)
        row_def.addWidget(self.start_btn)
        row_def.addWidget(self.stop_btn)

        row_def.addWidget(QLabel(self.i18n.tr("start_time")))
        self.start_time = QLineEdit()
        self.start_time.setReadOnly(True)
        self.start_time.setFixedWidth(160)
        row_def.addWidget(self.start_time)

        row_def.addWidget(QLabel(self.i18n.tr("end_time")))
        self.end_time = QLineEdit()
        self.end_time.setReadOnly(True)
        self.end_time.setFixedWidth(160)
        row_def.addWidget(self.end_time)

        row_def.addWidget(QLabel(self.i18n.tr("num_process")))
        self.num_process = QSpinBox()
        self.num_process.setRange(1, 512)
        self.num_process.setValue(5)
        self.num_process.setFixedWidth(80)
        row_def.addWidget(self.num_process)

        row_def.addWidget(QLabel(self.i18n.tr("num_run")))
        self.num_run = QSpinBox()
        self.num_run.setRange(1, 20)
        self.num_run.setValue(2)
        self.num_run.setFixedWidth(80)
        row_def.addWidget(self.num_run)

        main.addLayout(row_def)

        # Row G: Options (checkboxes)
        row_g = QHBoxLayout()
        row_g.addWidget(QLabel(self.i18n.tr("options")))
        self.fqdn_cb = QCheckBox(self.i18n.tr("opt_fqdn"))
        self.arp_cb = QCheckBox(self.i18n.tr("opt_arp"))
        self.vendor_cb = QCheckBox(self.i18n.tr("opt_vendor"))
        self.only_alive_cb = QCheckBox(self.i18n.tr("opt_only_alive"))

        self.fqdn_cb.setChecked(True)
        self.arp_cb.setChecked(True)
        self.vendor_cb.setChecked(True)
        self.only_alive_cb.setChecked(False)

        row_g.addWidget(self.fqdn_cb)
        row_g.addWidget(self.arp_cb)
        row_g.addWidget(self.vendor_cb)
        row_g.addWidget(self.only_alive_cb)
        row_g.addStretch(1)
        main.addLayout(row_g)

        # Search row (between options and save/load row)
        row_search = QHBoxLayout()
        row_search.addWidget(QLabel(self.i18n.tr("search")))
        self.search_edit = QLineEdit()
        row_search.addWidget(self.search_edit, 1)
        self.search_btn = QPushButton(self.i18n.tr("do_search"))
        self.reset_btn = QPushButton(self.i18n.tr("reset"))
        row_search.addWidget(self.search_btn)
        row_search.addWidget(self.reset_btn)
        main.addLayout(row_search)

        # Row H: Save/Load
        row_h = QHBoxLayout()
        self.save_btn = QPushButton(self.i18n.tr("save"))
        self.load_btn = QPushButton(self.i18n.tr("load"))
        self.save_btn.setEnabled(False)
        row_h.addWidget(self.save_btn)
        row_h.addWidget(self.load_btn)
        row_h.addStretch(1)
        main.addLayout(row_h)

        # Table
        self.model = HostTableModel()
        self.proxy = HostProxyModel()
        self.proxy.setSourceModel(self.model)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)

        # Make columns evenly stretch to fill space
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)

        main.addWidget(self.table, 1)

        # Translate headers
        self.model.set_headers([
            self.i18n.tr("ip_address"),
            self.i18n.tr("fqdn_col"),
            self.i18n.tr("arp_col"),
            self.i18n.tr("vendor_col"),
        ])

    def _connect_signals(self) -> None:
        self.calc_btn.clicked.connect(self.on_calculate)
        self.start_btn.clicked.connect(self.on_start)
        self.stop_btn.clicked.connect(self.on_stop)

        self.save_btn.clicked.connect(self.on_save)
        self.load_btn.clicked.connect(self.on_load)

        self.only_alive_cb.stateChanged.connect(self.on_only_alive_toggled)

        self.search_btn.clicked.connect(self.on_search)
        self.reset_btn.clicked.connect(self.on_reset_search)

        self.table.customContextMenuRequested.connect(self.on_context_menu)

    def _now_str(self) -> str:
        # ISO-like but readable
        return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def on_calculate(self) -> None:
        try:
            info = parse_network(self.net_edit.text())
        except Exception:
            QMessageBox.critical(self, self.i18n.tr("msg_invalid_network_title"), self.i18n.tr("msg_invalid_network_body"))
            return

        self.net_info = info
        self.net_edit.setText(info.network_cidr)
        self.net_info_edit.setText(self.i18n.tr("net_info", start=info.ip_start, stop=info.ip_stop, broadcast=info.broadcast))

    def on_start(self) -> None:
        if self.scan_running:
            QMessageBox.information(self, self.i18n.tr("app_title"), self.i18n.tr("msg_scan_running"))
            return

        # Validate network first
        self.on_calculate()
        if not self.net_info:
            return

        # Reset UI
        self.model.clear()
        self.proxy.set_search_text("")
        self.search_edit.setText("")
        self.end_time.setText("")
        self.save_btn.setEnabled(False)

        self.scan_started_at = self._now_str()
        self.start_time.setText(self.scan_started_at)

        self.scan_running = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self.engine = ScannerEngine(
            num_process=self.num_process.value(),
            num_run=self.num_run.value(),
            flag_fqdn=self.fqdn_cb.isChecked(),
            flag_arp=self.arp_cb.isChecked(),
            flag_vendor=self.vendor_cb.isChecked(),
        )

        self.worker = ScanWorker(self.engine, self.net_info.hosts)
        self.worker.host.connect(self._on_host)
        self.worker.progress.connect(self._on_progress)
        self.worker.state.connect(self._on_state)
        self.worker.finished.connect(self._on_finished)
        self.worker.stopped.connect(self._on_stopped)

        self.worker_thread = threading.Thread(target=self.worker.run, daemon=True)
        self.worker_thread.start()

    def on_stop(self) -> None:
        if not self.scan_running or not self.engine:
            return
        self.engine.stop()

    def _finish_common(self, msg: str) -> None:
        self.scan_running = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        self.scan_ended_at = self._now_str()
        self.end_time.setText(self.scan_ended_at)

        # Allow saving after completion (including Stop)
        self.save_btn.setEnabled(True)

        QMessageBox.information(self, self.i18n.tr("app_title"), msg)

    def _on_host(self, res: HostResult) -> None:
        self.model.upsert(res)
        # Keep default sorting by IP
        self.table.sortByColumn(0, Qt.AscendingOrder)

    def _on_progress(self, done: int, total: int) -> None:
        # You can extend this to a progress bar if needed
        # For now we update window title with progress info.
        self.setWindowTitle(f"{self.i18n.tr('app_title')} - {done}/{total}")

    def _on_state(self, s: str) -> None:
        # Could be displayed somewhere; keeping minimal.
        pass

    def _on_finished(self) -> None:
        self._finish_common(self.i18n.tr("msg_scan_done"))

    def _on_stopped(self) -> None:
        self._finish_common(self.i18n.tr("msg_scan_stopped"))

    def on_only_alive_toggled(self) -> None:
        self.proxy.set_only_alive(self.only_alive_cb.isChecked())

    def on_search(self) -> None:
        self.proxy.set_search_text(self.search_edit.text())

    def on_reset_search(self) -> None:
        self.search_edit.setText("")
        self.proxy.set_search_text("")
        # Keep alive filter as-is

    def on_context_menu(self, pos) -> None:
        # Right-click menu on a row: Re-scan
        idx = self.table.indexAt(pos)
        if not idx.isValid():
            return

        menu = QMenu(self.table)
        act = menu.addAction(self.i18n.tr("context_rescan"))

        action = menu.exec(self.table.viewport().mapToGlobal(pos))
        if action != act:
            return

        # Re-scan should not interfere with an active full scan
        if self.scan_running:
            return

        # Get the IP from the selected row (proxy -> source)
        ip = self.proxy.data(self.proxy.index(idx.row(), COL_IP), Qt.DisplayRole) or ""
        ip = str(ip)

        if not ip:
            return

        self._start_rescan(ip)

    def _start_rescan(self, ip: str) -> None:
        # Create a temporary engine with current settings
        engine = ScannerEngine(
            num_process=1,
            num_run=self.num_run.value(),
            flag_fqdn=self.fqdn_cb.isChecked(),
            flag_arp=self.arp_cb.isChecked(),
            flag_vendor=self.vendor_cb.isChecked(),
        )

        def run():
            res = engine.scan_one(ip)
            # We must update the model on the Qt thread.
            # Using Qt signal would be cleaner, but we keep it simple with a queued call.
            self.worker = None
            self._invoke_on_qt(lambda: self.model.upsert(res))

        t = threading.Thread(target=run, daemon=True)
        t.start()

    def _invoke_on_qt(self, fn):
        # A tiny helper: use a single-shot timer via Qt event loop.
        from PySide6.QtCore import QTimer
        QTimer.singleShot(0, fn)

    def on_save(self) -> None:
        if self.scan_running or not self.net_info:
            QMessageBox.information(self, self.i18n.tr("app_title"), self.i18n.tr("msg_save_not_ready"))
            return

        db_path, _ = QFileDialog.getSaveFileName(self, self.i18n.tr("db_save"), "", "SQLite (*.sqlite *.db);;All files (*)")
        if not db_path:
            return

        conn = dbmod.connect(db_path)
        dbmod.init_db(conn)

        rows = []
        for r in self.model.rows():
            rows.append(dbmod.ScanRow(
                ip=r.ip,
                alive=int(bool(r.alive)),
                fqdn=r.fqdn or "",
                mac=r.mac or "",
                vendor=r.vendor or "",
            ))

        scan_id = dbmod.insert_scan(
            conn,
            title=self.title_edit.text().strip() or "",
            network_cidr=self.net_info.network_cidr,
            ip_start=self.net_info.ip_start,
            ip_stop=self.net_info.ip_stop,
            broadcast=self.net_info.broadcast,
            started_at=self.scan_started_at or self.start_time.text(),
            ended_at=self.scan_ended_at or self.end_time.text(),
            num_process=self.num_process.value(),
            num_run=self.num_run.value(),
            flag_fqdn=self.fqdn_cb.isChecked(),
            flag_arp=self.arp_cb.isChecked(),
            flag_vendor=self.vendor_cb.isChecked(),
            rows=rows,
        )
        conn.close()
        # Keep it silent/minimal

    def on_load(self) -> None:
        db_path, _ = QFileDialog.getOpenFileName(self, self.i18n.tr("db_open"), "", "SQLite (*.sqlite *.db);;All files (*)")
        if not db_path:
            return

        conn = dbmod.connect(db_path)
        dbmod.init_db(conn)
        scans = dbmod.list_scans(conn)
        if not scans:
            conn.close()
            QMessageBox.information(self, self.i18n.tr("app_title"), self.i18n.tr("msg_load_empty"))
            return

        items = [f"{s.title} | {s.started_at}" for s in scans]
        choice, ok = QInputDialog.getItem(self, self.i18n.tr("scan_select"), self.i18n.tr("scan"), items, 0, False)
        if not ok or not choice:
            conn.close()
            return

        idx = items.index(choice)
        scan_id = scans[idx].id
        header, data = dbmod.load_scan(conn, scan_id)
        conn.close()

        # Populate GUI
        self.title_edit.setText(header.title)
        self.net_edit.setText(header.network_cidr)
        self.net_info = parse_network(header.network_cidr)
        self.net_info_edit.setText(self.i18n.tr("net_info", start=header.ip_start, stop=header.ip_stop, broadcast=header.broadcast))
        self.start_time.setText(header.started_at)
        self.end_time.setText(header.ended_at)
        self.scan_started_at = header.started_at
        self.scan_ended_at = header.ended_at

        self.num_process.setValue(header.num_process)
        self.num_run.setValue(header.num_run)
        self.fqdn_cb.setChecked(bool(header.flag_fqdn))
        self.arp_cb.setChecked(bool(header.flag_arp))
        self.vendor_cb.setChecked(bool(header.flag_vendor))

        # Load results in numeric IP order
        results: List[HostResult] = []
        for r in data:
            results.append(HostResult(ip=r.ip, alive=bool(r.alive), fqdn=r.fqdn, mac=r.mac, vendor=r.vendor))

        # Sort by numeric IP before showing
        results.sort(key=lambda x: int(__import__("ipaddress").IPv4Address(x.ip)))
        self.model.bulk_set_in_ip_order(results)
        self.table.sortByColumn(0, Qt.AscendingOrder)

        self.save_btn.setEnabled(True)  # loaded scan is already finished
