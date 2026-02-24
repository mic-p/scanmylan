from __future__ import annotations

import threading
from datetime import datetime
from typing import Optional
import csv

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableView,
    QVBoxLayout,
    QHBoxLayout,
    QWidget,
    QListWidget,
    QListWidgetItem,
    QMenu,
)

from i18n.i18n import tr, get_lang
from lib.netcalc import parse_network, NetInfo
from lib.localnets import list_local_ipv4_networks
from lib.scanner import LanScanner, ScanConfig, ScanResult
from lib import db as dbmod
from .table_model import ResultsModel, ResultsProxy, Row
from .net_select_dialog import NetSelectDialog


class ScannerSignals(QObject):
    # Thread-safe signals for GUI updates.
    host = Signal(object)        # ScanResult
    progress = Signal(int, int)  # done, total
    state = Signal(str)          # state
    finished = Signal(bool)      # stopped?


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.lang = get_lang()
        self.setWindowTitle(tr("app_title", self.lang))

        self._scanner: Optional[LanScanner] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._stopped = False
        self._scan_done = False
        self._netinfo: Optional[NetInfo] = None
        self._started_at: str = ""
        self._ended_at: str = ""

        # --- Widgets ---
        self.title_edit = QLineEdit()

        self.net_edit = QLineEdit()
        self.calc_btn = QPushButton(tr("calculate", self.lang))
        self.calc_btn.clicked.connect(self.on_calculate)

        self.read_net_btn = QPushButton(tr("read_net", self.lang))
        self.read_net_btn.clicked.connect(self.on_read_net)

        self.cidr_label = QLabel(tr("cidr_calc", self.lang))
        self.cidr_info = QLineEdit(tr("cidr_default", self.lang))
        self.cidr_info.setReadOnly(True)

        self.start_btn = QPushButton(tr("start", self.lang))
        self.stop_btn = QPushButton(tr("stop", self.lang))
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.on_start)
        self.stop_btn.clicked.connect(self.on_stop)

        self.start_time = QLineEdit("")
        self.end_time = QLineEdit("")
        self.start_time.setReadOnly(True)
        self.end_time.setReadOnly(True)

        self.num_process = QSpinBox()
        self.num_process.setRange(1, 512)
        self.num_process.setValue(5)

        self.num_run = QSpinBox()
        self.num_run.setRange(1, 20)
        self.num_run.setValue(2)

        # Options (checkboxes)
        from PySide6.QtWidgets import QCheckBox
        self.options_label = QLabel(tr("options", self.lang))
        self.opt_fqdn = QCheckBox(tr("opt_fqdn", self.lang))
        self.opt_arp = QCheckBox(tr("opt_arp", self.lang))
        self.opt_vendor = QCheckBox(tr("opt_vendor", self.lang))
        self.opt_alive_only = QCheckBox(tr("opt_alive_only", self.lang))

        self.opt_fqdn.setChecked(True)
        self.opt_arp.setChecked(True)
        self.opt_vendor.setChecked(True)
        self.opt_alive_only.setChecked(True)  # default ON
        self.opt_alive_only.stateChanged.connect(self.on_alive_only_changed)

        # Search row
        self.search_label = QLabel(tr("search", self.lang))
        self.search_edit = QLineEdit()
        self.search_btn = QPushButton(tr("search_btn", self.lang))
        self.reset_btn = QPushButton(tr("reset_btn", self.lang))
        self.search_btn.clicked.connect(self.on_search)
        self.reset_btn.clicked.connect(self.on_reset_search)
        self.search_edit.returnPressed.connect(self.on_search)
        self.search_edit.textChanged.connect(self.on_search_live)

        # Save/Load
        self.save_btn = QPushButton(tr("save", self.lang))
        self.load_btn = QPushButton(tr("load", self.lang))
        self.export_csv_btn = QPushButton(tr("export_csv", self.lang))
        self.export_csv_btn.clicked.connect(self.on_export_csv)
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self.on_save)
        self.load_btn.clicked.connect(self.on_load)

        # Table model/proxy
        self.model = ResultsModel()
        self.proxy = ResultsProxy()
        self.proxy.setSourceModel(self.model)
        self.proxy.set_alive_only(True)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.AscendingOrder)  # default sort by IP numeric
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.on_table_context)

        header = self.table.horizontalHeader()
        # Stretch all columns to the available width (equally).
        from PySide6.QtWidgets import QHeaderView
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        # Style read-only fields with grey background.
        self.setStyleSheet('QLineEdit[readOnly="true"] { background: #E8E8E8; }')

        # Layout
        root = QWidget()
        self.setCentralWidget(root)
        v = QVBoxLayout(root)

        # Row a: title
        ra = QHBoxLayout()
        ra.addWidget(QLabel(tr("title", self.lang)))
        ra.addWidget(self.title_edit, 1)
        v.addLayout(ra)

        # Row b: network + calculate
        rb = QHBoxLayout()
        rb.addWidget(QLabel(tr("network", self.lang)))
        rb.addWidget(self.net_edit, 1)
        rb.addWidget(self.calc_btn)
        rb.addWidget(self.read_net_btn)
        v.addLayout(rb)

        # Row c: cidr calculation label + field
        rc = QHBoxLayout()
        rc.addWidget(self.cidr_label)
        rc.addWidget(self.cidr_info, 1)
        v.addLayout(rc)

        # Row d: start/stop
        rd = QHBoxLayout()
        rd.addWidget(self.start_btn)
        rd.addWidget(self.stop_btn)
        rd.addStretch(1)
        v.addLayout(rd)

        # Row e: start/end time
        re = QHBoxLayout()
        re.addWidget(QLabel(tr("start_time", self.lang)))
        re.addWidget(self.start_time, 1)
        re.addWidget(QLabel(tr("end_time", self.lang)))
        re.addWidget(self.end_time, 1)
        v.addLayout(re)

        # Row f: num_process + num_run
        rf = QHBoxLayout()
        rf.addWidget(QLabel(tr("num_process", self.lang)))
        rf.addWidget(self.num_process)
        rf.addSpacing(16)
        rf.addWidget(QLabel(tr("num_run", self.lang)))
        rf.addWidget(self.num_run)
        rf.addStretch(1)
        v.addLayout(rf)

        # Row g: options
        rg = QHBoxLayout()
        rg.addWidget(self.options_label)
        rg.addWidget(self.opt_fqdn)
        rg.addWidget(self.opt_arp)
        rg.addWidget(self.opt_vendor)
        rg.addWidget(self.opt_alive_only)
        rg.addStretch(1)
        v.addLayout(rg)

        # Search row
        rs = QHBoxLayout()
        rs.addWidget(self.search_label)
        rs.addWidget(self.search_edit, 1)
        rs.addWidget(self.search_btn)
        rs.addWidget(self.reset_btn)
        v.addLayout(rs)

        # Save/Load row
        rh = QHBoxLayout()
        rh.addWidget(self.save_btn)
        rh.addWidget(self.load_btn)
        rh.addWidget(self.export_csv_btn)
        rh.addStretch(1)
        v.addLayout(rh)

        v.addWidget(self.table, 1)

        # Signals
        self.sig = ScannerSignals()
        self.sig.host.connect(self.on_host_result)
        self.sig.progress.connect(self.on_progress)
        self.sig.state.connect(self.on_state)
        self.sig.finished.connect(self.on_finished)

    # -----------------------------
    # Network validation/calculation
    # -----------------------------
    def on_calculate(self) -> None:
        try:
            self._netinfo = parse_network(self.net_edit.text())
            ni = self._netinfo
            self.cidr_info.setText(f"IP start: {ni.ip_start} | IP stop: {ni.ip_stop} | Broadcast: {ni.broadcast}")
        except Exception:
            QMessageBox.critical(self, "Error", tr("msg_invalid_net", self.lang))
            self._netinfo = None
            self.cidr_info.setText(tr("cidr_default", self.lang))

    def on_read_net(self) -> None:
        nets = list_local_ipv4_networks()
        if not nets:
            QMessageBox.information(self, "Info", tr("net_none_found", self.lang))
            return
        dlg = NetSelectDialog(nets=nets, lang=self.lang, parent=self)
        if dlg.exec() == QDialog.Accepted and dlg.selected is not None:
            self.net_edit.setText(dlg.selected.network)
            # Auto-calc to update CIDR info and validate quickly.
            self.on_calculate()

    # -----------------------------
    # Search
    # -----------------------------
    def on_search_live(self, txt: str) -> None:
        q = (txt or "").strip()
        if len(q) > 3:
            self.proxy.set_query(q)
        elif len(q) == 0:
            self.proxy.set_query("")

    def on_search(self) -> None:
        q = (self.search_edit.text() or "").strip()
        self.proxy.set_query(q)

    def on_reset_search(self) -> None:
        self.search_edit.setText("")
        self.proxy.set_query("")

    # -----------------------------
    # Alive-only filter
    # -----------------------------
    def on_alive_only_changed(self) -> None:
        self.proxy.set_alive_only(self.opt_alive_only.isChecked())

    # -----------------------------
    # Scan control
    # -----------------------------
    def on_start(self) -> None:
        self.on_calculate()
        if not self._netinfo:
            return

        # Reset UI and state
        self._stopped = False
        self._scan_done = False
        self.model.clear()
        self.save_btn.setEnabled(False)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self._started_at = datetime.now().isoformat(timespec="seconds")
        self._ended_at = ""
        self.start_time.setText(self._started_at)
        self.end_time.setText("")

        cfg = ScanConfig(
            title=self.title_edit.text().strip() or "",
            network=self._netinfo.network,
            ip_start=self._netinfo.ip_start,
            ip_stop=self._netinfo.ip_stop,
            broadcast=self._netinfo.broadcast,
            num_process=int(self.num_process.value()),
            num_run=int(self.num_run.value()),
            flag_fqdn=self.opt_fqdn.isChecked(),
            flag_arp=self.opt_arp.isChecked(),
            flag_vendor=self.opt_vendor.isChecked(),
        )

        ips = list(self._netinfo.hosts)
        self._scanner = LanScanner(
            ips=ips,
            config=cfg,
            on_host=lambda r: self.sig.host.emit(r),
            on_progress=lambda d, t: self.sig.progress.emit(d, t),
            on_state=lambda s: self.sig.state.emit(s),
        )

        def run_worker():
            try:
                self._scanner.run()
            finally:
                self.sig.finished.emit(self._stopped)

        self._scan_thread = threading.Thread(target=run_worker, daemon=True)
        self._scan_thread.start()

    def on_stop(self) -> None:
        if self._scanner:
            self._stopped = True
            self._scanner.stop()

    def on_state(self, s: str) -> None:
        # Optional hook for future status bar messages.
        pass

    def on_progress(self, done: int, total: int) -> None:
        self.setWindowTitle(f"{tr('app_title', self.lang)} - {done}/{total}")

    def on_host_result(self, r: ScanResult) -> None:
        self.model.upsert(Row(ip=r.ip, alive=r.alive, fqdn=r.fqdn, mac=r.mac, vendor=r.vendor))

    def on_finished(self, stopped: bool) -> None:
        self._ended_at = datetime.now().isoformat(timespec="seconds")
        self.end_time.setText(self._ended_at)

        self.stop_btn.setEnabled(False)
        self.start_btn.setEnabled(True)
        self._scan_done = True
        self.save_btn.setEnabled(not stopped)

    # -----------------------------
    # Context menu: Re-scan
    # -----------------------------
    def on_table_context(self, pos) -> None:
        idx = self.table.indexAt(pos)
        if not idx.isValid():
            return

        # Do not allow rescan while scan is running
        if self.stop_btn.isEnabled():
            QMessageBox.information(self, "Info", tr("msg_scan_running", self.lang))
            return

        # Get selected IP
        src_idx = self.proxy.mapToSource(idx)
        ip = self.model._rows[src_idx.row()].ip

        # ✅ Correct custom menu
        menu = QMenu(self)

        act_rescan = QAction(tr("context_rescan", self.lang), self)
        act_rescan.triggered.connect(lambda: self._do_rescan(ip))

        menu.addAction(act_rescan)

        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _do_rescan(self, ip: str) -> None:
        cfg = ScanConfig(
            title=self.title_edit.text().strip() or "",
            network=self.net_edit.text().strip() or "",
            ip_start=self._netinfo.ip_start if self._netinfo else "",
            ip_stop=self._netinfo.ip_stop if self._netinfo else "",
            broadcast=self._netinfo.broadcast if self._netinfo else "",
            num_process=1,
            num_run=int(self.num_run.value()),
            flag_fqdn=self.opt_fqdn.isChecked(),
            flag_arp=self.opt_arp.isChecked(),
            flag_vendor=self.opt_vendor.isChecked(),
        )
        scanner = LanScanner([ip], cfg)
        r = scanner.scan_single(ip)
        self.on_host_result(r)

    # -----------------------------
    # Save/Load DB
    # -----------------------------
    def on_save(self) -> None:
        if not self._scan_done or self._stopped:
            QMessageBox.warning(self, "Warning", tr("msg_scan_not_finished", self.lang))
            return

        dbfile, _ = QFileDialog.getSaveFileName(self, tr("save", self.lang), "", "SQLite (*.sqlite *.db);;All files (*.*)")
        if not dbfile:
            QMessageBox.information(self, "Info", tr("msg_no_db_selected", self.lang))
            return

        if not self._netinfo:
            self.on_calculate()
        if not self._netinfo:
            return

        header = {
            "title": self.title_edit.text().strip() or "",
            "network": self._netinfo.network,
            "ip_start": self._netinfo.ip_start,
            "ip_stop": self._netinfo.ip_stop,
            "broadcast": self._netinfo.broadcast,
            "num_process": int(self.num_process.value()),
            "num_run": int(self.num_run.value()),
            "flag_fqdn": self.opt_fqdn.isChecked(),
            "flag_arp": self.opt_arp.isChecked(),
            "flag_vendor": self.opt_vendor.isChecked(),
            "started_at": self._started_at or self.start_time.text().strip(),
            "ended_at": self._ended_at or self.end_time.text().strip(),
            "stopped": False,
        }
        rows = [{"ip": r.ip, "alive": r.alive, "fqdn": r.fqdn, "mac": r.mac, "vendor": r.vendor} for r in self.model.rows()]
        dbmod.insert_scan(dbfile, header, rows)

    def on_load(self) -> None:
        dbfile, _ = QFileDialog.getOpenFileName(self, tr("load", self.lang), "", "SQLite (*.sqlite *.db);;All files (*.*)")
        if not dbfile:
            QMessageBox.information(self, "Info", tr("msg_no_db_selected", self.lang))
            return

        scans = dbmod.list_scans(dbfile)
        if not scans:
            return

        dlg = QDialog(self)
        dlg.setWindowTitle(tr("msg_load_choose_scan", self.lang))
        v = QVBoxLayout(dlg)
        lw = QListWidget()
        for s in scans:
            item = QListWidgetItem(f"{s.started_at} - {s.title}")
            item.setData(Qt.UserRole, s.id)
            lw.addItem(item)
        v.addWidget(lw)

        btns = QHBoxLayout()
        ok = QPushButton("OK")
        cancel = QPushButton("Cancel")
        btns.addWidget(ok)
        btns.addWidget(cancel)
        v.addLayout(btns)

        chosen = {"id": None}

        def do_ok():
            it = lw.currentItem()
            if it:
                chosen["id"] = int(it.data(Qt.UserRole))
                dlg.accept()

        ok.clicked.connect(do_ok)
        cancel.clicked.connect(dlg.reject)

        if dlg.exec() != QDialog.Accepted or chosen["id"] is None:
            return

        header, rows = dbmod.load_scan(dbfile, chosen["id"])

        self.title_edit.setText(header.title)
        self.net_edit.setText(header.network)
        self.cidr_info.setText(f"IP start: {header.ip_start} | IP stop: {header.ip_stop} | Broadcast: {header.broadcast}")
        self.start_time.setText(header.started_at)
        self.end_time.setText(header.ended_at)

        self.num_process.setValue(header.num_process)
        self.num_run.setValue(header.num_run)
        self.opt_fqdn.setChecked(header.flag_fqdn)
        self.opt_arp.setChecked(header.flag_arp)
        self.opt_vendor.setChecked(header.flag_vendor)

        self.model.clear()
        for r in rows:
            self.model.upsert(Row(ip=r.ip, alive=r.alive, fqdn=r.fqdn, mac=r.mac, vendor=r.vendor))

        self._scan_done = True
        self._stopped = header.stopped
        self.save_btn.setEnabled(not self._stopped)


    # -----------------------------
    # Export CSV (current visible view)
    # -----------------------------
    def on_export_csv(self) -> None:
        # Export ONLY what is currently visible (proxy model):
        # - respects "show only alive"
        # - respects search filter
        # - respects current sort order
        if self.proxy.rowCount() <= 0:
            QMessageBox.information(self, "Info", tr("msg_no_rows", self.lang))
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            tr("export_csv", self.lang),
            "",
            "CSV (*.csv);;All files (*.*)",
       )
        if not path:
            return
        if not path.lower().endswith(".csv"):
            path += ".csv"

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["ip_address", "fqdn", "arp", "vendor"])
                for prow in range(self.proxy.rowCount()):
                    ip = str(self.proxy.index(prow, 0).data() or "")
                    fqdn = str(self.proxy.index(prow, 1).data() or "")
                    mac = str(self.proxy.index(prow, 2).data() or "")
                    vendor = str(self.proxy.index(prow, 3).data() or "")
                    w.writerow([ip, fqdn, mac, vendor])
            QMessageBox.information(self, "OK", tr("msg_export_ok", self.lang))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"CSV export failed: {e}")
