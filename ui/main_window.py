from __future__ import annotations

import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from PySide6.QtCore import QObject, Signal, Qt
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QMessageBox, QTableWidget,
    QTableWidgetItem, QSpinBox, QCheckBox, QFileDialog, QDialog, QListWidget,
    QListWidgetItem, QDialogButtonBox
)

from lib.scanner import LanScanner
from lib import db as db_lib


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class ScanSignals(QObject):
    host = Signal(dict)
    progress = Signal(int, int)
    state = Signal(str)
    finished = Signal(list)


class ScanWorker:
    def __init__(self, scanner: LanScanner, signals: ScanSignals):
        self.scanner = scanner
        self.signals = signals

    def run(self):
        try:
            res = self.scanner.run()
            self.signals.finished.emit(res)
        except Exception as e:
            self.signals.state.emit(f"error: {e}")
            self.signals.finished.emit([])


class ScanPickerDialog(QDialog):
    def __init__(self, scans: List[tuple], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Seleziona scansione")
        self.selected_scan_id: Optional[int] = None

        layout = QVBoxLayout(self)
        self.listw = QListWidget()
        for sid, title, started_at in scans:
            item = QListWidgetItem(f"{title}  |  {started_at}")
            item.setData(Qt.UserRole, sid)
            self.listw.addItem(item)
        layout.addWidget(self.listw)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _accept(self):
        item = self.listw.currentItem()
        if not item:
            return
        self.selected_scan_id = int(item.data(Qt.UserRole))
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LAN Scanner")

        self._scanner: Optional[LanScanner] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._signals = ScanSignals()
        self._signals.host.connect(self._on_host)
        self._signals.progress.connect(self._on_progress)
        self._signals.state.connect(self._on_state)
        self._signals.finished.connect(self._on_finished)

        self._results_by_ip: Dict[str, Dict[str, Any]] = {}
        self._final_results: List[Dict[str, Any]] = []

        # Row a: titolo + summary
        self.title_label = QLabel("titolo")
        self.title_edit = QLineEdit()
        self.summary_edit = QLineEdit()
        self.summary_edit.setPlaceholderText("riassunto del lavoro")

        # Row b: ethernet + network + calcola
        self.net_label = QLabel("ethernet")
        self.net_edit = QLineEdit()
        self.net_edit.setPlaceholderText("solo CIDR IPv4: es 192.168.88.0/24 (o IP singolo)")
        self.calc_btn = QPushButton("calcola")

        # Row c: network calc text
        self.net_info = QLineEdit()
        self.net_info.setReadOnly(True)

        # Row d/e: start/stop + time
        self.start_btn = QPushButton("start")
        self.stop_btn = QPushButton("stop")
        self.stop_btn.setEnabled(False)

        self.start_time = QLineEdit(); self.start_time.setReadOnly(True)
        self.end_time = QLineEdit(); self.end_time.setReadOnly(True)

        # Row f: num_process / num_run
        self.num_process = QSpinBox()
        self.num_process.setRange(1, 512)
        self.num_process.setValue(5)
        self.num_run = QSpinBox()
        self.num_run.setRange(1, 20)
        self.num_run.setValue(2)

        # Row g: flags
        self.flag_fqdn = QCheckBox("fqdn"); self.flag_fqdn.setChecked(True)
        self.flag_arp = QCheckBox("arp"); self.flag_arp.setChecked(True)
        self.flag_vendor = QCheckBox("vendor"); self.flag_vendor.setChecked(True)

        # Row h: save/load
        self.save_btn = QPushButton("salva")
        self.load_btn = QPushButton("carica")
        self.save_btn.setEnabled(False)

        self.progress_text = QLineEdit()
        self.progress_text.setReadOnly(True)

        # Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["ip_address", "fqdn", "arp", "vendor"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)

        root = QWidget()
        self.setCentralWidget(root)
        main = QVBoxLayout(root)

        row1 = QHBoxLayout()
        row1.addWidget(self.title_label)
        row1.addWidget(self.title_edit, 2)
        row1.addWidget(self.summary_edit, 4)
        main.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(self.net_label)
        row2.addWidget(self.net_edit, 3)
        row2.addWidget(self.calc_btn)
        main.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("ip_start | ip_stop | broadcast"))
        row3.addWidget(self.net_info, 1)
        main.addLayout(row3)

        row4 = QHBoxLayout()
        row4.addWidget(self.start_btn)
        row4.addWidget(self.stop_btn)
        row4.addWidget(QLabel("ora_inizio"))
        row4.addWidget(self.start_time)
        row4.addWidget(QLabel("ora_fine"))
        row4.addWidget(self.end_time)
        main.addLayout(row4)

        row5 = QHBoxLayout()
        row5.addWidget(QLabel("num_process"))
        row5.addWidget(self.num_process)
        row5.addWidget(QLabel("num_run"))
        row5.addWidget(self.num_run)
        row5.addStretch(1)
        row5.addWidget(QLabel("progress"))
        row5.addWidget(self.progress_text)
        main.addLayout(row5)

        row6 = QHBoxLayout()
        row6.addWidget(self.flag_fqdn)
        row6.addWidget(self.flag_arp)
        row6.addWidget(self.flag_vendor)
        row6.addStretch(1)
        main.addLayout(row6)

        row7 = QHBoxLayout()
        row7.addWidget(self.save_btn)
        row7.addWidget(self.load_btn)
        row7.addStretch(1)
        main.addLayout(row7)

        main.addWidget(self.table, 1)

        # Connect
        self.calc_btn.clicked.connect(self._calc_network)
        self.start_btn.clicked.connect(self._start_scan)
        self.stop_btn.clicked.connect(self._stop_scan)
        self.save_btn.clicked.connect(self._save_db)
        self.load_btn.clicked.connect(self._load_db)

    def _err(self, title: str, text: str):
        QMessageBox.critical(self, title, text)

    def _info(self, title: str, text: str):
        QMessageBox.information(self, title, text)

    def _calc_network(self) -> bool:
        try:
            info = LanScanner.compute_network_info(self.net_edit.text())
            self.net_edit.setText(info["network"])
            self.net_info.setText(f"{info['ip_start']}  |  {info['ip_stop']}  |  {info['broadcast']}")
            return True
        except Exception as e:
            self.net_info.setText("")
            self._err("Errore network", str(e))
            return False

    def _reset_run(self):
        self.table.setRowCount(0)
        self._results_by_ip.clear()
        self._final_results = []
        self.progress_text.setText("")
        self.start_time.setText("")
        self.end_time.setText("")
        self.save_btn.setEnabled(False)

    def _start_scan(self):
        if not self._calc_network():
            return

        self._reset_run()
        self.start_time.setText(now_text())

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.calc_btn.setEnabled(False)
        self.save_btn.setEnabled(False)

        self._scanner = LanScanner(
            network=self.net_edit.text().strip(),
            num_process=self.num_process.value(),
            num_run=self.num_run.value(),
            flag_fqdn=self.flag_fqdn.isChecked(),
            flag_arp=self.flag_arp.isChecked(),
            flag_vendor=self.flag_vendor.isChecked(),
            on_host=lambda d: self._signals.host.emit(d),
            on_progress=lambda d, t: self._signals.progress.emit(d, t),
            on_state=lambda s: self._signals.state.emit(s),
        )

        worker = ScanWorker(self._scanner, self._signals)
        self._scan_thread = threading.Thread(target=worker.run, daemon=True)
        self._scan_thread.start()

    def _stop_scan(self):
        if not self._scanner:
            return
        self.stop_btn.setEnabled(False)
        try:
            self._scanner.stop()
        except Exception:
            pass

    def _ensure_row(self, ip: str) -> int:
        existing = self._results_by_ip.get(ip, {}).get("_row")
        if existing is not None:
            return int(existing)
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(ip))
        self.table.setItem(row, 1, QTableWidgetItem(""))
        self.table.setItem(row, 2, QTableWidgetItem(""))
        self.table.setItem(row, 3, QTableWidgetItem(""))
        self._results_by_ip.setdefault(ip, {})["_row"] = row
        return row

    def _on_host(self, d: Dict[str, Any]):
        ip = str(d.get("ip_address") or "")
        if not ip:
            return
        self._results_by_ip.setdefault(ip, {}).update(d)
        row = self._ensure_row(ip)

        fqdn = str(self._results_by_ip[ip].get("fqdn") or "")
        mac = str(self._results_by_ip[ip].get("mac") or "")
        vendor = str(self._results_by_ip[ip].get("vendor") or "")

        self.table.item(row, 1).setText(fqdn)
        self.table.item(row, 2).setText(mac)
        self.table.item(row, 3).setText(vendor)

        alive = bool(self._results_by_ip[ip].get("alive"))
        if not alive:
            for c in range(4):
                it = self.table.item(row, c)
                it.setForeground(Qt.gray)

    def _on_progress(self, done: int, total: int):
        self.progress_text.setText(f"{done}/{total}")

    def _on_state(self, s: str):
        if s:
            self.setWindowTitle(f"LAN Scanner - {s}")

    def _on_finished(self, results: List[Dict[str, Any]]):
        self.end_time.setText(now_text())

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.calc_btn.setEnabled(True)

        self._final_results = results or []
        # save enabled only when scan thread ended (even if stopped)
        self.save_btn.setEnabled(True)

    def _save_db(self):
        if not self._final_results:
            self._err("Errore", "Nessun risultato da salvare.")
            return
        dbfile, _ = QFileDialog.getSaveFileName(self, "Salva su DB SQLite", "", "SQLite DB (*.sqlite *.db);;All files (*)")
        if not dbfile:
            return
        try:
            info = LanScanner.compute_network_info(self.net_edit.text())
        except Exception:
            info = {"network": self.net_edit.text().strip(), "ip_start": "", "ip_stop": "", "broadcast": ""}

        try:
            con = db_lib.connect(dbfile)
            db_lib.insert_scan(
                con,
                title=self.title_edit.text().strip() or "(senza titolo)",
                summary=self.summary_edit.text().strip(),
                network=info.get("network", ""),
                ip_start=info.get("ip_start", ""),
                ip_stop=info.get("ip_stop", ""),
                broadcast=info.get("broadcast", ""),
                started_at=self.start_time.text().strip() or now_text(),
                finished_at=self.end_time.text().strip() or now_text(),
                num_process=self.num_process.value(),
                num_run=self.num_run.value(),
                flag_fqdn=self.flag_fqdn.isChecked(),
                flag_arp=self.flag_arp.isChecked(),
                flag_vendor=self.flag_vendor.isChecked(),
                results=self._final_results,
            )
            con.close()
            self._info("Salvataggio", "Scansione salvata (aggiunta al DB).")
        except Exception as e:
            self._err("Errore DB", str(e))

    def _load_db(self):
        dbfile, _ = QFileDialog.getOpenFileName(self, "Apri DB SQLite", "", "SQLite DB (*.sqlite *.db);;All files (*)")
        if not dbfile:
            return
        try:
            con = db_lib.connect(dbfile)
            scans = db_lib.list_scans(con)
            if not scans:
                con.close()
                self._info("Carica", "Nessuna scansione nel DB.")
                return
            dlg = ScanPickerDialog(scans, parent=self)
            if dlg.exec() != QDialog.Accepted or dlg.selected_scan_id is None:
                con.close()
                return
            header, rows = db_lib.load_scan(con, dlg.selected_scan_id)
            con.close()
        except Exception as e:
            self._err("Errore DB", str(e))
            return

        self._reset_run()
        self.title_edit.setText(header.title)
        self.summary_edit.setText(header.summary)
        self.net_edit.setText(header.network)
        self.net_info.setText(f"{header.ip_start}  |  {header.ip_stop}  |  {header.broadcast}")
        self.start_time.setText(header.started_at)
        self.end_time.setText(header.finished_at)
        self.num_process.setValue(header.num_process)
        self.num_run.setValue(header.num_run)
        self.flag_fqdn.setChecked(bool(header.flag_fqdn))
        self.flag_arp.setChecked(bool(header.flag_arp))
        self.flag_vendor.setChecked(bool(header.flag_vendor))

        for r in rows:
            self._on_host(r)
        self.save_btn.setEnabled(True)
