from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QVBoxLayout, QListWidget, QHBoxLayout, QPushButton

from i18n.i18n import tr
from lib.localnets import LocalNet


class NetSelectDialog(QDialog):
    def __init__(self, nets: list[LocalNet], lang: str, parent=None) -> None:
        super().__init__(parent)
        self._lang = lang
        self._nets = list(nets)
        self.selected: LocalNet | None = None

        self.setWindowTitle(tr("net_select_title", self._lang))

        v = QVBoxLayout(self)
        self.listw = QListWidget()
        for n in self._nets:
            self.listw.addItem(n.label())
        if self._nets:
            self.listw.setCurrentRow(0)
        v.addWidget(self.listw)

        btns = QHBoxLayout()
        ok = QPushButton(tr("net_select_ok", self._lang))
        cancel = QPushButton(tr("net_select_cancel", self._lang))
        btns.addWidget(ok)
        btns.addWidget(cancel)
        v.addLayout(btns)

        ok.clicked.connect(self._do_ok)
        cancel.clicked.connect(self.reject)
        self.listw.itemDoubleClicked.connect(lambda *_: self._do_ok())

    def _do_ok(self) -> None:
        idx = self.listw.currentRow()
        if 0 <= idx < len(self._nets):
            self.selected = self._nets[idx]
        self.accept()
