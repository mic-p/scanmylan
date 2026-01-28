from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, List

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QSortFilterProxyModel

# Table model with numeric IP sorting via Qt.UserRole.
# Dead hosts are greyed and disabled (but still selectable).

@dataclass
class Row:
    ip: str
    alive: bool = False
    fqdn: str = ""
    mac: str = ""
    vendor: str = ""

class ResultsModel(QAbstractTableModel):
    HEADERS = ["IP Address", "FQDN", "ARP", "Vendor"]

    def __init__(self) -> None:
        super().__init__()
        self._rows: List[Row] = []

    def clear(self) -> None:
        self.beginResetModel()
        self._rows = []
        self.endResetModel()

    def upsert(self, row: Row) -> None:
        for i, r in enumerate(self._rows):
            if r.ip == row.ip:
                self._rows[i] = row
                self.dataChanged.emit(self.index(i, 0), self.index(i, 3), [])
                return
        self.beginInsertRows(QModelIndex(), len(self._rows), len(self._rows))
        self._rows.append(row)
        self.endInsertRows()

    def rows(self) -> List[Row]:
        return list(self._rows)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else 4

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid():
            return None
        r = self._rows[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            return [r.ip, r.fqdn, r.mac, r.vendor][col]

        if not r.alive:
            if role == Qt.ForegroundRole:
                return Qt.gray
            if role == Qt.BackgroundRole:
                return Qt.lightGray

        if role == Qt.UserRole:
            if col == 0:
                try:
                    return int(ipaddress.IPv4Address(r.ip))
                except Exception:
                    return 0
            return (self.data(index, Qt.DisplayRole) or "").lower()

        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlags:
        if not index.isValid():
            return Qt.NoItemFlags
        r = self._rows[index.row()]
        if not r.alive:
            return Qt.ItemIsSelectable  # disabled but selectable
        return Qt.ItemIsSelectable | Qt.ItemIsEnabled

class ResultsProxy(QSortFilterProxyModel):
    def __init__(self) -> None:
        super().__init__()
        self._alive_only = True
        self._query = ""

    def set_alive_only(self, v: bool) -> None:
        self._alive_only = bool(v)
        self.invalidateFilter()

    def set_query(self, q: str) -> None:
        self._query = (q or "").strip().lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model: ResultsModel = self.sourceModel()  # type: ignore
        if model is None:
            return True
        r = model._rows[source_row]
        if self._alive_only and not r.alive:
            return False
        if self._query:
            blob = " ".join([r.ip, r.fqdn, r.mac, r.vendor]).lower()
            return self._query in blob
        return True

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        lkey = self.sourceModel().data(left, Qt.UserRole)
        rkey = self.sourceModel().data(right, Qt.UserRole)
        return lkey < rkey
