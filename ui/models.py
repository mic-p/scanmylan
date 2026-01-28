"""Qt models for the results table."""

from __future__ import annotations

import ipaddress
from typing import List, Optional

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QSortFilterProxyModel

from lib.scanner import HostResult


COL_IP = 0
COL_FQDN = 1
COL_MAC = 2
COL_VENDOR = 3


class HostTableModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self._rows: List[HostResult] = []
        self._headers = ["IP", "FQDN", "ARP", "Vendor"]

    def set_headers(self, headers: List[str]) -> None:
        self._headers = headers
        self.headerDataChanged.emit(Qt.Horizontal, 0, len(headers) - 1)

    def clear(self) -> None:
        self.beginResetModel()
        self._rows = []
        self.endResetModel()

    def upsert(self, res: HostResult) -> None:
        # Update existing row by IP, or append.
        for i, r in enumerate(self._rows):
            if r.ip == res.ip:
                self._rows[i] = res
                top_left = self.index(i, 0)
                bottom_right = self.index(i, 3)
                self.dataChanged.emit(top_left, bottom_right, [Qt.DisplayRole])
                return

        self.beginInsertRows(QModelIndex(), len(self._rows), len(self._rows))
        self._rows.append(res)
        self.endInsertRows()

    def bulk_set_in_ip_order(self, results: List[HostResult]) -> None:
        self.beginResetModel()
        self._rows = list(results)
        self.endResetModel()

    def rows(self) -> List[HostResult]:
        return list(self._rows)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 4

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None
        r = self._rows[index.row()]
        c = index.column()

        if role == Qt.DisplayRole:
            if c == COL_IP:
                return r.ip
            if c == COL_FQDN:
                return r.fqdn
            if c == COL_MAC:
                return r.mac
            if c == COL_VENDOR:
                return r.vendor
            return ""

        if role == Qt.UserRole:
            # Useful for sorting/filtering
            if c == COL_IP:
                try:
                    return int(ipaddress.IPv4Address(r.ip))
                except Exception:
                    return 0
            if c == COL_FQDN:
                return r.fqdn or ""
            if c == COL_MAC:
                return r.mac or ""
            if c == COL_VENDOR:
                return r.vendor or ""
            return ""

        if role == Qt.UserRole + 1:
            # alive flag
            return bool(r.alive)

        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            if 0 <= section < len(self._headers):
                return self._headers[section]
        return None

    def sort(self, column: int, order: Qt.SortOrder = Qt.AscendingOrder) -> None:
        reverse = order == Qt.DescendingOrder

        def key(res: HostResult):
            if column == COL_IP:
                try:
                    return int(ipaddress.IPv4Address(res.ip))
                except Exception:
                    return 0
            if column == COL_FQDN:
                return (res.fqdn or "").lower()
            if column == COL_MAC:
                return (res.mac or "").lower()
            if column == COL_VENDOR:
                return (res.vendor or "").lower()
            return 0

        self.layoutAboutToBeChanged.emit()
        self._rows.sort(key=key, reverse=reverse)
        self.layoutChanged.emit()


class HostProxyModel(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self.only_alive = False
        self.search_text = ""

    def set_only_alive(self, value: bool) -> None:
        self.only_alive = bool(value)
        self.invalidateFilter()

    def set_search_text(self, value: str) -> None:
        self.search_text = (value or "").strip().lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        m = self.sourceModel()
        if m is None:
            return True

        # Alive filter
        if self.only_alive:
            idx = m.index(source_row, 0, source_parent)
            alive = m.data(idx, Qt.UserRole + 1)
            if not alive:
                return False

        # Search filter
        if self.search_text:
            for col in range(0, 4):
                idx = m.index(source_row, col, source_parent)
                txt = (m.data(idx, Qt.DisplayRole) or "").lower()
                if self.search_text in txt:
                    return True
            return False

        return True

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        # Numeric IP sorting on first column
        if left.column() == COL_IP and right.column() == COL_IP:
            l = self.sourceModel().data(left, Qt.UserRole) or 0
            r = self.sourceModel().data(right, Qt.UserRole) or 0
            return l < r
        return super().lessThan(left, right)
