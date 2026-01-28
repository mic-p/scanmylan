"""SQLite persistence (new schema, no backward compatibility).

We store:
- scan header/config in table `scan`
- per-IP results in table `scan_result`

A scan has 1-N relationship with scan_result.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any


@dataclass
class ScanHeader:
    id: int
    title: str
    network_cidr: str
    ip_start: str
    ip_stop: str
    broadcast: str
    started_at: str
    ended_at: str
    num_process: int
    num_run: int
    flag_fqdn: int
    flag_arp: int
    flag_vendor: int


@dataclass
class ScanRow:
    ip: str
    alive: int
    fqdn: str
    mac: str
    vendor: str


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS scan (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            network_cidr TEXT NOT NULL,
            ip_start TEXT NOT NULL,
            ip_stop TEXT NOT NULL,
            broadcast TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT NOT NULL,
            num_process INTEGER NOT NULL,
            num_run INTEGER NOT NULL,
            flag_fqdn INTEGER NOT NULL,
            flag_arp INTEGER NOT NULL,
            flag_vendor INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_result (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            alive INTEGER NOT NULL,
            fqdn TEXT NOT NULL,
            mac TEXT NOT NULL,
            vendor TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_scan_started ON scan(started_at);
        CREATE INDEX IF NOT EXISTS idx_scan_result_scan ON scan_result(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scan_result_ip ON scan_result(ip);
        """
    )
    conn.commit()


def insert_scan(
    conn: sqlite3.Connection,
    *,
    title: str,
    network_cidr: str,
    ip_start: str,
    ip_stop: str,
    broadcast: str,
    started_at: str,
    ended_at: str,
    num_process: int,
    num_run: int,
    flag_fqdn: bool,
    flag_arp: bool,
    flag_vendor: bool,
    rows: List[ScanRow],
) -> int:
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO scan(
            title, network_cidr, ip_start, ip_stop, broadcast,
            started_at, ended_at, num_process, num_run,
            flag_fqdn, flag_arp, flag_vendor
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            title,
            network_cidr,
            ip_start,
            ip_stop,
            broadcast,
            started_at,
            ended_at,
            int(num_process),
            int(num_run),
            int(bool(flag_fqdn)),
            int(bool(flag_arp)),
            int(bool(flag_vendor)),
        ),
    )
    scan_id = cur.lastrowid

    cur.executemany(
        """
        INSERT INTO scan_result(scan_id, ip, alive, fqdn, mac, vendor)
        VALUES(?,?,?,?,?,?)
        """,
        [(scan_id, r.ip, int(r.alive), r.fqdn or "", r.mac or "", r.vendor or "") for r in rows],
    )
    conn.commit()
    return int(scan_id)


def list_scans(conn: sqlite3.Connection) -> List[ScanHeader]:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, title, network_cidr, ip_start, ip_stop, broadcast,
               started_at, ended_at, num_process, num_run, flag_fqdn, flag_arp, flag_vendor
        FROM scan
        ORDER BY started_at DESC
        """
    )
    rows = cur.fetchall()
    return [ScanHeader(*r) for r in rows]


def load_scan(conn: sqlite3.Connection, scan_id: int) -> Tuple[ScanHeader, List[ScanRow]]:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, title, network_cidr, ip_start, ip_stop, broadcast,
               started_at, ended_at, num_process, num_run, flag_fqdn, flag_arp, flag_vendor
        FROM scan
        WHERE id=?
        """,
        (scan_id,),
    )
    hdr_row = cur.fetchone()
    if not hdr_row:
        raise ValueError("Scan not found")

    header = ScanHeader(*hdr_row)

    cur.execute(
        """
        SELECT ip, alive, fqdn, mac, vendor
        FROM scan_result
        WHERE scan_id=?
        ORDER BY ip
        """,
        (scan_id,),
    )
    data = [ScanRow(*r) for r in cur.fetchall()]
    return header, data
