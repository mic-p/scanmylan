from __future__ import annotations
import sqlite3
from dataclasses import dataclass
from typing import Dict, List, Tuple, Any

@dataclass
class ScanHeader:
    scan_id: int
    title: str
    summary: str
    network: str
    ip_start: str
    ip_stop: str
    broadcast: str
    started_at: str
    finished_at: str
    num_process: int
    num_run: int
    flag_fqdn: int
    flag_arp: int
    flag_vendor: int

def connect(dbfile: str) -> sqlite3.Connection:
    con = sqlite3.connect(dbfile)
    con.execute("PRAGMA foreign_keys=ON")
    return con

def ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS scan (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            network TEXT NOT NULL,
            ip_start TEXT NOT NULL,
            ip_stop TEXT NOT NULL,
            broadcast TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            num_process INTEGER NOT NULL,
            num_run INTEGER NOT NULL,
            flag_fqdn INTEGER NOT NULL,
            flag_arp INTEGER NOT NULL,
            flag_vendor INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_result (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            alive INTEGER NOT NULL,
            fqdn TEXT NOT NULL,
            mac TEXT NOT NULL,
            vendor TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_scan_started_at ON scan(started_at);
        CREATE INDEX IF NOT EXISTS idx_scan_result_scan_id ON scan_result(scan_id);
        """
    )
    con.commit()

def insert_scan(
    con: sqlite3.Connection,
    *,
    title: str,
    summary: str,
    network: str,
    ip_start: str,
    ip_stop: str,
    broadcast: str,
    started_at: str,
    finished_at: str,
    num_process: int,
    num_run: int,
    flag_fqdn: bool,
    flag_arp: bool,
    flag_vendor: bool,
    results: List[Dict[str, Any]],
) -> int:
    ensure_schema(con)
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO scan(title, summary, network, ip_start, ip_stop, broadcast,
                         started_at, finished_at, num_process, num_run, flag_fqdn, flag_arp, flag_vendor)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            title,
            summary,
            network,
            ip_start,
            ip_stop,
            broadcast,
            started_at,
            finished_at,
            int(num_process),
            int(num_run),
            1 if flag_fqdn else 0,
            1 if flag_arp else 0,
            1 if flag_vendor else 0,
        ),
    )
    scan_id = int(cur.lastrowid)
    for row in results:
        cur.execute(
            """
            INSERT INTO scan_result(scan_id, ip_address, alive, fqdn, mac, vendor)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                str(row.get("ip_address") or ""),
                1 if row.get("alive") else 0,
                str(row.get("fqdn") or ""),
                str(row.get("mac") or ""),
                str(row.get("vendor") or ""),
            ),
        )
    con.commit()
    return scan_id

def list_scans(con: sqlite3.Connection) -> List[Tuple[int, str, str]]:
    ensure_schema(con)
    cur = con.cursor()
    cur.execute("SELECT id, title, started_at FROM scan ORDER BY started_at DESC")
    return [(int(r[0]), str(r[1]), str(r[2])) for r in cur.fetchall()]

def load_scan(con: sqlite3.Connection, scan_id: int) -> Tuple[ScanHeader, List[Dict[str, Any]]]:
    ensure_schema(con)
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, title, summary, network, ip_start, ip_stop, broadcast,
               started_at, finished_at, num_process, num_run, flag_fqdn, flag_arp, flag_vendor
        FROM scan WHERE id=?
        """,
        (int(scan_id),),
    )
    r = cur.fetchone()
    if not r:
        raise ValueError("scan_id not found")
    header = ScanHeader(
        scan_id=int(r[0]),
        title=str(r[1]),
        summary=str(r[2]),
        network=str(r[3]),
        ip_start=str(r[4]),
        ip_stop=str(r[5]),
        broadcast=str(r[6]),
        started_at=str(r[7]),
        finished_at=str(r[8]),
        num_process=int(r[9]),
        num_run=int(r[10]),
        flag_fqdn=int(r[11]),
        flag_arp=int(r[12]),
        flag_vendor=int(r[13]),
    )
    cur.execute(
        """
        SELECT ip_address, alive, fqdn, mac, vendor
        FROM scan_result WHERE scan_id=?
        ORDER BY ip_address
        """,
        (int(scan_id),),
    )
    rows: List[Dict[str, Any]] = []
    for ip, alive, fqdn, mac, vendor in cur.fetchall():
        rows.append(
            {
                "ip_address": str(ip),
                "alive": bool(alive),
                "fqdn": str(fqdn),
                "mac": str(mac),
                "vendor": str(vendor),
            }
        )
    return header, rows
