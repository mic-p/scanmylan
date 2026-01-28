from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any, Dict, List

# NEW DB (no compatibility):
# scan (1) -> scan_result (N)

SCHEMA_SQL = """
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS scan (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  network TEXT NOT NULL,
  ip_start TEXT NOT NULL,
  ip_stop TEXT NOT NULL,
  broadcast TEXT NOT NULL,
  num_process INTEGER NOT NULL,
  num_run INTEGER NOT NULL,
  flag_fqdn INTEGER NOT NULL,
  flag_arp INTEGER NOT NULL,
  flag_vendor INTEGER NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT NOT NULL,
  stopped INTEGER NOT NULL DEFAULT 0
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

CREATE INDEX IF NOT EXISTS idx_scan_started_at ON scan(started_at);
CREATE INDEX IF NOT EXISTS idx_scan_result_scan_id ON scan_result(scan_id);
"""

@dataclass
class ScanHeader:
    id: int
    title: str
    started_at: str
    ended_at: str
    network: str
    ip_start: str
    ip_stop: str
    broadcast: str
    num_process: int
    num_run: int
    flag_fqdn: bool
    flag_arp: bool
    flag_vendor: bool
    stopped: bool

@dataclass
class ScanRow:
    ip: str
    alive: bool
    fqdn: str
    mac: str
    vendor: str

def connect(dbfile: str) -> sqlite3.Connection:
    con = sqlite3.connect(dbfile)
    con.execute("PRAGMA foreign_keys=ON;")
    con.executescript(SCHEMA_SQL)
    con.commit()
    return con

def insert_scan(dbfile: str, header: Dict[str, Any], rows: List[Dict[str, Any]]) -> int:
    con = connect(dbfile)
    cur = con.cursor()
    cur.execute(
        """INSERT INTO scan
        (title, network, ip_start, ip_stop, broadcast, num_process, num_run,
         flag_fqdn, flag_arp, flag_vendor, started_at, ended_at, stopped)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            header["title"],
            header["network"],
            header["ip_start"],
            header["ip_stop"],
            header["broadcast"],
            int(header["num_process"]),
            int(header["num_run"]),
            1 if header["flag_fqdn"] else 0,
            1 if header["flag_arp"] else 0,
            1 if header["flag_vendor"] else 0,
            header["started_at"],
            header["ended_at"],
            1 if header.get("stopped", False) else 0,
        ),
    )
    scan_id = int(cur.lastrowid)
    cur.executemany(
        """INSERT INTO scan_result (scan_id, ip, alive, fqdn, mac, vendor)
             VALUES (?,?,?,?,?,?)""",
        [
            (
                scan_id,
                r["ip"],
                1 if r.get("alive", False) else 0,
                r.get("fqdn", "") or "",
                r.get("mac", "") or "",
                r.get("vendor", "") or "",
            )
            for r in rows
        ],
    )
    con.commit()
    con.close()
    return scan_id

def list_scans(dbfile: str) -> List[ScanHeader]:
    con = connect(dbfile)
    cur = con.cursor()
    cur.execute(
        """SELECT id, title, started_at, ended_at, network, ip_start, ip_stop, broadcast,
                  num_process, num_run, flag_fqdn, flag_arp, flag_vendor, stopped
           FROM scan
           ORDER BY datetime(started_at) DESC, id DESC"""
    )
    out: List[ScanHeader] = []
    for r in cur.fetchall():
        out.append(
            ScanHeader(
                id=r[0], title=r[1], started_at=r[2], ended_at=r[3], network=r[4],
                ip_start=r[5], ip_stop=r[6], broadcast=r[7],
                num_process=int(r[8]), num_run=int(r[9]),
                flag_fqdn=bool(r[10]), flag_arp=bool(r[11]), flag_vendor=bool(r[12]),
                stopped=bool(r[13]),
            )
        )
    con.close()
    return out

def load_scan(dbfile: str, scan_id: int) -> tuple[ScanHeader, List[ScanRow]]:
    con = connect(dbfile)
    cur = con.cursor()
    cur.execute(
        """SELECT id, title, started_at, ended_at, network, ip_start, ip_stop, broadcast,
                  num_process, num_run, flag_fqdn, flag_arp, flag_vendor, stopped
           FROM scan WHERE id=?""",
        (scan_id,),
    )
    r = cur.fetchone()
    if not r:
        con.close()
        raise ValueError("scan not found")
    header = ScanHeader(
        id=r[0], title=r[1], started_at=r[2], ended_at=r[3], network=r[4],
        ip_start=r[5], ip_stop=r[6], broadcast=r[7],
        num_process=int(r[8]), num_run=int(r[9]),
        flag_fqdn=bool(r[10]), flag_arp=bool(r[11]), flag_vendor=bool(r[12]),
        stopped=bool(r[13]),
    )
    cur.execute("SELECT ip, alive, fqdn, mac, vendor FROM scan_result WHERE scan_id=? ORDER BY id ASC", (scan_id,))
    rows: List[ScanRow] = []
    for rr in cur.fetchall():
        rows.append(ScanRow(ip=rr[0], alive=bool(rr[1]), fqdn=rr[2] or "", mac=rr[3] or "", vendor=rr[4] or ""))
    con.close()
    return header, rows
