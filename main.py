"""Unified entry point.

- If executed with --network and --dbfile -> CLI scan and save, then exit.
- Otherwise -> start GUI.

CLI requirements:
- Use subprocess ping (through ScannerEngine)
- Progress messages should be clear from the very start
- Final output printed with tabulate
- Ctrl+C stops everything and DOES NOT save
"""

from __future__ import annotations

import argparse
import sys
import datetime as _dt

from tabulate import tabulate

from lib.netcalc import parse_network
from lib.scanner import ScannerEngine
from lib import db as dbmod


def _now_str() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_cli(args: argparse.Namespace) -> int:
    info = parse_network(args.network)

    title = (args.title or "").strip()
    if not title:
        title = f"Scan {info.network_cidr}"

    started_at = _now_str()

    print(f"[+] Starting scan\n    title: {title}\n    network: {info.network_cidr}\n    hosts: {len(info.hosts)}\n    concurrent: {args.num_process}\n    ping_retries: {args.num_run}\n")
    print(f"[+] Options: fqdn={args.fqdn} arp={args.arp} vendor={args.vendor}\n")

    engine = ScannerEngine(
        num_process=args.num_process,
        num_run=args.num_run,
        flag_fqdn=args.fqdn,
        flag_arp=args.arp,
        flag_vendor=args.vendor,
    )

    # Progress: prefer tqdm, fallback to simple prints.
    try:
        from tqdm import tqdm  # type: ignore
        bar = tqdm(total=len(info.hosts), desc="Scanning", unit="host")
        def on_progress(done: int, total: int):
            bar.n = done
            bar.total = total
            bar.refresh()
    except Exception:
        bar = None
        def on_progress(done: int, total: int):
            # Print immediately from 0->1 so user sees it's running
            if done == 1 or done == total or done % 10 == 0:
                print(f"[=] Progress: {done}/{total}", flush=True)

    def on_state(s: str):
        # We emit at least one clear message early
        print(f"[+] State: {s}", flush=True)

    results = []
    try:
        # Emit an explicit initial progress line
        on_state("ping + per-host details")
        on_progress(0, len(info.hosts))
        results = engine.scan_many(info.hosts, on_progress=on_progress, on_state=on_state)
        if bar is not None:
            bar.close()
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C received: stopping scan (no save).", flush=True)
        engine.stop()
        return 2

    ended_at = _now_str()

    # Print table with tabulate
    table = []
    for r in results:
        table.append([r.ip, "yes" if r.alive else "no", r.fqdn, r.mac, r.vendor])

    print("\n[+] Scan completed")
    print(f"    started: {started_at}")
    print(f"    ended:   {ended_at}\n")

    print(tabulate(table, headers=["ip", "alive", "fqdn", "arp_mac", "vendor"], tablefmt="github"))

    # Save
    conn = dbmod.connect(args.dbfile)
    dbmod.init_db(conn)
    scan_rows = [dbmod.ScanRow(ip=r.ip, alive=int(bool(r.alive)), fqdn=r.fqdn or "", mac=r.mac or "", vendor=r.vendor or "") for r in results]
    dbmod.insert_scan(
        conn,
        title=title,
        network_cidr=info.network_cidr,
        ip_start=info.ip_start,
        ip_stop=info.ip_stop,
        broadcast=info.broadcast,
        started_at=started_at,
        ended_at=ended_at,
        num_process=args.num_process,
        num_run=args.num_run,
        flag_fqdn=args.fqdn,
        flag_arp=args.arp,
        flag_vendor=args.vendor,
        rows=scan_rows,
    )
    conn.close()
    print(f"\n[+] Saved to DB: {args.dbfile}")
    return 0


def run_gui() -> int:
    from main_gui import main
    return main()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="LAN scanner (CLI or GUI)")
    p.add_argument("--network", help="IPv4 network in CIDR (e.g. 192.168.1.0/24)")
    p.add_argument("--dbfile", help="SQLite DB file to save results (CLI mode)")
    p.add_argument("--title", default="", help="Scan title")
    p.add_argument("--num-process", type=int, default=5, help="Concurrent ping processes")
    p.add_argument("--num-run", type=int, default=2, help="Ping retries per host")
    p.add_argument("--fqdn", action=argparse.BooleanOptionalAction, default=True, help="Resolve FQDN")
    p.add_argument("--arp", action=argparse.BooleanOptionalAction, default=True, help="Read ARP MAC")
    p.add_argument("--vendor", action=argparse.BooleanOptionalAction, default=True, help="Vendor lookup")
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.network and args.dbfile:
        return run_cli(args)

    # No CLI args: start GUI
    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
