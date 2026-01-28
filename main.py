from __future__ import annotations

import argparse
import signal
import sys
from datetime import datetime
from typing import Any, Dict, List

from lib.scanner import LanScanner
from lib import db as db_lib


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_cli(args: argparse.Namespace) -> int:
    started_at = now_text()
    interrupted = False
    results: List[Dict[str, Any]] = []

    use_tqdm = False
    pbar = None
    try:
        from tqdm import tqdm  # type: ignore
        use_tqdm = True
    except Exception:
        use_tqdm = False

    def on_progress(done: int, total: int):
        nonlocal pbar
        if use_tqdm:
            if pbar is None:
                from tqdm import tqdm  # type: ignore
                pbar = tqdm(total=total, unit="host")
            pbar.total = total
            pbar.n = done
            pbar.refresh()
        else:
            if total > 0 and (done == total or done % 10 == 0):
                print(f"progress: {done}/{total}")

    def on_state(s: str):
        if s:
            print(f"state: {s}")

    scanner = LanScanner(
        network=args.network,
        num_process=args.num_process,
        num_run=args.num_run,
        flag_fqdn=not args.no_fqdn,
        flag_arp=not args.no_arp,
        flag_vendor=not args.no_vendor,
        on_progress=on_progress,
        on_state=on_state,
    )

    def handle_sigint(sig, frame):
        nonlocal interrupted
        interrupted = True
        scanner.stop()

    signal.signal(signal.SIGINT, handle_sigint)

    try:
        results = scanner.run()
    finally:
        if pbar is not None:
            pbar.close()

    if interrupted:
        print("\nInterrotto (CTRL+C): stop completo, NON salvo nulla.")
        return 130

    finished_at = now_text()

    info = LanScanner.compute_network_info(args.network)
    con = db_lib.connect(args.dbfile)
    db_lib.insert_scan(
        con,
        title=args.title or "(senza titolo)",
        summary=args.summary or "",
        network=info.get("network", ""),
        ip_start=info.get("ip_start", ""),
        ip_stop=info.get("ip_stop", ""),
        broadcast=info.get("broadcast", ""),
        started_at=started_at,
        finished_at=finished_at,
        num_process=args.num_process,
        num_run=args.num_run,
        flag_fqdn=not args.no_fqdn,
        flag_arp=not args.no_arp,
        flag_vendor=not args.no_vendor,
        results=results,
    )
    con.close()

    try:
        from tabulate import tabulate  # type: ignore
        table = []
        for r in results:
            table.append([
                r.get("ip_address", ""),
                r.get("fqdn", ""),
                r.get("mac", ""),
                r.get("vendor", ""),
                "yes" if r.get("alive") else "no",
            ])
        print("\n" + tabulate(table, headers=["ip_address", "fqdn", "arp", "vendor", "alive"], tablefmt="github"))
    except Exception:
        for r in results:
            print(r)

    print(f"\nSalvato su: {args.dbfile}")
    return 0


def main():
    if len(sys.argv) == 1:
        from main_gui import main as gui_main
        gui_main()
        return

    parser = argparse.ArgumentParser(description="LAN Scanner (CLI/GUI)")
    parser.add_argument("--network", help="IPv4 CIDR network, es: 192.168.88.0/24")
    parser.add_argument("--dbfile", help="Path file SQLite per salvare (CLI)")
    parser.add_argument("--title", default="", help="Titolo scansione")
    parser.add_argument("--summary", default="", help="Riassunto scansione")

    parser.add_argument("--num-process", type=int, default=5, dest="num_process", help="Ping concorrenti")
    parser.add_argument("--num-run", type=int, default=2, dest="num_run", help="Retry per IP")

    parser.add_argument("--no-fqdn", action="store_true", help="Disabilita fqdn")
    parser.add_argument("--no-arp", action="store_true", help="Disabilita arp")
    parser.add_argument("--no-vendor", action="store_true", help="Disabilita vendor")

    args = parser.parse_args()

    if not args.network or not args.dbfile:
        from main_gui import main as gui_main
        gui_main()
        return

    sys.exit(run_cli(args))


if __name__ == "__main__":
    main()
