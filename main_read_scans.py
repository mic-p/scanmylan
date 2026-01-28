from __future__ import annotations

import argparse
import sys
from typing import Optional

from tabulate import tabulate

from lib import db as dbmod


def _print_scan_list(scans: list[dbmod.ScanHeader]) -> None:
    rows = []
    for s in scans:
        rows.append([s.id, s.started_at, s.ended_at, s.title, s.network, "YES" if s.stopped else "NO"])
    print(tabulate(rows, headers=["ID", "Started", "Ended", "Title", "Network", "Stopped"], tablefmt="grid"))


def _print_scan_results(header: dbmod.ScanHeader, rows: list[dbmod.ScanRow], only_alive: bool) -> None:
    out = []
    for r in rows:
        if only_alive and not r.alive:
            continue
        out.append([r.ip, "YES" if r.alive else "NO", r.fqdn, r.mac, r.vendor])

    print(tabulate(
        out,
        headers=["IP", "Alive", "FQDN", "MAC", "Vendor"],
        tablefmt="grid",
    ))


def _find_by_started_at(scans: list[dbmod.ScanHeader], started_at: str) -> Optional[int]:
    # Exact match first
    for s in scans:
        if s.started_at == started_at:
            return s.id
    # If user provided a prefix, allow prefix match (useful when copy/paste)
    for s in scans:
        if s.started_at.startswith(started_at):
            return s.id
    return None


def _interactive_select(dbfile: str, only_alive: bool) -> int:
    scans = dbmod.list_scans(dbfile)
    if not scans:
        print("[INFO] No scans found.")
        return 1

    # Try curses (Linux/macOS). If it fails, fall back to simple prompt.
    try:
        import curses  # type: ignore

        def _curses_main(stdscr):
            curses.curs_set(0)
            stdscr.nodelay(False)
            pos = 0

            while True:
                stdscr.erase()
                stdscr.addstr(0, 0, "Select a scan (UP/DOWN, ENTER to open, q to quit)")
                stdscr.addstr(1, 0, "-" * 80)

                for i, s in enumerate(scans[: min(len(scans), curses.LINES - 4)]):
                    prefix = "-> " if i == pos else "   "
                    line = f"{prefix}{s.id} | {s.started_at} | {s.title}"
                    stdscr.addstr(2 + i, 0, line[: max(0, curses.COLS - 1)])

                ch = stdscr.getch()
                if ch in (ord("q"), ord("Q")):
                    return None
                if ch in (curses.KEY_UP, ord("k")):
                    pos = max(0, pos - 1)
                elif ch in (curses.KEY_DOWN, ord("j")):
                    pos = min(len(scans) - 1, pos + 1)
                elif ch in (10, 13):  # Enter
                    return scans[pos].id

        scan_id = curses.wrapper(_curses_main)
        if scan_id is None:
            return 0

    except Exception:
        # Fallback prompt (works on Windows too)
        print("Available scans:")
        _print_scan_list(scans)
        while True:
            raw = input("Enter scan ID to open (or empty to quit): ").strip()
            if not raw:
                return 0
            try:
                scan_id = int(raw)
                break
            except ValueError:
                print("Invalid ID. Try again.")
                continue

    header, rows = dbmod.load_scan(dbfile, scan_id)
    print(f"\n[SCAN] {header.id} | {header.started_at} | {header.title} | {header.network}\n")
    _print_scan_results(header, rows, only_alive=only_alive)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Read LAN Scanner SQLite DB")
    p.add_argument("--dbfile", required=True, help="Path to the SQLite DB created by the scanner")

    g = p.add_mutually_exclusive_group(required=False)
    g.add_argument("--list", action="store_true", help="List available scans")
    g.add_argument("--show-id", type=int, help="Show a scan by ID")
    g.add_argument("--show-started-at", help="Show a scan by started_at (exact or prefix match)")
    g.add_argument("--latest", action="store_true", help="Show the most recent scan")
    g.add_argument("--interactive", action="store_true", help="Interactive selection (curses if available)")

    p.add_argument("--only-alive", action="store_true", help="Show/print only alive hosts")

    args = p.parse_args()

    scans = dbmod.list_scans(args.dbfile)

    if args.list:
        if not scans:
            print("[INFO] No scans found.")
            return 0
        _print_scan_list(scans)
        return 0

    if args.interactive:
        return _interactive_select(args.dbfile, only_alive=args.only_alive)

    # Default behavior if no mode: list + exit with hint
    if not (args.show_id or args.show_started_at or args.latest):
        if not scans:
            print("[INFO] No scans found.")
            return 0
        _print_scan_list(scans)
        print("\nTip: use --show-id <ID>, --latest, --show-started-at <timestamp>, or --interactive")
        return 0

    if args.latest:
        if not scans:
            print("[INFO] No scans found.")
            return 0
        scan_id = scans[0].id
    elif args.show_id is not None:
        scan_id = args.show_id
    else:
        if not scans:
            print("[INFO] No scans found.")
            return 0
        found = _find_by_started_at(scans, args.show_started_at or "")
        if found is None:
            print("[ERROR] No scan found for that started_at.")
            return 2
        scan_id = found

    header, rows = dbmod.load_scan(args.dbfile, scan_id)
    print(f"[SCAN] {header.id} | {header.started_at} | {header.title} | {header.network}\n")
    _print_scan_results(header, rows, only_alive=args.only_alive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

