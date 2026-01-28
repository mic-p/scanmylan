from __future__ import annotations

import sys
import argparse
from datetime import datetime

from lib.netcalc import parse_network
from lib.scanner import LanScanner, ScanConfig
from lib import db as dbmod

def run_cli(args: argparse.Namespace) -> int:
    ni = parse_network(args.network)

    cfg = ScanConfig(
        title=args.title or "",
        network=ni.network,
        ip_start=ni.ip_start,
        ip_stop=ni.ip_stop,
        broadcast=ni.broadcast,
        num_process=args.num_process,
        num_run=args.num_run,
        flag_fqdn=not args.no_fqdn,
        flag_arp=not args.no_arp,
        flag_vendor=not args.no_vendor,
    )

    started_at = datetime.now().isoformat(timespec="seconds")
    total = len(ni.hosts)

    print(f"[INFO] Starting scan on network: {ni.network}")
    print(f"[INFO] Host count: {total}")
    print(f"[INFO] Concurrency: {cfg.num_process} | Retries: {cfg.num_run}")
    print("[INFO] Pipeline: ping -> (fqdn) -> (arp) -> (vendor) per alive host")

    results = []

    # Better progress: always show from the beginning.
    try:
        from tqdm import tqdm  # type: ignore
        bar = tqdm(total=total, desc="Scanning", unit="host")
        def on_progress(d, t):
            bar.n = d
            bar.refresh()
    except Exception:
        bar = None
        def on_progress(d, t):
            print(f"[PROGRESS] {d}/{t}")

    scanner = LanScanner(
        ips=ni.hosts,
        config=cfg,
        on_host=lambda r: results.append(r),
        on_progress=on_progress,
        on_state=lambda s: print(f"[STATE] {s}"),
    )

    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n[WARN] CTRL+C received: stopping now. (Nothing will be saved)")
        scanner.stop()
        return 2
    finally:
        if bar is not None:
            try:
                bar.close()
            except Exception:
                pass

    ended_at = datetime.now().isoformat(timespec="seconds")

    header = {
        "title": cfg.title,
        "network": cfg.network,
        "ip_start": cfg.ip_start,
        "ip_stop": cfg.ip_stop,
        "broadcast": cfg.broadcast,
        "num_process": cfg.num_process,
        "num_run": cfg.num_run,
        "flag_fqdn": cfg.flag_fqdn,
        "flag_arp": cfg.flag_arp,
        "flag_vendor": cfg.flag_vendor,
        "started_at": started_at,
        "ended_at": ended_at,
        "stopped": False,
    }
    rows = [{"ip": r.ip, "alive": r.alive, "fqdn": r.fqdn, "mac": r.mac, "vendor": r.vendor} for r in results]
    scan_id = dbmod.insert_scan(args.dbfile, header, rows)
    print(f"[INFO] Saved to DB: {args.dbfile} (scan_id={scan_id})")

    from tabulate import tabulate  # type: ignore
    import ipaddress

    table = []
    for r in sorted(results, key=lambda x: int(ipaddress.IPv4Address(x.ip))):
        # If user requested only alive hosts, skip dead entries
        if args.only_alive and not r.alive:
            continue

        table.append([r.ip, "YES" if r.alive else "NO", r.fqdn, r.mac, r.vendor])

    print(tabulate(table, headers=["IP", "Alive", "FQDN", "MAC", "Vendor"], tablefmt="grid"))
    return 0

def main() -> int:
    p = argparse.ArgumentParser(description="LAN Scanner (GUI or CLI)")
    p.add_argument("--network", help="IPv4 CIDR (e.g. 192.168.1.0/24) or single IPv4 (treated as /32)")
    p.add_argument("--dbfile", help="SQLite DB file (required in CLI mode)")
    p.add_argument("--title", default="", help="Scan title")
    p.add_argument("--num-process", type=int, default=5, help="Concurrent ping processes")
    p.add_argument("--num-run", type=int, default=2, help="Ping retries per host")
    p.add_argument("--no-fqdn", action="store_true", help="Disable FQDN lookup")
    p.add_argument("--no-arp", action="store_true", help="Disable ARP lookup")
    p.add_argument("--no-vendor", action="store_true", help="Disable vendor lookup")
    p.add_argument("--only-alive", action="store_true", help="Print only alive hosts")
    args = p.parse_args()

    if args.network and not args.dbfile:
        print ("\nPlease pass also dbfile!\n")
        p.print_help()
        return 2
    elif args.network and args.dbfile:
        return run_cli(args)

    from main_gui import main as gui_main
    return gui_main()

if __name__ == "__main__":
    raise SystemExit(main())
