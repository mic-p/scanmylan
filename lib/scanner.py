"""Scanning engine.

Pipeline per IP (only if ping is alive):
A+B) ping with retries, concurrency = num_process
C) fqdn (optional)
D) arp lookup (optional) immediately after the ping success
E) vendor lookup (optional) immediately after mac was found

Stop behavior:
- sets a stop event
- terminates and kills all running ping subprocesses
- worker functions should check the stop event between steps
"""

from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from .icmp import popen_ping, DEFAULT_TIMEOUT_SEC, DEFAULT_ECHO_COUNT
from .arp import get_mac_for_ip
from .vendor import lookup_vendor


@dataclass
class HostResult:
    ip: str
    alive: bool
    fqdn: str = ""
    mac: str = ""
    vendor: str = ""


class ScannerEngine:
    def __init__(
        self,
        *,
        num_process: int = 5,
        num_run: int = 2,
        flag_fqdn: bool = True,
        flag_arp: bool = True,
        flag_vendor: bool = True,
        ping_timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        ping_echo_count: int = DEFAULT_ECHO_COUNT,
    ):
        self.num_process = int(num_process)
        self.num_run = int(num_run)
        self.flag_fqdn = bool(flag_fqdn)
        self.flag_arp = bool(flag_arp)
        self.flag_vendor = bool(flag_vendor)
        self.ping_timeout_sec = int(ping_timeout_sec)
        self.ping_echo_count = int(ping_echo_count)

        self._stop_evt = threading.Event()
        self._procs_lock = threading.Lock()
        self._running_procs = set()  # type: ignore[var-annotated]

    def stop(self) -> None:
        self._stop_evt.set()
        # Kill all running ping processes
        with self._procs_lock:
            procs = list(self._running_procs)

        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass

        # Give a very short grace period, then hard kill
        time.sleep(0.1)
        for p in procs:
            try:
                if p.poll() is None:
                    p.kill()
            except Exception:
                pass

    def is_stopped(self) -> bool:
        return self._stop_evt.is_set()

    def _register_proc(self, p) -> None:
        with self._procs_lock:
            self._running_procs.add(p)

    def _unregister_proc(self, p) -> None:
        with self._procs_lock:
            self._running_procs.discard(p)

    def _ping_with_retries(self, ip: str) -> bool:
        # Retry logic: up to num_run times when return code != 0
        for _ in range(max(1, self.num_run)):
            if self.is_stopped():
                return False
            p = popen_ping(ip, timeout_sec=self.ping_timeout_sec, echo_count=self.ping_echo_count)
            self._register_proc(p)
            try:
                rc = p.wait()
            finally:
                self._unregister_proc(p)

            if rc == 0:
                return True
        return False

    def _resolve_fqdn(self, ip: str) -> str:
        if not self.flag_fqdn or self.is_stopped():
            return ""
        # Keep DNS lookups bounded
        old = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(2.0)
            try:
                return socket.gethostbyaddr(ip)[0] or ""
            except Exception:
                return ""
        finally:
            socket.setdefaulttimeout(old)

    def _resolve_arp_mac(self, ip: str) -> str:
        if not self.flag_arp or self.is_stopped():
            return ""
        try:
            return get_mac_for_ip(ip) or ""
        except Exception:
            return ""

    def _resolve_vendor(self, mac: str) -> str:
        if not self.flag_vendor or self.is_stopped() or not mac:
            return ""
        try:
            return lookup_vendor(mac) or ""
        except Exception:
            return ""

    def scan_one(self, ip: str) -> HostResult:
        # This method is used both by bulk scan and by GUI "Re-scan".
        alive = self._ping_with_retries(ip)
        if self.is_stopped():
            return HostResult(ip=ip, alive=False)

        if not alive:
            return HostResult(ip=ip, alive=False)

        fqdn = self._resolve_fqdn(ip)
        mac = self._resolve_arp_mac(ip)
        vendor = self._resolve_vendor(mac)

        return HostResult(ip=ip, alive=True, fqdn=fqdn, mac=mac, vendor=vendor)

    def scan_many(
        self,
        ips: Iterable[str],
        *,
        on_host: Optional[Callable[[HostResult], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_state: Optional[Callable[[str], None]] = None,
    ) -> List[HostResult]:
        ips_list = list(ips)
        total = len(ips_list)
        done = 0
        results: Dict[str, HostResult] = {}

        if on_state:
            on_state("ping+details")

        with ThreadPoolExecutor(max_workers=self.num_process) as ex:
            fut_map = {ex.submit(self.scan_one, ip): ip for ip in ips_list}
            for fut in as_completed(fut_map):
                if self.is_stopped():
                    break
                ip = fut_map[fut]
                try:
                    res = fut.result()
                except Exception:
                    res = HostResult(ip=ip, alive=False)

                results[ip] = res
                done += 1
                if on_host:
                    on_host(res)
                if on_progress:
                    on_progress(done, total)

        # Return results in the original IP order
        return [results.get(ip, HostResult(ip=ip, alive=False)) for ip in ips_list]
