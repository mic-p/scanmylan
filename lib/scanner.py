from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .icmp import popen_ping, DEFAULT_TIMEOUT_SEC, DEFAULT_ECHO_COUNT
from .arp import get_mac_for_ip
from .vendor import vendor_from_mac

# Scanning pipeline per IP:
# 1) Ping (with retries)
# 2) If alive: FQDN (optional)
# 3) If alive: ARP (optional) - immediately after successful ping
# 4) If alive and MAC exists: Vendor (optional) - immediately after ARP
#
# Stop:
# - Set stop event
# - Terminate and kill all running ping subprocesses
# - Workers stop as soon as possible

@dataclass
class ScanResult:
    ip: str
    alive: bool = False
    fqdn: str = ""
    mac: str = ""
    vendor: str = ""

@dataclass
class ScanConfig:
    title: str
    network: str
    ip_start: str
    ip_stop: str
    broadcast: str
    num_process: int = 5
    num_run: int = 2
    flag_fqdn: bool = True
    flag_arp: bool = True
    flag_vendor: bool = True

class LanScanner:
    def __init__(
        self,
        ips: List[str],
        config: ScanConfig,
        on_host: Optional[Callable[[ScanResult], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_state: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.ips = ips
        self.config = config
        self.on_host = on_host
        self.on_progress = on_progress
        self.on_state = on_state

        self._stop_evt = threading.Event()
        self._lock = threading.Lock()
        self._running_procs: Dict[str, object] = {}

    def stop(self) -> None:
        self._stop_evt.set()
        with self._lock:
            procs = list(self._running_procs.values())
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass

    def _emit_state(self, s: str) -> None:
        if self.on_state:
            try:
                self.on_state(s)
            except Exception:
                pass

    def _emit_progress(self, done: int, total: int) -> None:
        if self.on_progress:
            try:
                self.on_progress(done, total)
            except Exception:
                pass

    def _emit_host(self, r: ScanResult) -> None:
        if self.on_host:
            try:
                self.on_host(r)
            except Exception:
                pass

    def _ping_with_retries(self, ip: str) -> bool:
        for _ in range(int(self.config.num_run)):
            if self._stop_evt.is_set():
                return False
            p = popen_ping(ip, timeout_sec=DEFAULT_TIMEOUT_SEC, echo_count=DEFAULT_ECHO_COUNT)
            with self._lock:
                self._running_procs[ip] = p
            try:
                rc = p.wait(timeout=DEFAULT_TIMEOUT_SEC * (DEFAULT_ECHO_COUNT + 1) + 1)
                ok = (rc == 0)
            except Exception:
                ok = False
                try:
                    p.terminate()
                except Exception:
                    pass
                try:
                    p.kill()
                except Exception:
                    pass
            finally:
                with self._lock:
                    self._running_procs.pop(ip, None)
            if ok:
                return True
        return False

    def _fqdn(self, ip: str) -> str:
        if not self.config.flag_fqdn or self._stop_evt.is_set():
            return ""
        try:
            old = socket.getdefaulttimeout()
            socket.setdefaulttimeout(2)
            try:
                return socket.gethostbyaddr(ip)[0] or ""
            finally:
                socket.setdefaulttimeout(old)
        except Exception:
            return ""

    def _arp_mac(self, ip: str) -> str:
        if not self.config.flag_arp or self._stop_evt.is_set():
            return ""
        try:
            return get_mac_for_ip(ip) or ""
        except Exception:
            return ""

    def _vendor(self, mac: str) -> str:
        if not self.config.flag_vendor or self._stop_evt.is_set():
            return ""
        try:
            return vendor_from_mac(mac) or ""
        except Exception:
            return ""

    def _scan_one(self, ip: str) -> ScanResult:
        r = ScanResult(ip=ip)
        if self._stop_evt.is_set():
            return r

        r.alive = self._ping_with_retries(ip)
        if not r.alive or self._stop_evt.is_set():
            return r

        r.fqdn = self._fqdn(ip)
        if self._stop_evt.is_set():
            return r

        r.mac = self._arp_mac(ip)
        if self._stop_evt.is_set():
            return r

        if r.mac:
            r.vendor = self._vendor(r.mac)

        return r

    def run(self) -> List[ScanResult]:
        total = len(self.ips)
        done = 0
        results: List[ScanResult] = []
        self._emit_state("ping")

        with ThreadPoolExecutor(max_workers=int(self.config.num_process)) as ex:
            futs = {ex.submit(self._scan_one, ip): ip for ip in self.ips}
            for fut in as_completed(futs):
                if self._stop_evt.is_set():
                    break
                try:
                    r = fut.result()
                except Exception:
                    r = ScanResult(ip=futs[fut], alive=False)
                results.append(r)
                self._emit_host(r)
                done += 1
                self._emit_progress(done, total)

        return results

    def scan_single(self, ip: str) -> ScanResult:
        # Single-host scan for GUI context menu.
        self._stop_evt.clear()
        return self._scan_one(ip)
