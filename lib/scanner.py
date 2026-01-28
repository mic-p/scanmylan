from __future__ import annotations
import ipaddress
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Callable, Dict, List, Optional, Any

from .icmp import popen_ping, DEFAULT_TIMEOUT_SECONDS, DEFAULT_ECHO_COUNT
from .arp import read_arp_table
from .vendor import vendor_from_mac

@dataclass
class HostResult:
    ip_address: str
    alive: bool = False
    fqdn: str = ""
    mac: str = ""
    vendor: str = ""

class LanScanner:
    def __init__(
        self,
        *,
        network: str,
        num_process: int = 5,
        num_run: int = 2,
        flag_fqdn: bool = True,
        flag_arp: bool = True,
        flag_vendor: bool = True,
        ping_timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        ping_echo_count: int = DEFAULT_ECHO_COUNT,
        on_host: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_state: Optional[Callable[[str], None]] = None,
    ):
        self.network = network
        self.num_process = int(num_process)
        self.num_run = int(num_run)
        self.flag_fqdn = bool(flag_fqdn)
        self.flag_arp = bool(flag_arp)
        self.flag_vendor = bool(flag_vendor)
        self.ping_timeout_seconds = int(ping_timeout_seconds)
        self.ping_echo_count = int(ping_echo_count)

        self.on_host = on_host
        self.on_progress = on_progress
        self.on_state = on_state

        self._stop_event = threading.Event()
        self._active_lock = threading.Lock()
        self._active_procs = set()
        self._results: Dict[str, HostResult] = {}

    def stop(self) -> None:
        self._stop_event.set()
        with self._active_lock:
            procs = list(self._active_procs)
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        time.sleep(0.2)
        for p in procs:
            try:
                if p.poll() is None:
                    p.kill()
            except Exception:
                pass

    def stopped(self) -> bool:
        return self._stop_event.is_set()

    def _emit_host(self, hr: HostResult) -> None:
        if self.on_host:
            self.on_host(asdict(hr))

    def _emit_progress(self, done: int, total: int) -> None:
        if self.on_progress:
            self.on_progress(done, total)

    def _emit_state(self, text: str) -> None:
        if self.on_state:
            self.on_state(text)

    @staticmethod
    def compute_network_info(network_text: str) -> Dict[str, str]:
        network_text = (network_text or "").strip()
        if not network_text:
            raise ValueError("Network vuota")
        if "/" not in network_text:
            network_text = f"{network_text}/32"
        net = ipaddress.ip_network(network_text, strict=False)
        if net.version != 4:
            raise ValueError("Solo IPv4 supportato")
        if net.prefixlen == 32:
            ip_start = str(net.network_address)
            ip_stop = str(net.network_address)
        else:
            hosts = list(net.hosts())
            ip_start = str(hosts[0])
            ip_stop = str(hosts[-1])
        return {
            "network": str(net.with_prefixlen),
            "ip_start": ip_start,
            "ip_stop": ip_stop,
            "broadcast": str(net.broadcast_address),
        }

    def _iter_hosts(self) -> List[str]:
        info = self.compute_network_info(self.network)
        net = ipaddress.ip_network(info["network"], strict=False)
        if net.prefixlen == 32:
            return [str(net.network_address)]
        return [str(h) for h in net.hosts()]

    def run(self) -> List[Dict[str, Any]]:
        self._stop_event.clear()
        self._results.clear()

        hosts = self._iter_hosts()
        total = len(hosts)
        done = 0

        self._emit_state("ping")

        def ping_task(ip: str) -> HostResult:
            hr = HostResult(ip_address=ip)
            if self.stopped():
                return hr
            for _ in range(max(1, self.num_run)):
                if self.stopped():
                    return hr
                p = popen_ping(ip, timeout_seconds=self.ping_timeout_seconds, echo_count=self.ping_echo_count)
                with self._active_lock:
                    self._active_procs.add(p)
                try:
                    p.communicate()
                    rc = p.returncode if p.returncode is not None else 1
                finally:
                    with self._active_lock:
                        self._active_procs.discard(p)
                if rc == 0:
                    hr.alive = True
                    break
            return hr

        with ThreadPoolExecutor(max_workers=max(1, self.num_process)) as ex:
            future_map = {ex.submit(ping_task, ip): ip for ip in hosts}
            for fut in as_completed(future_map):
                if self.stopped():
                    break
                hr = fut.result()
                self._results[hr.ip_address] = hr
                self._emit_host(hr)
                done += 1
                self._emit_progress(done, total)

        if self.stopped():
            self._emit_state("stopped")
            return [asdict(v) for v in self._results.values()]

        if self.flag_fqdn:
            self._emit_state("fqdn")
            socket.setdefaulttimeout(2.0)
            for hr in list(self._results.values()):
                if self.stopped():
                    break
                if not hr.alive:
                    continue
                try:
                    hr.fqdn = socket.gethostbyaddr(hr.ip_address)[0] or ""
                except Exception:
                    hr.fqdn = ""
                self._emit_host(hr)

        if self.stopped():
            self._emit_state("stopped")
            return [asdict(v) for v in self._results.values()]

        arp_map: Dict[str, str] = {}
        if self.flag_arp:
            self._emit_state("arp")
            try:
                arp_map = read_arp_table()
            except Exception:
                arp_map = {}
            for hr in list(self._results.values()):
                if self.stopped():
                    break
                if not hr.alive:
                    continue
                hr.mac = arp_map.get(hr.ip_address, "") or ""
                self._emit_host(hr)

        if self.stopped():
            self._emit_state("stopped")
            return [asdict(v) for v in self._results.values()]

        if self.flag_vendor:
            self._emit_state("vendor")
            for hr in list(self._results.values()):
                if self.stopped():
                    break
                if not hr.alive or not hr.mac:
                    continue
                hr.vendor = vendor_from_mac(hr.mac) or ""
                self._emit_host(hr)

        self._emit_state("done" if not self.stopped() else "stopped")
        return [asdict(self._results[ip]) for ip in sorted(self._results.keys(), key=lambda x: ipaddress.ip_address(x))]
