from __future__ import annotations

import ipaddress
from dataclasses import dataclass

@dataclass(frozen=True)
class NetInfo:
    network: str
    ip_start: str
    ip_stop: str
    broadcast: str
    hosts: list[str]

def parse_network(text: str) -> NetInfo:
    # IPv4 CIDR only. If single IPv4 is provided, treat as /32.
    text = (text or "").strip()
    if not text:
        raise ValueError("empty")
    if "/" not in text:
        text = f"{text}/32"
    net = ipaddress.ip_network(text, strict=False)
    if not isinstance(net, ipaddress.IPv4Network):
        raise ValueError("IPv4 only")
    hosts = [str(h) for h in net.hosts()]
    if net.prefixlen == 32:
        hosts = [str(net.network_address)]
    ip_start = hosts[0] if hosts else str(net.network_address)
    ip_stop = hosts[-1] if hosts else str(net.broadcast_address)
    return NetInfo(
        network=str(net),
        ip_start=ip_start,
        ip_stop=ip_stop,
        broadcast=str(net.broadcast_address),
        hosts=hosts,
    )
