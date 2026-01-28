"""Network calculation using ipaddress.

Input:
- IPv4 CIDR (e.g. 192.168.1.0/24)
- single IPv4 address is accepted and treated as /32

Output:
- list of host IP strings (excluding network & broadcast)
- ip_start/ip_stop/broadcast for UI display
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import List


@dataclass
class NetInfo:
    network_cidr: str
    ip_start: str
    ip_stop: str
    broadcast: str
    hosts: List[str]


def parse_network(text: str) -> NetInfo:
    raw = (text or "").strip()
    if not raw:
        raise ValueError("empty")

    # Accept single IP and treat as /32
    if "/" not in raw:
        raw = f"{raw}/32"

    net = ipaddress.IPv4Network(raw, strict=False)

    hosts = [str(h) for h in net.hosts()]  # excludes network & broadcast
    ip_start = hosts[0] if hosts else str(net.network_address)
    ip_stop = hosts[-1] if hosts else str(net.broadcast_address)
    broadcast = str(net.broadcast_address)

    return NetInfo(
        network_cidr=str(net.with_prefixlen),
        ip_start=ip_start,
        ip_stop=ip_stop,
        broadcast=broadcast,
        hosts=hosts,
    )
