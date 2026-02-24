"""
Interface counter state.
Maintains per-interface counters and increments them realistically
so that counter samples reflect a plausible network device.
"""

import random
import time
from dataclasses import dataclass, field


@dataclass
class InterfaceState:
    if_index: int
    if_type: int = 6           # ethernetCsmacd
    if_speed: int = 1_000_000_000  # 1 Gbps
    if_direction: int = 1      # full-duplex

    # Counters
    in_octets: int = 0
    in_ucast_pkts: int = 0
    in_multicast_pkts: int = 0
    in_broadcast_pkts: int = 0
    in_discards: int = 0
    in_errors: int = 0
    in_unknown_protos: int = 0
    out_octets: int = 0
    out_ucast_pkts: int = 0
    out_multicast_pkts: int = 0
    out_broadcast_pkts: int = 0
    out_discards: int = 0
    out_errors: int = 0
    promiscuous_mode: int = 0

    # Runtime
    last_updated: float = field(default_factory=time.time)
    admin_status: int = 1   # up
    oper_status: int = 1    # up

    def tick(self, elapsed_seconds: float, utilization: float = 0.1):
        """
        Advance counters by simulating traffic at the given utilization fraction (0.0-1.0).
        """
        bps = self.if_speed * utilization
        bytes_per_tick = bps * elapsed_seconds / 8
        pkts_per_tick = bytes_per_tick / 512  # avg 512 bytes/pkt

        in_bytes = int(bytes_per_tick * random.uniform(0.4, 0.6))
        out_bytes = int(bytes_per_tick - in_bytes)
        in_pkts = max(1, int(pkts_per_tick * random.uniform(0.4, 0.6)))
        out_pkts = max(1, int(pkts_per_tick - in_pkts))

        self.in_octets = (self.in_octets + in_bytes) & 0xFFFF_FFFF_FFFF_FFFF
        self.in_ucast_pkts = (self.in_ucast_pkts + in_pkts) & 0xFFFF_FFFF
        self.in_multicast_pkts = (self.in_multicast_pkts + max(0, int(in_pkts * 0.01))) & 0xFFFF_FFFF
        self.in_broadcast_pkts = (self.in_broadcast_pkts + max(0, int(in_pkts * 0.005))) & 0xFFFF_FFFF
        self.out_octets = (self.out_octets + out_bytes) & 0xFFFF_FFFF_FFFF_FFFF
        self.out_ucast_pkts = (self.out_ucast_pkts + out_pkts) & 0xFFFF_FFFF
        self.out_multicast_pkts = (self.out_multicast_pkts + max(0, int(out_pkts * 0.01))) & 0xFFFF_FFFF
        self.out_broadcast_pkts = (self.out_broadcast_pkts + max(0, int(out_pkts * 0.005))) & 0xFFFF_FFFF

        # Occasional errors (much rarer)
        if random.random() < 0.001:
            self.in_errors += 1
        if random.random() < 0.001:
            self.out_errors += 1
        if random.random() < 0.0005:
            self.in_discards += 1

        self.last_updated = time.time()


class InterfaceRegistry:
    def __init__(self, interface_configs: list[dict]):
        self.interfaces: dict[int, InterfaceState] = {}
        for cfg in interface_configs:
            idx = cfg["index"]
            self.interfaces[idx] = InterfaceState(
                if_index=idx,
                if_type=cfg.get("type", 6),
                if_speed=cfg.get("speed", 1_000_000_000),
                if_direction=cfg.get("direction", 1),
                admin_status=cfg.get("admin_status", 1),
                oper_status=cfg.get("oper_status", 1),
                promiscuous_mode=cfg.get("promiscuous_mode", 0),
            )

    def tick_all(self, elapsed: float, utilization: float):
        for iface in self.interfaces.values():
            iface.tick(elapsed, utilization)

    def get_indices(self) -> list[int]:
        return list(self.interfaces.keys())

    def get(self, idx: int) -> InterfaceState:
        return self.interfaces[idx]
