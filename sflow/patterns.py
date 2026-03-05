"""
Traffic pattern generators.
Each pattern produces a stream of flow metadata used to build sFlow samples.
"""

import random
import ipaddress
from dataclasses import dataclass
from typing import Iterator


@dataclass
class FlowSpec:
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int         # 1=ICMP, 6=TCP, 17=UDP, 58=ICMPv6
    frame_length: int
    vlan_id: int | None
    tos: int
    ttl: int
    input_if: int
    output_if: int
    ip_version: int = 4   # 4 or 6


def _rand_mac() -> str:
    return ":".join(f"{random.randint(0, 255):02X}" for _ in range(6))


def _rand_ip(subnet: str) -> str:
    net = ipaddress.IPv4Network(subnet, strict=False)
    hosts = list(net.hosts())
    return str(random.choice(hosts))


def _rand_ipv6(subnet: str) -> str:
    net = ipaddress.IPv6Network(subnet, strict=False)
    offset = random.randint(0, min(2**32 - 1, net.num_addresses - 1))
    return str(ipaddress.IPv6Address(int(net.network_address) + offset))


def _rand_port(well_known: bool = False) -> int:
    if well_known:
        return random.choice([80, 443, 22, 25, 53, 8080, 8443, 3306, 5432, 6379])
    return random.randint(1024, 65535)


class TrafficPattern:
    """Base class for traffic patterns."""

    def __init__(self, cfg: dict, interfaces: list[int]):
        self.cfg = cfg
        self.interfaces = interfaces

    def _random_if_pair(self):
        if len(self.interfaces) >= 2:
            inp, out = random.sample(self.interfaces, 2)
        else:
            inp = out = self.interfaces[0]
        return inp, out

    def flows(self) -> Iterator[FlowSpec]:
        raise NotImplementedError


class RandomPattern(TrafficPattern):
    """Completely random src/dst IPs, ports, and protocols."""

    def flows(self) -> Iterator[FlowSpec]:
        src_subnet = self.cfg.get("src_subnet", "10.0.0.0/8")
        dst_subnet = self.cfg.get("dst_subnet", "10.0.0.0/8")
        protocols = self.cfg.get("protocols", [6, 17, 1])
        frame_min = self.cfg.get("frame_size_min", 64)
        frame_max = self.cfg.get("frame_size_max", 1518)
        vlan_id = self.cfg.get("vlan_id", None)
        ip_version = self.cfg.get("ip_version", 4)
        _ip_fn = _rand_ipv6 if ip_version == 6 else _rand_ip

        while True:
            inp, out = self._random_if_pair()
            proto = random.choice(protocols)
            yield FlowSpec(
                src_mac=_rand_mac(),
                dst_mac=_rand_mac(),
                src_ip=_ip_fn(src_subnet),
                dst_ip=_ip_fn(dst_subnet),
                src_port=_rand_port(),
                dst_port=_rand_port(well_known=True),
                protocol=proto,
                frame_length=random.randint(frame_min, frame_max),
                vlan_id=vlan_id,
                tos=random.choice([0, 0x10, 0x28, 0x48]),
                ttl=random.randint(32, 128),
                input_if=inp,
                output_if=out,
                ip_version=ip_version,
            )


class WebTrafficPattern(TrafficPattern):
    """Simulates web traffic: many clients hitting a small set of servers."""

    def flows(self) -> Iterator[FlowSpec]:
        client_subnet = self.cfg.get("client_subnet", "192.168.0.0/16")
        server_ips = self.cfg.get("server_ips", ["10.0.1.10", "10.0.1.11"])
        protocols = [6]  # TCP only
        frame_min = self.cfg.get("frame_size_min", 64)
        frame_max = self.cfg.get("frame_size_max", 1518)
        vlan_id = self.cfg.get("vlan_id", None)
        ip_version = self.cfg.get("ip_version", 4)
        _ip_fn = _rand_ipv6 if ip_version == 6 else _rand_ip

        while True:
            inp, out = self._random_if_pair()
            server_ip = random.choice(server_ips)
            # Alternate request / response direction
            if random.random() < 0.5:
                src_ip = _ip_fn(client_subnet)
                dst_ip = server_ip
                dst_port = random.choice([80, 443, 8080, 8443])
                src_port = _rand_port()
                frame_len = random.randint(frame_min, 200)  # small request
            else:
                src_ip = server_ip
                dst_ip = _ip_fn(client_subnet)
                src_port = random.choice([80, 443, 8080, 8443])
                dst_port = _rand_port()
                frame_len = random.randint(400, frame_max)  # larger response

            yield FlowSpec(
                src_mac=_rand_mac(),
                dst_mac=_rand_mac(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=6,
                frame_length=frame_len,
                vlan_id=vlan_id,
                tos=0,
                ttl=64,
                input_if=inp,
                output_if=out,
                ip_version=ip_version,
            )


class DnsTrafficPattern(TrafficPattern):
    """Simulates DNS query/response traffic."""

    def flows(self) -> Iterator[FlowSpec]:
        client_subnet = self.cfg.get("client_subnet", "10.0.0.0/8")
        dns_servers = self.cfg.get("dns_servers", ["8.8.8.8", "1.1.1.1"])
        vlan_id = self.cfg.get("vlan_id", None)
        ip_version = self.cfg.get("ip_version", 4)
        _ip_fn = _rand_ipv6 if ip_version == 6 else _rand_ip

        while True:
            inp, out = self._random_if_pair()
            dns = random.choice(dns_servers)
            if random.random() < 0.5:
                src_ip = _ip_fn(client_subnet)
                dst_ip = dns
                src_port = _rand_port()
                dst_port = 53
                frame_len = random.randint(64, 128)
            else:
                src_ip = dns
                dst_ip = _ip_fn(client_subnet)
                src_port = 53
                dst_port = _rand_port()
                frame_len = random.randint(64, 512)

            yield FlowSpec(
                src_mac=_rand_mac(),
                dst_mac=_rand_mac(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=17,  # UDP
                frame_length=frame_len,
                vlan_id=vlan_id,
                tos=0,
                ttl=64,
                input_if=inp,
                output_if=out,
                ip_version=ip_version,
            )


class CustomFlowPattern(TrafficPattern):
    """
    Replays a fixed list of flow specs from config (useful for deterministic testing).
    Cycles through the list indefinitely.
    """

    def flows(self) -> Iterator[FlowSpec]:
        entries = self.cfg.get("flows", [])
        if not entries:
            raise ValueError("custom pattern requires 'flows' list in pattern config")
        global_ip_version = self.cfg.get("ip_version", 4)
        idx = 0
        while True:
            e = entries[idx % len(entries)]
            inp, out = self._random_if_pair()
            yield FlowSpec(
                src_mac=e.get("src_mac", _rand_mac()),
                dst_mac=e.get("dst_mac", _rand_mac()),
                src_ip=e["src_ip"],
                dst_ip=e["dst_ip"],
                src_port=e.get("src_port", _rand_port()),
                dst_port=e.get("dst_port", 80),
                protocol=e.get("protocol", 6),
                frame_length=e.get("frame_length", 512),
                vlan_id=e.get("vlan_id", None),
                tos=e.get("tos", 0),
                ttl=e.get("ttl", 64),
                input_if=e.get("input_if", inp),
                output_if=e.get("output_if", out),
                ip_version=e.get("ip_version", global_ip_version),
            )
            idx += 1


PATTERNS = {
    "random": RandomPattern,
    "web": WebTrafficPattern,
    "dns": DnsTrafficPattern,
    "custom": CustomFlowPattern,
}


def get_pattern(name: str, cfg: dict, interfaces: list[int]) -> TrafficPattern:
    cls = PATTERNS.get(name)
    if cls is None:
        raise ValueError(f"Unknown traffic pattern '{name}'. Choose from: {list(PATTERNS)}")
    return cls(cfg, interfaces)
