"""
System tests for SFlowGenerator.

Each test binds a local UDP listener socket *before* starting the generator,
then verifies that real sFlow v5 datagrams arrive and are structurally correct.

Two suites:
  TestGeneratorIPv4System  — IPv4 agent address, IPv4 flow packet headers
  TestGeneratorIPv6System  — IPv6 agent address, IPv6 flow packet headers
                             (transport stays IPv4 UDP to 127.0.0.1)
"""

import socket
import struct
import threading
import time

from sflow.generator import SFlowGenerator


# ─── helpers ──────────────────────────────────────────────────────────────────

def _make_config(port: int, agent_ip: str, ip_version: int) -> dict:
    """Build a minimal in-process config dict aimed at 127.0.0.1:port."""
    pattern: dict = {
        "type": "random",
        "protocols": [6],           # TCP only — deterministic EtherType
        "ip_version": ip_version,
    }
    if ip_version == 6:
        pattern["src_subnet"] = "2001:db8::/48"
        pattern["dst_subnet"] = "2001:db8:1::/48"
    else:
        pattern["src_subnet"] = "10.0.0.0/24"
        pattern["dst_subnet"] = "10.0.1.0/24"

    return {
        "collector": {"host": "127.0.0.1", "port": port},
        "agent":     {"ip": agent_ip, "sub_agent_id": 0},
        "sampling":  {"rate": 512, "max_header_size": 128, "samples_per_datagram": 1},
        "flow":      {"flows_per_second": 50, "sample_types": ["flow"]},
        "counter_polling": {"interval_seconds": 60},   # disable counters
        "interfaces": [{"index": 1}, {"index": 2}],
        "link_utilization": 0.1,
        "pattern": pattern,
    }


def _run_and_collect(
    agent_ip: str,
    ip_version: int,
    target_count: int = 5,
    timeout: float = 5.0,
) -> list[bytes]:
    """
    Bind a UDP listener, start the generator, collect *target_count* datagrams
    (or as many as arrive within *timeout* seconds), then stop everything.

    The listener is bound *before* the generator starts so no early datagrams
    are lost.
    """
    received: list[bytes] = []
    done = threading.Event()

    # Bind listener first; let the OS pick a free port.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.settimeout(0.2)

    cfg = _make_config(port, agent_ip=agent_ip, ip_version=ip_version)
    gen = SFlowGenerator(cfg)

    def _listen():
        while not done.is_set():
            try:
                data, _ = sock.recvfrom(65535)
                received.append(data)
                if len(received) >= target_count:
                    done.set()
            except socket.timeout:
                pass

    listener_thread = threading.Thread(target=_listen, daemon=True)
    gen_thread = threading.Thread(target=gen.start, daemon=True)

    listener_thread.start()
    gen_thread.start()

    done.wait(timeout=timeout)
    gen.stop()
    done.set()                        # unblock listener if target not reached

    listener_thread.join(timeout=2.0)
    gen_thread.join(timeout=2.0)
    sock.close()

    return received


def _ethertype_from_datagram(dg: bytes) -> int:
    """
    Extract the EtherType from the first flow sample's raw packet header record.

    sFlow datagram layout (offsets vary by agent IP version):
      IPv4 agent (ip_type=1): samples start at byte 28
        version(4) + ip_type(4) + agent_ip(4) + sub_id(4) + seq(4) + uptime(4) + nsamples(4) = 28
      IPv6 agent (ip_type=2): samples start at byte 40
        version(4) + ip_type(4) + agent_ip(16) + sub_id(4) + seq(4) + uptime(4) + nsamples(4) = 40

    Inside the first flow sample:
      type(4) + length(4) + body_fixed_32B + records...  → records start at +40
    Inside the first raw-packet-header record:
      type(4) + length(4) + protocol(4) + frame_len(4) + stripped(4) + hdr_size(4) = 24B header
      then header_data bytes → Ethernet EtherType is at header_data + 12
    """
    ip_type = struct.unpack_from("!I", dg, 4)[0]
    samples_offset = 28 if ip_type == 1 else 40
    # flow sample: 8B (type+len) + 32B (fixed body) = 40B before first record
    # raw record : 8B (type+len) + 16B (4×uint32 fixed body) = 24B before header_data
    eth_start = samples_offset + 40 + 24
    return struct.unpack_from("!H", dg, eth_start + 12)[0]


# ─── IPv4 system tests ────────────────────────────────────────────────────────

class TestGeneratorIPv4System:
    """Generator emits real UDP datagrams: IPv4 agent, IPv4 flow headers."""

    def test_traffic_is_sent(self):
        """At least 5 datagrams must arrive within the timeout."""
        datagrams = _run_and_collect(
            agent_ip="192.168.1.1", ip_version=4, target_count=5, timeout=5.0
        )
        assert len(datagrams) >= 5, (
            f"Expected >= 5 datagrams but received {len(datagrams)}"
        )

    def test_datagram_is_valid_sflow_v5(self):
        """Version field == 5, ip_type == 1, agent IP bytes match."""
        datagrams = _run_and_collect(
            agent_ip="192.168.1.1", ip_version=4, target_count=1, timeout=5.0
        )
        assert datagrams, "No datagram received"
        dg = datagrams[0]

        assert len(dg) >= 28, "Datagram shorter than minimum IPv4 sFlow header"
        assert struct.unpack_from("!I", dg, 0)[0] == 5, "sFlow version must be 5"
        assert struct.unpack_from("!I", dg, 4)[0] == 1, "ip_type must be 1 (IPv4)"
        assert socket.inet_ntoa(dg[8:12]) == "192.168.1.1", "Agent IP mismatch"

    def test_flow_records_contain_ipv4_ethernet_headers(self):
        """EtherType inside the raw packet header record must be 0x0800 (IPv4)."""
        datagrams = _run_and_collect(
            agent_ip="192.168.1.1", ip_version=4, target_count=1, timeout=5.0
        )
        assert datagrams, "No datagram received"
        assert _ethertype_from_datagram(datagrams[0]) == 0x0800, (
            "Expected EtherType 0x0800 (IPv4) in flow record"
        )


# ─── IPv6 system tests ────────────────────────────────────────────────────────

class TestGeneratorIPv6System:
    """Generator emits real UDP datagrams: IPv6 agent, IPv6 flow headers.

    Transport is still IPv4 UDP to 127.0.0.1 — sFlow over IPv4 describing
    IPv6 traffic is a standard and supported configuration.
    """

    def test_traffic_is_sent(self):
        """At least 5 datagrams must arrive within the timeout."""
        datagrams = _run_and_collect(
            agent_ip="2001:db8::1", ip_version=6, target_count=5, timeout=5.0
        )
        assert len(datagrams) >= 5, (
            f"Expected >= 5 datagrams but received {len(datagrams)}"
        )

    def test_datagram_is_valid_sflow_v5(self):
        """Version field == 5, ip_type == 2, agent IP bytes match."""
        datagrams = _run_and_collect(
            agent_ip="2001:db8::1", ip_version=6, target_count=1, timeout=5.0
        )
        assert datagrams, "No datagram received"
        dg = datagrams[0]

        assert len(dg) >= 40, "Datagram shorter than minimum IPv6 sFlow header"
        assert struct.unpack_from("!I", dg, 0)[0] == 5, "sFlow version must be 5"
        assert struct.unpack_from("!I", dg, 4)[0] == 2, "ip_type must be 2 (IPv6)"
        assert socket.inet_ntop(socket.AF_INET6, dg[8:24]) == "2001:db8::1", (
            "Agent IP mismatch"
        )

    def test_flow_records_contain_ipv6_ethernet_headers(self):
        """EtherType inside the raw packet header record must be 0x86DD (IPv6)."""
        datagrams = _run_and_collect(
            agent_ip="2001:db8::1", ip_version=6, target_count=1, timeout=5.0
        )
        assert datagrams, "No datagram received"
        assert _ethertype_from_datagram(datagrams[0]) == 0x86DD, (
            "Expected EtherType 0x86DD (IPv6) in flow record"
        )
