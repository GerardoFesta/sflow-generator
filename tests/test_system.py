"""
System tests for SFlowGenerator.

Each test binds a local UDP listener socket *before* starting the generator,
then verifies that real sFlow v5 datagrams arrive and are structurally correct.

Two suites:
  TestGeneratorIPv4System  — IPv4 agent address, IPv4 flow packet headers
  TestGeneratorIPv6System  — IPv6 agent address, IPv6 flow packet headers
                             (transport stays IPv4 UDP to 127.0.0.1)
"""

import ipaddress
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


def _ipv6_header_from_datagram(dg: bytes) -> dict:
    """
    Parse the IPv6 header fields from inside the first flow record of an
    IPv6-agent sFlow datagram.

    Byte layout for an IPv6-agent datagram with one flow sample:
      sFlow header : 40 B  (version+ip_type+agent_ip16+sub_id+seq+uptime+nsamples)
      Flow sample  : 40 B  (type+len + 8 fixed uint32s)
      Raw record   : 24 B  (type+len + 4 fixed uint32s)
      Ethernet     : 14 B  (dst_mac+src_mac+ethertype)
      IPv6 header  : 40 B
    Total to start of IPv6 header: 40+40+24+14 = 118
    """
    ipv6_start = 40 + 40 + 24 + 14   # = 118
    ver_tc_fl   = struct.unpack_from("!I", dg, ipv6_start)[0]
    payload_len = struct.unpack_from("!H", dg, ipv6_start + 4)[0]
    next_header = struct.unpack_from("!B", dg, ipv6_start + 6)[0]
    hop_limit   = struct.unpack_from("!B", dg, ipv6_start + 7)[0]
    src_ip = socket.inet_ntop(socket.AF_INET6, dg[ipv6_start + 8  : ipv6_start + 24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, dg[ipv6_start + 24 : ipv6_start + 40])
    return {
        "version":     ver_tc_fl >> 28,
        "payload_len": payload_len,
        "next_header": next_header,
        "hop_limit":   hop_limit,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
    }


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

    def test_ipv6_version_field_in_flow_record(self):
        """The IPv6 header inside the flow record has IP version == 6."""
        datagrams = _run_and_collect(
            agent_ip="2001:db8::1", ip_version=6, target_count=1, timeout=5.0
        )
        assert datagrams, "No datagram received"
        ipv6 = _ipv6_header_from_datagram(datagrams[0])
        assert ipv6["version"] == 6, (
            f"Expected version=6 in sampled IPv6 header, got {ipv6['version']}"
        )

    def test_ipv6_addresses_in_configured_subnets(self):
        """src/dst IPs in the flow record fall within the configured subnets."""
        datagrams = _run_and_collect(
            agent_ip="2001:db8::1", ip_version=6, target_count=1, timeout=5.0
        )
        assert datagrams, "No datagram received"
        ipv6 = _ipv6_header_from_datagram(datagrams[0])
        src_net = ipaddress.IPv6Network("2001:db8::/48")
        dst_net = ipaddress.IPv6Network("2001:db8:1::/48")
        assert ipaddress.IPv6Address(ipv6["src_ip"]) in src_net, (
            f"src_ip {ipv6['src_ip']} not in 2001:db8::/48"
        )
        assert ipaddress.IPv6Address(ipv6["dst_ip"]) in dst_net, (
            f"dst_ip {ipv6['dst_ip']} not in 2001:db8:1::/48"
        )

    def test_datagram_sequence_numbers_are_monotonic(self):
        """sFlow datagram sequence numbers must strictly increase."""
        datagrams = _run_and_collect(
            agent_ip="2001:db8::1", ip_version=6, target_count=5, timeout=5.0
        )
        assert len(datagrams) >= 5, (
            f"Expected >= 5 datagrams but received {len(datagrams)}"
        )
        # For IPv6 agent: version(4)+ip_type(4)+agent_ip(16)+sub_agent_id(4) = 28 bytes
        # then sequence_number at offset 28
        seqs = [struct.unpack_from("!I", dg, 28)[0] for dg in datagrams]
        for i in range(1, len(seqs)):
            assert seqs[i] > seqs[i - 1], (
                f"Sequence numbers not monotonic: {seqs}"
            )

    def test_counter_samples_produced_with_ipv6_agent(self):
        """Counter samples (type=2) are emitted alongside flow samples with IPv6 agent."""
        received: list[bytes] = []
        done = threading.Event()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.settimeout(0.2)

        cfg = _make_config(port, agent_ip="2001:db8::1", ip_version=6)
        cfg["flow"]["sample_types"] = ["flow", "counter"]
        cfg["counter_polling"]["interval_seconds"] = 1   # fire quickly

        gen = SFlowGenerator(cfg)

        def _listen():
            while not done.is_set():
                try:
                    data, _ = sock.recvfrom(65535)
                    received.append(data)
                except socket.timeout:
                    pass

        listener_thread = threading.Thread(target=_listen, daemon=True)
        gen_thread = threading.Thread(target=gen.start, daemon=True)
        listener_thread.start()
        gen_thread.start()

        time.sleep(3.0)   # long enough for counter interval to fire at least once
        gen.stop()
        done.set()
        listener_thread.join(timeout=2.0)
        gen_thread.join(timeout=2.0)
        sock.close()

        assert received, "No datagrams received at all"

        # Walk every sample in every IPv6-agent datagram and collect sample types.
        sample_types: set[int] = set()
        for dg in received:
            ip_type = struct.unpack_from("!I", dg, 4)[0]
            if ip_type != 2:
                continue
            num_samples = struct.unpack_from("!I", dg, 36)[0]
            offset = 40   # samples start after the 40-byte IPv6 sFlow header
            for _ in range(num_samples):
                if offset + 8 > len(dg):
                    break
                stype = struct.unpack_from("!I", dg, offset)[0]
                slen  = struct.unpack_from("!I", dg, offset + 4)[0]
                sample_types.add(stype)
                offset += 8 + slen

        assert 1 in sample_types, "No flow samples (type=1) found in IPv6-agent datagrams"
        assert 2 in sample_types, "No counter samples (type=2) found in IPv6-agent datagrams"
