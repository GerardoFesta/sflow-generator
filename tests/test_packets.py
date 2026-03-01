"""
Tests for sFlow v5 packet builder.
Run with: python -m pytest tests/ -v
"""

import struct
import socket
import pytest
from sflow.packet import (
    build_sflow_datagram,
    build_flow_sample,
    build_counter_sample,
    build_raw_packet_header_record,
    build_generic_if_counter_record,
    build_ethernet_ipv4_header,
    build_ethernet_ipv6_header,
    _pad4,
)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def parse_uint32(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from("!I", data, offset)[0], offset + 4


def parse_uint64(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from("!Q", data, offset)[0], offset + 8


# ─── Ethernet header tests ───────────────────────────────────────────────────

class TestEthernetIPv4Header:
    def test_basic_structure(self):
        hdr = build_ethernet_ipv4_header(
            src_mac="AA:BB:CC:DD:EE:FF",
            dst_mac="11:22:33:44:55:66",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=80,
            protocol=6,
        )
        # Ethernet: 14 bytes, IPv4: 20 bytes, L4 stub: 8 bytes = 42
        assert len(hdr) == 42

    def test_ethertype_ipv4(self):
        hdr = build_ethernet_ipv4_header(
            src_mac="AA:BB:CC:DD:EE:FF",
            dst_mac="11:22:33:44:55:66",
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            src_port=100,
            dst_port=200,
            protocol=17,
        )
        ethertype = struct.unpack_from("!H", hdr, 12)[0]
        assert ethertype == 0x0800

    def test_vlan_tag_inserted(self):
        hdr = build_ethernet_ipv4_header(
            src_mac="AA:BB:CC:DD:EE:FF",
            dst_mac="11:22:33:44:55:66",
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            src_port=100,
            dst_port=200,
            protocol=6,
            vlan_id=100,
        )
        # 14 + 4 (802.1Q) + 20 + 8 = 46
        assert len(hdr) == 46
        vlan_tpid = struct.unpack_from("!H", hdr, 12)[0]
        assert vlan_tpid == 0x8100

    def test_ip_addresses_correct(self):
        hdr = build_ethernet_ipv4_header(
            src_mac="AA:BB:CC:DD:EE:FF",
            dst_mac="11:22:33:44:55:66",
            src_ip="192.168.1.1",
            dst_ip="8.8.8.8",
            src_port=5000,
            dst_port=53,
            protocol=17,
        )
        # IPv4 src/dst are at bytes 26 and 30 (after 14 eth + 12 ip header fields)
        src_ip_bytes = hdr[26:30]
        dst_ip_bytes = hdr[30:34]
        assert socket.inet_ntoa(src_ip_bytes) == "192.168.1.1"
        assert socket.inet_ntoa(dst_ip_bytes) == "8.8.8.8"


# ─── Flow record tests ───────────────────────────────────────────────────────

class TestRawPacketHeaderRecord:
    def test_record_type_and_length(self):
        raw = build_raw_packet_header_record(b"ABCDEFGH", frame_length=1500)
        record_type, length = struct.unpack_from("!II", raw)
        assert record_type == 1         # enterprise=0, format=1
        assert length == len(raw) - 8  # length excludes type+length fields

    def test_header_padding_to_4_bytes(self):
        # 5-byte header should be padded to 8
        raw = build_raw_packet_header_record(b"HELLO", frame_length=100)
        # offset 8: protocol, frame_length, stripped, header_size = 16 bytes
        header_size = struct.unpack_from("!I", raw, 8 + 12)[0]
        assert header_size == 5
        # total body = 16 (fixed) + 8 (padded 5→8)
        _, length = struct.unpack_from("!II", raw)
        assert length == 16 + 8

    def test_frame_length_preserved(self):
        raw = build_raw_packet_header_record(b"X" * 64, frame_length=1518)
        frame_len = struct.unpack_from("!I", raw, 8 + 4)[0]
        assert frame_len == 1518

    def test_header_protocol_default_ethernet(self):
        raw = build_raw_packet_header_record(b"DATA", frame_length=100)
        protocol = struct.unpack_from("!I", raw, 8)[0]
        assert protocol == 1  # Ethernet


# ─── Flow sample tests ───────────────────────────────────────────────────────

class TestFlowSample:
    def _make_sample(self, **kwargs):
        defaults = dict(
            sequence_number=1,
            source_id_type=0,
            source_id_index=1,
            sampling_rate=512,
            sample_pool=512000,
            drops=0,
            input_if=1,
            output_if=2,
            flow_records=[build_raw_packet_header_record(b"A" * 40, 1000)],
        )
        defaults.update(kwargs)
        return build_flow_sample(**defaults)

    def test_sample_type_enterprise0_format1(self):
        sample = self._make_sample()
        sample_type = struct.unpack_from("!I", sample)[0]
        assert sample_type == 1

    def test_sampling_rate_in_body(self):
        sample = self._make_sample(sampling_rate=1024)
        # body starts at offset 8 (type=4, length=4)
        # body: seq(4) source_id(4) rate(4) pool(4) drops(4) in(4) out(4) nrec(4) ...
        rate = struct.unpack_from("!I", sample, 8 + 4 + 4)[0]
        assert rate == 1024

    def test_source_id_encoding(self):
        sample = self._make_sample(source_id_type=0, source_id_index=3)
        source_id = struct.unpack_from("!I", sample, 8 + 4)[0]
        expected = (0 << 24) | 3
        assert source_id == expected


# ─── Counter sample tests ─────────────────────────────────────────────────────

class TestCounterSample:
    def _make_counter(self):
        rec = build_generic_if_counter_record(
            if_index=1, if_type=6, if_speed=1_000_000_000,
            if_direction=1, if_admin_status=1, if_oper_status=1,
            in_octets=1_000_000, in_ucast_pkts=1000,
            in_multicast_pkts=10, in_broadcast_pkts=5,
            in_discards=0, in_errors=0, in_unknown_protos=0,
            out_octets=2_000_000, out_ucast_pkts=2000,
            out_multicast_pkts=20, out_broadcast_pkts=10,
            out_discards=0, out_errors=0, promiscuous_mode=0,
        )
        return build_counter_sample(
            sequence_number=1,
            source_id_type=0,
            source_id_index=1,
            counter_records=[rec],
        )

    def test_sample_type_enterprise0_format2(self):
        sample = self._make_counter()
        sample_type = struct.unpack_from("!I", sample)[0]
        assert sample_type == 2

    def test_num_records_is_one(self):
        sample = self._make_counter()
        # body: seq(4) source_id(4) num_records(4)
        num_records = struct.unpack_from("!I", sample, 8 + 4 + 4)[0]
        assert num_records == 1


# ─── Datagram tests ───────────────────────────────────────────────────────────

class TestSFlowDatagram:
    def _make_datagram(self, samples=None):
        if samples is None:
            rec = build_raw_packet_header_record(b"A" * 40, 1000)
            samples = [
                build_flow_sample(1, 0, 1, 512, 512000, 0, 1, 2, [rec])
            ]
        return build_sflow_datagram(
            agent_ip="192.168.1.1",
            sub_agent_id=0,
            sequence_number=1,
            uptime_ms=12345,
            samples=samples,
        )

    def test_version_is_5(self):
        dg = self._make_datagram()
        version = struct.unpack_from("!I", dg, 0)[0]
        assert version == 5

    def test_ip_type_ipv4(self):
        dg = self._make_datagram()
        ip_type = struct.unpack_from("!I", dg, 4)[0]
        assert ip_type == 1

    def test_agent_ip_correct(self):
        dg = self._make_datagram()
        agent_ip = socket.inet_ntoa(dg[8:12])
        assert agent_ip == "192.168.1.1"

    def test_num_samples_field(self):
        rec = build_raw_packet_header_record(b"A" * 40, 1000)
        s1 = build_flow_sample(1, 0, 1, 512, 0, 0, 1, 2, [rec])
        s2 = build_flow_sample(2, 0, 1, 512, 0, 0, 1, 2, [rec])
        dg = self._make_datagram(samples=[s1, s2])
        # IPv4 datagram header: version(4) ip_type(4) agent_ip(4)
        #   sub_agent_id(4) seq(4) uptime(4) num_samples(4) = 28 bytes
        num_samples = struct.unpack_from("!I", dg, 24)[0]
        assert num_samples == 2

    def test_sequence_number(self):
        dg = self._make_datagram()
        seq = struct.unpack_from("!I", dg, 16)[0]
        assert seq == 1

    def test_uptime_ms(self):
        dg = self._make_datagram()
        uptime = struct.unpack_from("!I", dg, 20)[0]
        assert uptime == 12345

    def test_minimum_datagram_size(self):
        dg = self._make_datagram()
        # Must be at least the header: 28 bytes
        assert len(dg) > 28


# ─── IPv6 Ethernet header tests ──────────────────────────────────────────────

class TestEthernetIPv6Header:
    def _make_header(self, **kwargs):
        defaults = dict(
            src_mac="AA:BB:CC:DD:EE:FF",
            dst_mac="11:22:33:44:55:66",
            src_ip="2001:db8::1",
            dst_ip="2001:db8::2",
            src_port=1234,
            dst_port=80,
            protocol=6,
        )
        defaults.update(kwargs)
        return build_ethernet_ipv6_header(**defaults)

    def test_basic_structure(self):
        hdr = self._make_header()
        # Ethernet: 14 bytes, IPv6: 40 bytes, L4 stub: 8 bytes = 62
        assert len(hdr) == 62

    def test_ethertype_ipv6(self):
        hdr = self._make_header()
        ethertype = struct.unpack_from("!H", hdr, 12)[0]
        assert ethertype == 0x86DD

    def test_vlan_variant(self):
        hdr = self._make_header(vlan_id=100)
        # 14 + 4 (802.1Q) + 40 + 8 = 66
        assert len(hdr) == 66
        vlan_tpid = struct.unpack_from("!H", hdr, 12)[0]
        assert vlan_tpid == 0x8100
        # EtherType for IPv6 follows VLAN tag at offset 16
        ethertype = struct.unpack_from("!H", hdr, 16)[0]
        assert ethertype == 0x86DD

    def test_ip_addresses_correct(self):
        src = "2001:db8::1"
        dst = "2001:db8::2"
        hdr = self._make_header(src_ip=src, dst_ip=dst)
        # IPv6 header starts at offset 14; src addr at 14+8=22, dst at 14+8+16=38
        src_bytes = hdr[22:38]
        dst_bytes = hdr[38:54]
        assert socket.inet_ntop(socket.AF_INET6, src_bytes) == src
        assert socket.inet_ntop(socket.AF_INET6, dst_bytes) == dst

    def test_version_field(self):
        hdr = self._make_header()
        # First 4 bytes of IPv6 header at offset 14: top 4 bits = version = 6
        ver_tc_fl = struct.unpack_from("!I", hdr, 14)[0]
        version = ver_tc_fl >> 28
        assert version == 6

    def test_l4_ports_correct(self):
        hdr = self._make_header(src_port=5555, dst_port=443, protocol=6)
        # L4 stub at offset 14+40=54
        src_port = struct.unpack_from("!H", hdr, 54)[0]
        dst_port = struct.unpack_from("!H", hdr, 56)[0]
        assert src_port == 5555
        assert dst_port == 443

    def test_non_tcp_udp_l4_is_zeros(self):
        hdr = self._make_header(protocol=58)  # ICMPv6
        l4 = hdr[54:62]
        assert l4 == b"\x00" * 8


# ─── IPv6 agent datagram tests ────────────────────────────────────────────────

class TestSFlowDatagramIPv6Agent:
    def _make_datagram_ipv6(self, agent_ip="2001:db8::1"):
        rec = build_raw_packet_header_record(b"A" * 40, 1000)
        samples = [build_flow_sample(1, 0, 1, 512, 512000, 0, 1, 2, [rec])]
        return build_sflow_datagram(
            agent_ip=agent_ip,
            sub_agent_id=0,
            sequence_number=1,
            uptime_ms=12345,
            samples=samples,
            agent_ip_version=2,
        )

    def test_ip_type_is_2(self):
        dg = self._make_datagram_ipv6()
        ip_type = struct.unpack_from("!I", dg, 4)[0]
        assert ip_type == 2

    def test_agent_ip_correct(self):
        agent_ip = "2001:db8::1"
        dg = self._make_datagram_ipv6(agent_ip=agent_ip)
        # IPv6 agent IP: 16 bytes at offset 8
        agent_bytes = dg[8:24]
        assert socket.inet_ntop(socket.AF_INET6, agent_bytes) == agent_ip

    def test_version_still_5(self):
        dg = self._make_datagram_ipv6()
        version = struct.unpack_from("!I", dg, 0)[0]
        assert version == 5

    def test_num_samples_field_ipv6(self):
        rec = build_raw_packet_header_record(b"A" * 40, 1000)
        s1 = build_flow_sample(1, 0, 1, 512, 0, 0, 1, 2, [rec])
        s2 = build_flow_sample(2, 0, 1, 512, 0, 0, 1, 2, [rec])
        dg = build_sflow_datagram(
            agent_ip="2001:db8::1",
            sub_agent_id=0,
            sequence_number=1,
            uptime_ms=0,
            samples=[s1, s2],
            agent_ip_version=2,
        )
        # IPv6 datagram header: version(4) ip_type(4) agent_ip(16)
        #   sub_agent_id(4) seq(4) uptime(4) num_samples(4) = 40 bytes
        num_samples = struct.unpack_from("!I", dg, 36)[0]
        assert num_samples == 2


# ─── Padding helper ──────────────────────────────────────────────────────────

class TestPad4:
    @pytest.mark.parametrize("n,expected", [
        (0, 0), (1, 4), (4, 4), (5, 8), (8, 8), (9, 12), (100, 100), (101, 104)
    ])
    def test_pad4(self, n, expected):
        assert _pad4(n) == expected
