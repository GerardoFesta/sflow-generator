"""
sFlow v5 Packet Builder
Implements the full sFlow v5 datagram format as defined in sflow.org specification.

Datagram structure (XDR-encoded, big-endian):
  SFlow Datagram:
    version           = 5
    agent_ip_type     = 1 (IPv4) | 2 (IPv6)
    agent_ip          = 4 or 16 bytes
    sub_agent_id      = uint32
    sequence_number   = uint32
    uptime            = uint32 (ms)
    num_samples       = uint32
    samples[]         = Flow Samples | Counter Samples

  Flow Sample (enterprise=0, format=1):
    sample_type       = (enterprise << 12) | format
    sample_length     = uint32
    sequence_number   = uint32
    source_id         = (source_id_type << 24) | source_id_index
    sampling_rate     = uint32
    sample_pool       = uint32
    drops             = uint32
    input_if          = uint32
    output_if         = uint32
    num_records       = uint32
    flow_records[]

  Counter Sample (enterprise=0, format=2):
    sample_type       = (enterprise << 12) | format
    sample_length     = uint32
    sequence_number   = uint32
    source_id         = (source_id_type << 24) | source_id_index
    num_records       = uint32
    counter_records[]

  Raw Packet Header Record (enterprise=0, format=1):
    record_type       = (enterprise << 12) | format
    record_length     = uint32
    header_protocol   = uint32 (1=Ethernet, 11=IPv4, 14=IPv6)
    frame_length      = uint32
    stripped          = uint32
    header_size       = uint32
    header_data       = bytes (padded to 4-byte boundary)

  Generic Interface Counter Record (enterprise=0, format=1):
    record_type / length / ifIndex / ifType / ifSpeed(hyper)
    ifDirection / status / in/out octets/packets/errors...
"""

import struct
import socket
from typing import Optional


# ─── helpers ──────────────────────────────────────────────────────────────────

def _pad4(n: int) -> int:
    """Round up to next 4-byte boundary."""
    return (n + 3) & ~3


def _ip4_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def _mac_to_bytes(mac: str) -> bytes:
    """Convert 'AA:BB:CC:DD:EE:FF' to 6 bytes."""
    return bytes(int(x, 16) for x in mac.split(":"))


# ─── Ethernet / IP header fabrication ────────────────────────────────────────

def build_ethernet_ipv4_header(
    src_mac: str,
    dst_mac: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: int,        # 6=TCP, 17=UDP, 1=ICMP
    vlan_id: Optional[int] = None,
    tos: int = 0,
    ttl: int = 64,
    pkt_id: int = 0,
) -> bytes:
    """
    Build a raw Ethernet (+ optional 802.1Q) + IPv4 + L4 header bytes.
    This is the sampled packet header content that goes into the flow record.
    """
    eth_type_ip = 0x0800
    eth_type_vlan = 0x8100

    # Ethernet header
    eth = _mac_to_bytes(dst_mac) + _mac_to_bytes(src_mac)
    if vlan_id is not None:
        eth += struct.pack("!HH", eth_type_vlan, (vlan_id & 0x0FFF))
    eth += struct.pack("!H", eth_type_ip)

    # IPv4 header (20 bytes, no options)
    ip_total_len = 40  # header only for the sample
    ihl = 5           # 5 * 4 = 20 bytes
    ver_ihl = (4 << 4) | ihl
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,             # version + IHL
        tos,                 # DSCP/ECN
        ip_total_len,        # total length
        pkt_id & 0xFFFF,     # identification
        0,                   # flags + fragment offset
        ttl,                 # TTL
        protocol,            # protocol
        0,                   # checksum placeholder
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    # Compute checksum
    ip_hdr = ip_hdr[:10] + struct.pack("!H", _ip_checksum(ip_hdr)) + ip_hdr[12:]

    # L4 stub (8 bytes, enough for source/dest ports)
    if protocol in (6, 17):  # TCP or UDP
        l4 = struct.pack("!HH", src_port, dst_port) + b"\x00" * 4
    else:
        l4 = b"\x00" * 8  # ICMP or others

    return eth + ip_hdr + l4


def build_ethernet_ipv6_header(
    src_mac: str,
    dst_mac: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: int,        # 6=TCP, 17=UDP, 58=ICMPv6
    vlan_id: Optional[int] = None,
    traffic_class: int = 0,
    flow_label: int = 0,
    hop_limit: int = 64,
) -> bytes:
    """
    Build a raw Ethernet (+ optional 802.1Q) + IPv6 + L4 header bytes.
    This is the sampled packet header content that goes into the flow record.
    """
    eth_type_ipv6 = 0x86DD
    eth_type_vlan = 0x8100

    # Ethernet header
    eth = _mac_to_bytes(dst_mac) + _mac_to_bytes(src_mac)
    if vlan_id is not None:
        eth += struct.pack("!HH", eth_type_vlan, (vlan_id & 0x0FFF))
    eth += struct.pack("!H", eth_type_ipv6)

    # IPv6 header (40 bytes fixed): version(4)|traffic_class(8)|flow_label(20), ...
    payload_len = 8  # L4 stub only
    ver_tc_fl = (6 << 28) | ((traffic_class & 0xFF) << 20) | (flow_label & 0xFFFFF)
    ip6_hdr = struct.pack(
        "!IHBB16s16s",
        ver_tc_fl,
        payload_len,
        protocol,
        hop_limit,
        socket.inet_pton(socket.AF_INET6, src_ip),
        socket.inet_pton(socket.AF_INET6, dst_ip),
    )

    # L4 stub (8 bytes, enough for source/dest ports)
    if protocol in (6, 17):  # TCP or UDP
        l4 = struct.pack("!HH", src_port, dst_port) + b"\x00" * 4
    else:
        l4 = b"\x00" * 8  # ICMPv6 or others

    return eth + ip6_hdr + l4


def _ip_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    s = 0
    for i in range(0, len(header), 2):
        word = (header[i] << 8) + header[i + 1]
        s += word
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


# ─── sFlow record builders ────────────────────────────────────────────────────

def build_raw_packet_header_record(
    header_data: bytes,
    frame_length: int,
    header_protocol: int = 1,   # 1 = Ethernet
    stripped: int = 4,          # bytes stripped (e.g. FCS)
) -> bytes:
    """Enterprise=0, Format=1: Raw packet header flow record."""
    # Pad header to 4-byte boundary
    padded = header_data.ljust(_pad4(len(header_data)), b"\x00")
    body = struct.pack(
        "!IIII",
        header_protocol,
        frame_length,
        stripped,
        len(header_data),
    ) + padded

    record_type = (0 << 12) | 1   # enterprise=0, format=1
    return struct.pack("!II", record_type, len(body)) + body


def build_extended_switch_record(
    src_vlan: int = 1,
    src_priority: int = 0,
    dst_vlan: int = 1,
    dst_priority: int = 0,
) -> bytes:
    """Enterprise=0, Format=1001: Extended switch data."""
    body = struct.pack("!IIII", src_vlan, src_priority, dst_vlan, dst_priority)
    record_type = (0 << 12) | 1001
    return struct.pack("!II", record_type, len(body)) + body


def build_flow_sample(
    sequence_number: int,
    source_id_type: int,
    source_id_index: int,
    sampling_rate: int,
    sample_pool: int,
    drops: int,
    input_if: int,
    output_if: int,
    flow_records: list[bytes],
) -> bytes:
    """Enterprise=0, Format=1: Flow Sample."""
    num_records = len(flow_records)
    records_data = b"".join(flow_records)

    source_id = (source_id_type << 24) | (source_id_index & 0x00FFFFFF)

    body = struct.pack(
        "!IIIIIII",
        sequence_number,
        source_id,
        sampling_rate,
        sample_pool,
        drops,
        input_if,
        output_if,
    ) + struct.pack("!I", num_records) + records_data

    sample_type = (0 << 12) | 1   # enterprise=0, format=1
    return struct.pack("!II", sample_type, len(body)) + body


def build_generic_if_counter_record(
    if_index: int,
    if_type: int,
    if_speed: int,
    if_direction: int,
    if_admin_status: int,
    if_oper_status: int,
    in_octets: int,
    in_ucast_pkts: int,
    in_multicast_pkts: int,
    in_broadcast_pkts: int,
    in_discards: int,
    in_errors: int,
    in_unknown_protos: int,
    out_octets: int,
    out_ucast_pkts: int,
    out_multicast_pkts: int,
    out_broadcast_pkts: int,
    out_discards: int,
    out_errors: int,
    promiscuous_mode: int,
) -> bytes:
    """Enterprise=0, Format=1: Generic Interface Counters."""
    status = ((if_admin_status & 0x7) << 3) | (if_oper_status & 0x7)
    body = struct.pack(
        "!II",
        if_index,
        if_type,
    )
    body += struct.pack("!Q", if_speed)             # ifSpeed: hyper (64-bit)
    body += struct.pack("!I", if_direction)
    body += struct.pack("!I", status)
    body += struct.pack("!Q", in_octets)            # ifInOctets: hyper
    body += struct.pack("!I", in_ucast_pkts)
    body += struct.pack("!I", in_multicast_pkts)
    body += struct.pack("!I", in_broadcast_pkts)
    body += struct.pack("!I", in_discards)
    body += struct.pack("!I", in_errors)
    body += struct.pack("!I", in_unknown_protos)
    body += struct.pack("!Q", out_octets)           # ifOutOctets: hyper
    body += struct.pack("!I", out_ucast_pkts)
    body += struct.pack("!I", out_multicast_pkts)
    body += struct.pack("!I", out_broadcast_pkts)
    body += struct.pack("!I", out_discards)
    body += struct.pack("!I", out_errors)
    body += struct.pack("!I", promiscuous_mode)

    record_type = (0 << 12) | 1  # enterprise=0, format=1
    return struct.pack("!II", record_type, len(body)) + body


def build_counter_sample(
    sequence_number: int,
    source_id_type: int,
    source_id_index: int,
    counter_records: list[bytes],
) -> bytes:
    """Enterprise=0, Format=2: Counter Sample."""
    source_id = (source_id_type << 24) | (source_id_index & 0x00FFFFFF)
    body = struct.pack(
        "!III",
        sequence_number,
        source_id,
        len(counter_records),
    ) + b"".join(counter_records)

    sample_type = (0 << 12) | 2  # enterprise=0, format=2
    return struct.pack("!II", sample_type, len(body)) + body


# ─── sFlow Datagram ───────────────────────────────────────────────────────────

def build_sflow_datagram(
    agent_ip: str,
    sub_agent_id: int,
    sequence_number: int,
    uptime_ms: int,
    samples: list[bytes],
    agent_ip_version: int = 1,  # 1=IPv4, 2=IPv6
) -> bytes:
    """Assemble a complete sFlow v5 UDP datagram payload."""
    header = struct.pack("!II", 5, agent_ip_version)
    if agent_ip_version == 1:
        header += _ip4_to_bytes(agent_ip)
    else:
        header += socket.inet_pton(socket.AF_INET6, agent_ip)

    header += struct.pack(
        "!III",
        sub_agent_id,
        sequence_number,
        uptime_ms,
    )
    header += struct.pack("!I", len(samples))
    return header + b"".join(samples)
