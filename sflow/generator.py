"""
sFlow Generator Engine
Coordinates packet building, timing, and UDP transmission.
"""

import socket
import time
import logging
import threading
import ipaddress
from typing import Any

from .packet import (
    build_sflow_datagram,
    build_flow_sample,
    build_counter_sample,
    build_raw_packet_header_record,
    build_generic_if_counter_record,
    build_ethernet_ipv4_header,
    build_ethernet_ipv6_header,
)
from .patterns import get_pattern, FlowSpec
from .interfaces import InterfaceRegistry

log = logging.getLogger("sflow.generator")


class SFlowGenerator:
    def __init__(self, config: dict):
        self.config = config
        self._running = False
        self._flow_seq = 0
        self._counter_seq = 0
        self._datagram_seq = 0
        self._start_time = time.time()

        # Collector target
        collector = config["collector"]
        self.target_host = collector["host"]
        self.target_port = collector.get("port", 6343)

        # Agent identity
        agent = config["agent"]
        self.agent_ip = agent["ip"]
        self.sub_agent_id = agent.get("sub_agent_id", 0)
        try:
            ipaddress.IPv6Address(self.agent_ip)
            self._agent_ip_version = 2
        except ValueError:
            self._agent_ip_version = 1

        # Sampling parameters
        sampling = config.get("sampling", {})
        self.sampling_rate = sampling.get("rate", 512)
        self.max_header_size = sampling.get("max_header_size", 128)
        self.samples_per_datagram = sampling.get("samples_per_datagram", 5)

        # Flow emission rate
        flow = config.get("flow", {})
        self.flows_per_second = flow.get("flows_per_second", 100)
        self.sample_types = flow.get("sample_types", ["flow", "counter"])

        # Counter polling
        counter = config.get("counter_polling", {})
        self.counter_interval = counter.get("interval_seconds", 30)
        self._last_counter_time = 0.0

        # Interface registry
        iface_cfgs = config.get("interfaces", [{"index": 1}, {"index": 2}])
        self.iface_registry = InterfaceRegistry(iface_cfgs)
        self.if_indices = self.iface_registry.get_indices()

        # Traffic pattern
        pattern_cfg = config.get("pattern", {})
        pattern_name = pattern_cfg.get("type", "random")
        self.pattern = get_pattern(pattern_name, pattern_cfg, self.if_indices)
        self._flow_iter = self.pattern.flows()

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Utilization (for counter ticks)
        self.link_utilization = config.get("link_utilization", 0.1)

        log.info(
            "sFlow Generator initialized → %s:%d | agent=%s | rate=%d pps | pattern=%s",
            self.target_host,
            self.target_port,
            self.agent_ip,
            self.flows_per_second,
            pattern_name,
        )

    # ─── public API ──────────────────────────────────────────────────────────

    def start(self):
        self._running = True
        log.info("Starting sFlow generator...")
        self._run_loop()

    def stop(self):
        self._running = False
        self._sock.close()
        log.info("sFlow generator stopped.")

    # ─── main loop ───────────────────────────────────────────────────────────

    def _run_loop(self):
        interval = 1.0 / max(1, self.flows_per_second)
        last_tick = time.time()
        stats_interval = 10
        last_stats = time.time()
        sent_count = 0

        while self._running:
            now = time.time()
            elapsed = now - last_tick

            # Tick interface counters
            self.iface_registry.tick_all(elapsed, self.link_utilization)
            last_tick = now

            samples = []

            # ── Flow samples ─────────────────────────────────────────────────
            if "flow" in self.sample_types:
                flow_samples = self._build_flow_samples()
                samples.extend(flow_samples)

            # ── Counter samples (periodic) ───────────────────────────────────
            if "counter" in self.sample_types:
                if now - self._last_counter_time >= self.counter_interval:
                    counter_samples = self._build_counter_samples()
                    samples.extend(counter_samples)
                    self._last_counter_time = now

            if samples:
                datagram = self._build_datagram(samples)
                self._send(datagram)
                sent_count += len(samples)

            # Stats logging
            if now - last_stats >= stats_interval:
                log.info(
                    "Sent %d samples in last %ds | datagram_seq=%d",
                    sent_count,
                    stats_interval,
                    self._datagram_seq,
                )
                sent_count = 0
                last_stats = now

            # Pace to target rate (sleep remainder of interval)
            elapsed_processing = time.time() - now
            sleep_time = interval - elapsed_processing
            if sleep_time > 0:
                time.sleep(sleep_time)

    # ─── sample builders ─────────────────────────────────────────────────────

    def _build_flow_samples(self) -> list[bytes]:
        samples = []
        n = min(self.samples_per_datagram, max(1, self.flows_per_second // 20))

        for _ in range(n):
            flow: FlowSpec = next(self._flow_iter)
            self._flow_seq += 1

            # Build sampled packet header
            if flow.ip_version == 6:
                raw_header = build_ethernet_ipv6_header(
                    src_mac=flow.src_mac,
                    dst_mac=flow.dst_mac,
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    src_port=flow.src_port,
                    dst_port=flow.dst_port,
                    protocol=flow.protocol,
                    vlan_id=flow.vlan_id,
                    hop_limit=flow.ttl,
                )
            else:
                raw_header = build_ethernet_ipv4_header(
                    src_mac=flow.src_mac,
                    dst_mac=flow.dst_mac,
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    src_port=flow.src_port,
                    dst_port=flow.dst_port,
                    protocol=flow.protocol,
                    vlan_id=flow.vlan_id,
                    tos=flow.tos,
                    ttl=flow.ttl,
                    pkt_id=self._flow_seq,
                )
            # Truncate header to max_header_size
            truncated = raw_header[: self.max_header_size]

            pkt_record = build_raw_packet_header_record(
                header_data=truncated,
                frame_length=flow.frame_length,
                header_protocol=1,  # Ethernet
                stripped=4,         # FCS stripped
            )

            # Estimate sample_pool from sampling_rate
            sample_pool = self._flow_seq * self.sampling_rate

            flow_sample = build_flow_sample(
                sequence_number=self._flow_seq,
                source_id_type=0,   # ifIndex
                source_id_index=flow.input_if,
                sampling_rate=self.sampling_rate,
                sample_pool=sample_pool,
                drops=0,
                input_if=flow.input_if,
                output_if=flow.output_if,
                flow_records=[pkt_record],
            )
            samples.append(flow_sample)

        return samples

    def _build_counter_samples(self) -> list[bytes]:
        samples = []
        for idx in self.if_indices:
            self._counter_seq += 1
            iface = self.iface_registry.get(idx)

            counter_record = build_generic_if_counter_record(
                if_index=iface.if_index,
                if_type=iface.if_type,
                if_speed=iface.if_speed,
                if_direction=iface.if_direction,
                if_admin_status=iface.admin_status,
                if_oper_status=iface.oper_status,
                in_octets=iface.in_octets,
                in_ucast_pkts=iface.in_ucast_pkts,
                in_multicast_pkts=iface.in_multicast_pkts,
                in_broadcast_pkts=iface.in_broadcast_pkts,
                in_discards=iface.in_discards,
                in_errors=iface.in_errors,
                in_unknown_protos=iface.in_unknown_protos,
                out_octets=iface.out_octets,
                out_ucast_pkts=iface.out_ucast_pkts,
                out_multicast_pkts=iface.out_multicast_pkts,
                out_broadcast_pkts=iface.out_broadcast_pkts,
                out_discards=iface.out_discards,
                out_errors=iface.out_errors,
                promiscuous_mode=iface.promiscuous_mode,
            )

            counter_sample = build_counter_sample(
                sequence_number=self._counter_seq,
                source_id_type=0,
                source_id_index=idx,
                counter_records=[counter_record],
            )
            samples.append(counter_sample)

        return samples

    def _build_datagram(self, samples: list[bytes]) -> bytes:
        self._datagram_seq += 1
        uptime_ms = int((time.time() - self._start_time) * 1000)
        return build_sflow_datagram(
            agent_ip=self.agent_ip,
            sub_agent_id=self.sub_agent_id,
            sequence_number=self._datagram_seq,
            uptime_ms=uptime_ms,
            samples=samples,
            agent_ip_version=self._agent_ip_version,
        )

    def _send(self, datagram: bytes):
        try:
            self._sock.sendto(datagram, (self.target_host, self.target_port))
            log.debug(
                "Sent %d bytes to %s:%d (datagram #%d)",
                len(datagram),
                self.target_host,
                self.target_port,
                self._datagram_seq,
            )
        except OSError as e:
            log.error("UDP send failed: %s", e)
