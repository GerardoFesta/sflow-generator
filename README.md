# sFlow v5 Packet Generator

A fully spec-compliant, Dockerized sFlow v5 packet generator for testing network monitoring stacks (ntopng, sFlow-RT, pmacct, Wireshark, sflowtool, etc.).

---

## What is sFlow?

sFlow (RFC 3176 / sflow.org v5 spec) is a network monitoring protocol used by switches and routers. It sends **UDP datagrams** to a collector containing two types of samples:

| Sample Type | Description |
|---|---|
| **Flow Sample** | A truncated copy of a sampled packet header (1-in-N sampling) |
| **Counter Sample** | Periodic interface counters (octets, packets, errors, etc.) |

---

## Packet Structure (sFlow v5 over UDP/6343)

```
UDP Datagram
└── sFlow Datagram
    ├── version          = 5 (uint32)
    ├── agent_ip_type    = 1 (IPv4) | 2 (IPv6)
    ├── agent_ip         = 4 or 16 bytes
    ├── sub_agent_id     (uint32)
    ├── sequence_number  (uint32, monotonically increasing)
    ├── uptime_ms        (uint32, ms since boot)
    ├── num_samples      (uint32)
    └── samples[]
        ├── Flow Sample (enterprise=0, format=1)
        │   ├── sequence_number
        │   ├── source_id        = (type<<24) | index
        │   ├── sampling_rate    (1-in-N)
        │   ├── sample_pool      (total packets seen)
        │   ├── drops
        │   ├── input_if / output_if
        │   └── flow_records[]
        │       └── Raw Packet Header (enterprise=0, format=1)
        │           ├── header_protocol  (1=Ethernet, 11=IPv4)
        │           ├── frame_length     (original full frame size)
        │           ├── stripped         (bytes removed, e.g. FCS=4)
        │           └── header_data      (truncated packet bytes, ≤256B)
        └── Counter Sample (enterprise=0, format=2)
            ├── sequence_number
            ├── source_id
            └── counter_records[]
                └── Generic Interface Counters (enterprise=0, format=1)
                    ├── ifIndex, ifType, ifSpeed (64-bit)
                    ├── ifDirection, status
                    ├── ifIn/OutOctets (64-bit each)
                    └── ifIn/OutUcastPkts, Multicast, Broadcast,
                        Discards, Errors, UnknownProtos
```

All fields are **XDR-encoded (big-endian)**. Header data is **padded to 4-byte boundaries**.

---

## Configurable Parameters

### Via `config.yaml`

| Section | Key | Description |
|---|---|---|
| `collector` | `host` | sFlow collector hostname or IP |
| `collector` | `port` | UDP port (default: 6343) |
| `agent` | `ip` | Simulated switch/router IP address |
| `agent` | `sub_agent_id` | Sub-agent identifier (default: 0) |
| `sampling` | `rate` | 1-in-N packet sampling rate (default: 512) |
| `sampling` | `max_header_size` | Bytes of packet header to include (max 256) |
| `sampling` | `samples_per_datagram` | How many samples per UDP packet |
| `flow` | `flows_per_second` | Emission rate of flow sample records |
| `flow` | `sample_types` | `[flow, counter]` or subset |
| `counter_polling` | `interval_seconds` | How often to send interface counters |
| `interfaces[]` | `index` | ifIndex (unique per interface) |
| `interfaces[]` | `type` | ifType (6=ethernetCsmacd) |
| `interfaces[]` | `speed` | Link speed in bps |
| `interfaces[]` | `direction` | 1=full-duplex, 2=half-duplex |
| `interfaces[]` | `admin_status` / `oper_status` | 1=up, 2=down |
| `link_utilization` | — | Fraction of link capacity (for counter simulation) |
| `pattern` | `type` | Traffic pattern: `random`, `web`, `dns`, `custom` |

### Via Environment Variables (Docker-friendly)

| Variable | Overrides |
|---|---|
| `SFLOW_COLLECTOR_HOST` | `collector.host` |
| `SFLOW_COLLECTOR_PORT` | `collector.port` |
| `SFLOW_AGENT_IP` | `agent.ip` |
| `SFLOW_AGENT_SUB_ID` | `agent.sub_agent_id` |
| `SFLOW_SAMPLING_RATE` | `sampling.rate` |
| `SFLOW_FLOWS_PER_SECOND` | `flow.flows_per_second` |
| `SFLOW_COUNTER_INTERVAL` | `counter_polling.interval_seconds` |
| `SFLOW_PATTERN` | `pattern.type` |
| `SFLOW_LOG_LEVEL` | Log verbosity: DEBUG \| INFO \| WARNING \| ERROR |

---

## Traffic Patterns

| Pattern | Description |
|---|---|
| `random` | Random src/dst IPs, ports, protocols. Configure `src_subnet`, `dst_subnet`, `protocols`, `frame_size_min/max`, `vlan_id` |
| `web` | HTTP/HTTPS traffic simulation. Clients from `client_subnet` hitting `server_ips` on ports 80/443/8080/8443 |
| `dns` | DNS query/response simulation. Clients hitting `dns_servers` on UDP/53 |
| `custom` | Replay a fixed list of flows defined in config — ideal for deterministic test scenarios |

---

## Quick Start

### Option 1 — Run directly (Python 3.11+)

```bash
pip install -r requirements.txt

# Validate config
python main.py --config config.yaml --validate

# Start generating (point at your collector)
SFLOW_COLLECTOR_HOST=10.0.0.50 python main.py
```

### Option 2 — Docker with local sflowtool listener

```bash
# Starts generator + sflowtool listener (prints decoded packets to stdout)
docker-compose --profile with-listener up --build
```

### Option 3 — Docker, external collector

```bash
# Edit config.yaml or use env vars
SFLOW_COLLECTOR_HOST=10.0.0.50 \
SFLOW_COLLECTOR_PORT=6343 \
SFLOW_AGENT_IP=192.168.1.1 \
SFLOW_FLOWS_PER_SECOND=500 \
SFLOW_PATTERN=web \
docker-compose --profile default up --build
```

### Option 4 — Verify with Wireshark

```bash
# Capture on loopback, filter: udp.port == 6343
wireshark -f "udp port 6343" -i lo &
python main.py
```

---

## Examples

### Simulating a busy web tier

```yaml
# config.yaml
collector:
  host: "10.0.0.50"

agent:
  ip: "10.1.0.1"

sampling:
  rate: 256

flow:
  flows_per_second: 1000

pattern:
  type: web
  client_subnet: "10.100.0.0/16"
  server_ips:
    - "10.1.0.10"
    - "10.1.0.11"
    - "10.1.0.12"

interfaces:
  - index: 1
    speed: 10000000000
  - index: 2
    speed: 10000000000
```

### Deterministic test with fixed flows

```yaml
pattern:
  type: custom
  flows:
    - src_ip: "10.0.0.1"
      dst_ip: "10.0.0.2"
      src_port: 54321
      dst_port: 443
      protocol: 6
      frame_length: 1200
      vlan_id: 100
    - src_ip: "10.0.0.3"
      dst_ip: "8.8.8.8"
      src_port: 55000
      dst_port: 53
      protocol: 17
      frame_length: 100
```

---

## Extending

**Add a new traffic pattern**: subclass `TrafficPattern` in `patterns.py` and implement `flows() -> Iterator[FlowSpec]`. Register it in the `PATTERNS` dict.

**Add extended flow records**: implement a new builder function in `packet.py` following the `build_*_record()` convention and append it to the `flow_records` list in `generator.py`.

**Add IPv6 sFlow agent support**: set `agent_ip_version: 2` and provide an IPv6 `agent.ip` — the datagram builder already handles both.
