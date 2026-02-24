#!/usr/bin/env python3
"""
sFlow v5 Packet Generator
Usage:
    python main.py [--config config.yaml] [--validate]
    python main.py --help
"""

import argparse
import logging
import signal
import sys
import os

import yaml

from sflow import SFlowGenerator


def setup_logging(level_name: str):
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        level=level,
        stream=sys.stdout,
    )


def load_config(path: str) -> dict:
    with open(path) as f:
        raw = yaml.safe_load(f)

    overrides = {
        "SFLOW_COLLECTOR_HOST": ("collector", "host"),
        "SFLOW_COLLECTOR_PORT": ("collector", "port"),
        "SFLOW_AGENT_IP": ("agent", "ip"),
        "SFLOW_AGENT_SUB_ID": ("agent", "sub_agent_id"),
        "SFLOW_SAMPLING_RATE": ("sampling", "rate"),
        "SFLOW_FLOWS_PER_SECOND": ("flow", "flows_per_second"),
        "SFLOW_COUNTER_INTERVAL": ("counter_polling", "interval_seconds"),
        "SFLOW_PATTERN": ("pattern", "type"),
        "SFLOW_LOG_LEVEL": None,  # handled separately
    }

    for env_key, cfg_path in overrides.items():
        val = os.environ.get(env_key)
        if val is None or cfg_path is None:
            continue
        section, key = cfg_path
        if section not in raw:
            raw[section] = {}
        try:
            val = int(val)
        except ValueError:
            pass
        raw[section][key] = val
        logging.debug("Env override: %s.%s = %s", section, key, val)

    return raw


def validate_config(config: dict) -> bool:
    errors = []

    if "collector" not in config or "host" not in config["collector"]:
        errors.append("Missing collector.host")
    if "agent" not in config or "ip" not in config["agent"]:
        errors.append("Missing agent.ip")

    ifaces = config.get("interfaces", [])
    if ifaces:
        for i, iface in enumerate(ifaces):
            if "index" not in iface:
                errors.append(f"Interface [{i}] missing 'index'")

    pattern = config.get("pattern", {})
    ptype = pattern.get("type", "random")
    valid_types = ["random", "web", "dns", "custom"]
    if ptype not in valid_types:
        errors.append(f"pattern.type '{ptype}' not in {valid_types}")

    if ptype == "custom" and not pattern.get("flows"):
        errors.append("pattern.type=custom requires pattern.flows list")

    if errors:
        for e in errors:
            logging.error("Config error: %s", e)
        return False

    logging.info("Config validation passed.")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="sFlow v5 Packet Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variable overrides:
  SFLOW_COLLECTOR_HOST    Collector hostname/IP
  SFLOW_COLLECTOR_PORT    Collector UDP port (default 6343)
  SFLOW_AGENT_IP          Simulated agent IP address
  SFLOW_AGENT_SUB_ID      Sub-agent ID (default 0)
  SFLOW_SAMPLING_RATE     Packet sampling rate (default 512)
  SFLOW_FLOWS_PER_SECOND  Flow samples to emit per second
  SFLOW_COUNTER_INTERVAL  Counter polling interval in seconds
  SFLOW_PATTERN           Traffic pattern: random|web|dns|custom
  SFLOW_LOG_LEVEL         Log level: DEBUG|INFO|WARNING|ERROR
        """,
    )
    parser.add_argument(
        "--config",
        default=os.environ.get("SFLOW_CONFIG", "config.yaml"),
        help="Path to YAML config file (default: config.yaml)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate config and exit without sending packets",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("SFLOW_LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO)",
    )
    args = parser.parse_args()

    setup_logging(args.log_level)

    try:
        config = load_config(args.config)
    except FileNotFoundError:
        logging.error("Config file not found: %s", args.config)
        sys.exit(1)
    except yaml.YAMLError as e:
        logging.error("YAML parse error: %s", e)
        sys.exit(1)

    if not validate_config(config):
        sys.exit(2)

    if args.validate:
        print("Config is valid. Exiting (--validate mode).")
        sys.exit(0)

    generator = SFlowGenerator(config)

    def _shutdown(sig, frame):
        logging.info("Received signal %s, shutting down...", signal.Signals(sig).name)
        generator.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    generator.start()


if __name__ == "__main__":
    main()
