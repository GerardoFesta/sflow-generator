"""
Container tests for IPv6 sFlow generation.

Builds the Docker image from source and runs it against a local UDP listener
to verify that IPv6 sFlow v5 datagrams are correctly produced in the
containerised environment.

Requirements:
  - Docker must be installed and the daemon must be running.
  - Tests are marked @pytest.mark.docker and skipped if Docker is unavailable.

Run only these tests:
  python -m pytest tests/test_container.py -v

Skip container tests:
  python -m pytest tests/ -v -m "not docker"
"""

import os
import socket
import struct
import subprocess
import threading
import time

import pytest

# ─── constants ───────────────────────────────────────────────────────────────

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_IMAGE_TAG    = "sflow-generator-test:latest"
_IPV6_CONFIG  = os.path.join(_PROJECT_ROOT, "config-ipv6-test.yaml")
_LISTEN_PORT  = 19876   # must match config-ipv6-test.yaml collector.port


# ─── helpers ─────────────────────────────────────────────────────────────────

def _docker_available() -> bool:
    try:
        r = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=10
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _collect_datagrams(
    port: int,
    target_count: int = 10,
    timeout: float = 30.0,
) -> list[bytes]:
    """Bind a UDP listener on 0.0.0.0:port and collect up to target_count datagrams."""
    received: list[bytes] = []
    done = threading.Event()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(0.3)

    def _listen():
        while not done.is_set():
            try:
                data, _ = sock.recvfrom(65535)
                received.append(data)
                if len(received) >= target_count:
                    done.set()
            except socket.timeout:
                pass

    t = threading.Thread(target=_listen, daemon=True)
    t.start()
    done.wait(timeout=timeout)
    done.set()
    t.join(timeout=2.0)
    sock.close()
    return received


def _stop_container(name: str) -> None:
    subprocess.run(["docker", "stop", name], capture_output=True, timeout=15)


# ─── fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def docker_image():
    """Build the Docker image once per module; remove it after all tests finish."""
    subprocess.run(
        ["docker", "build", "-t", _IMAGE_TAG, "."],
        cwd=_PROJECT_ROOT,
        check=True,
    )
    yield _IMAGE_TAG
    subprocess.run(["docker", "rmi", "-f", _IMAGE_TAG], capture_output=True)


@pytest.fixture(scope="module")
def ipv6_datagrams(docker_image):
    """
    Bind the listener socket first, then start the container, collect 15
    datagrams (or wait 30 s), then stop everything.  Shared by all tests
    so the image is only run once.
    """
    container_name = "sflow-ipv6-container-test"
    received: list[bytes] = []
    done = threading.Event()

    # Bind before starting the container so no early packets are lost.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", _LISTEN_PORT))
    sock.settimeout(0.3)

    def _listen():
        while not done.is_set():
            try:
                data, _ = sock.recvfrom(65535)
                received.append(data)
                if len(received) >= 15:
                    done.set()
            except socket.timeout:
                pass

    listener_thread = threading.Thread(target=_listen, daemon=True)
    listener_thread.start()

    proc = subprocess.Popen(
        [
            "docker", "run", "--rm",
            "--name", container_name,
            "-v", f"{_IPV6_CONFIG}:/app/config.yaml:ro",
            docker_image,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    done.wait(timeout=30.0)

    _stop_container(container_name)
    proc.wait(timeout=10)
    done.set()
    listener_thread.join(timeout=2.0)
    sock.close()

    return received


# ─── tests ────────────────────────────────────────────────────────────────────

@pytest.mark.docker
@pytest.mark.skipif(not _docker_available(), reason="Docker daemon not available")
class TestContainerIPv6:
    """
    Verifies that the containerised generator produces valid IPv6 sFlow v5
    datagrams when configured with an IPv6 agent and IPv6 flow pattern.
    """

    def test_datagrams_are_received(self, ipv6_datagrams):
        """Container must emit at least 5 datagrams within the timeout."""
        assert len(ipv6_datagrams) >= 5, (
            f"Expected >= 5 datagrams from container, got {len(ipv6_datagrams)}"
        )

    def test_sflow_version_is_5(self, ipv6_datagrams):
        """Every datagram must start with sFlow version 5."""
        for i, dg in enumerate(ipv6_datagrams):
            version = struct.unpack_from("!I", dg, 0)[0]
            assert version == 5, f"Datagram {i}: expected version=5, got {version}"

    def test_ip_type_is_2_for_ipv6_agent(self, ipv6_datagrams):
        """ip_type field must be 2 (IPv6) in every datagram."""
        for i, dg in enumerate(ipv6_datagrams):
            ip_type = struct.unpack_from("!I", dg, 4)[0]
            assert ip_type == 2, f"Datagram {i}: expected ip_type=2, got {ip_type}"

    def test_agent_ip_is_correct(self, ipv6_datagrams):
        """Agent IP bytes must decode to the configured 2001:db8::1."""
        for i, dg in enumerate(ipv6_datagrams):
            agent_ip = socket.inet_ntop(socket.AF_INET6, dg[8:24])
            assert agent_ip == "2001:db8::1", (
                f"Datagram {i}: agent IP mismatch: {agent_ip}"
            )

    def test_flow_records_have_ipv6_ethertype(self, ipv6_datagrams):
        """Flow records must carry EtherType 0x86DD (IPv6)."""
        # Only check datagrams that contain flow samples (type=1)
        flow_datagrams = []
        for dg in ipv6_datagrams:
            offset = 40
            num_samples = struct.unpack_from("!I", dg, 36)[0]
            for _ in range(num_samples):
                if offset + 8 > len(dg):
                    break
                stype = struct.unpack_from("!I", dg, offset)[0]
                if stype == 1:
                    flow_datagrams.append(dg)
                    break
                slen = struct.unpack_from("!I", dg, offset + 4)[0]
                offset += 8 + slen

        assert flow_datagrams, "No flow-sample datagrams found in container output"

        # For IPv6 agent: samples start at 40; flow_sample(40) + raw_record(24) = 64
        # Ethernet header at 40+40+24=104, EtherType at 104+12=116
        eth_start = 40 + 40 + 24
        for i, dg in enumerate(flow_datagrams[:5]):
            ethertype = struct.unpack_from("!H", dg, eth_start + 12)[0]
            assert ethertype == 0x86DD, (
                f"Flow datagram {i}: expected 0x86DD, got 0x{ethertype:04X}"
            )

    def test_sequence_numbers_are_monotonic(self, ipv6_datagrams):
        """Datagram sequence numbers must strictly increase."""
        # sequence_number is at offset 28 for IPv6-agent datagrams
        seqs = [struct.unpack_from("!I", dg, 28)[0] for dg in ipv6_datagrams]
        for i in range(1, len(seqs)):
            assert seqs[i] > seqs[i - 1], (
                f"Non-monotonic sequence numbers: {seqs[i-1]} then {seqs[i]}"
            )

    def test_counter_samples_are_emitted(self, ipv6_datagrams):
        """Counter samples (type=2) must appear in the container output."""
        # The config sets counter_polling.interval_seconds=2, so within 30 s
        # of collection we should see at least one counter sample.
        found_counter = False
        for dg in ipv6_datagrams:
            offset = 40
            num_samples = struct.unpack_from("!I", dg, 36)[0]
            for _ in range(num_samples):
                if offset + 8 > len(dg):
                    break
                stype = struct.unpack_from("!I", dg, offset)[0]
                if stype == 2:
                    found_counter = True
                    break
                slen = struct.unpack_from("!I", dg, offset + 4)[0]
                offset += 8 + slen
            if found_counter:
                break
        assert found_counter, (
            "No counter samples (type=2) found in containerised IPv6 output"
        )
