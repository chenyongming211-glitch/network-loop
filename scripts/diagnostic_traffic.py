#!/usr/bin/env python3
"""Bounded generated-veth traffic diagnostics, never deployment-gate evidence.

Run only inside an authorized outer acceptance transaction. This utility does
not create interfaces, attach programs, alter network settings, or clean objects.
"""
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time

WARMUP_NS = 500_000_000
MEASUREMENT_NS = 5_000_000_000
WARMUP_PACKET_LIMIT = 100_000
MEASUREMENT_PACKET_LIMIT = 2_000_000


def generated_interface(run_id, side):
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise ValueError("invalid generated run ID")
    if side not in ("host", "peer"):
        raise ValueError("invalid generated side")
    return ("l2h" if side == "host" else "l2n") + run_id[:10]


def validate_link(link, run_id, side, ifindex):
    name = generated_interface(run_id, side)
    if (type(ifindex) is not int or ifindex <= 0
            or link.get("ifindex") != ifindex or link.get("ifname") != name
            or "master" in link or "UP" not in link.get("flags", [])
            or link.get("linkinfo", {}).get("info_kind") != "veth"):
        raise ValueError("generated interface identity, topology or state changed")


def validate_namespace(run_id, side, current, initial, generated):
    generated_interface(run_id, side)
    if initial == generated or current != (initial if side == "host" else generated):
        raise ValueError("generated namespace identity mismatch")


def fingerprint_selected(frame):
    if not 60 <= len(frame) <= 65535:
        raise ValueError("frame is outside the fingerprint contract")
    value = 0xcbf29ce484222325
    for byte in len(frame).to_bytes(2, "big") + frame[:60]:
        value = ((value ^ byte) * 0x100000001b3) & 0xffffffffffffffff
    return value & 15 == 0


def parse_mac(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
        raise ValueError("invalid diagnostic MAC")
    address = bytes.fromhex(value.replace(":", ""))
    if address == bytes(6) or address[0] & 1:
        raise ValueError("diagnostic MAC must be nonzero unicast")
    return address


def build_corpus(profile, source_mac="02:00:00:00:00:01", destination_mac="02:00:00:00:00:02"):
    if profile not in ("mixed", "selected", "unselected"):
        raise ValueError("invalid diagnostic corpus")
    source, destination = parse_mac(source_mac), parse_mac(destination_mac)
    header = (destination + source + bytes.fromhex("08060001080006040001")
              + source + bytes(4) + destination + bytes(4))
    frames = []
    # ARP has a kernel receiver; an unhandled EtherType increments rx_dropped
    # even without eBPF. Use peer MACs and zero IPs, matching the formal harness.
    # The corpus stays identical across modes for each direction in a transaction.
    for variant in range(256):
        for size in (64, 512, 1514):
            frame = header + bytes(17) + bytes([variant]) + bytes(size - 60)
            selected = fingerprint_selected(frame)
            if profile == "mixed" or selected == (profile == "selected"):
                frames.append(frame)
    return tuple(frames)


def measure_window(send, frames, clock, duration_ns, packet_limit, noise=None):
    if (type(duration_ns) is not int or not 0 < duration_ns <= MEASUREMENT_NS
            or type(packet_limit) is not int or not 0 < packet_limit <= MEASUREMENT_PACKET_LIMIT
            or not frames or len(frames) > 768
            or any(not isinstance(f, bytes) or len(f) not in (64, 512, 1514) for f in frames)):
        raise ValueError("invalid bounded measurement inputs")
    # Precompute content-selection and frame metadata OUTSIDE the timed window.
    corpus = tuple((frame, len(frame), fingerprint_selected(frame)) for frame in frames)
    packets = byte_count = selected_count = 0
    before = noise() if noise else None
    started = previous = clock()
    deadline = started + duration_ns
    while packets < packet_limit:
        now = clock()
        if now < previous:
            raise RuntimeError("monotonic clock moved backwards")
        previous = now
        if now >= deadline:
            break
        frame, length, selected = corpus[packets % len(corpus)]
        if send(frame) != length:
            raise RuntimeError("incomplete packet send")
        packets += 1
        byte_count += length
        selected_count += selected
    ended = clock()
    after = noise() if noise else None
    if ended < previous or ended <= started or packets == 0:
        raise RuntimeError("invalid measurement clock or empty window")
    elapsed = ended - started
    result = {
        "packets": packets, "bytes": byte_count, "elapsed_ns": elapsed,
        "packets_per_second": packets * 1_000_000_000 // elapsed,
        "bytes_per_second": byte_count * 1_000_000_000 // elapsed,
        "selected_packets": selected_count,
        "selected_ratio_permille": selected_count * 1000 // packets,
        "stop_reason": "duration" if ended >= deadline else "packet_limit",
    }
    if noise:
        from diagnostic_noise import delta
        result['noise'] = delta(before, after, elapsed)
    return result


def run_windows(send, frames, clock, verify_identity=lambda: None, noise=None):
    warmup = measure_window(send, frames, clock, WARMUP_NS, WARMUP_PACKET_LIMIT, noise)
    verify_identity()
    measurement = measure_window(send, frames, clock, MEASUREMENT_NS, MEASUREMENT_PACKET_LIMIT, noise)
    verify_identity()
    return {"diagnostic_schema_version": 1, "deployment_gate_evidence": False,
            "warmup": warmup, "measurement": measurement}


def namespace_identity(path):
    metadata = os.stat(path)
    return metadata.st_dev, metadata.st_ino


def inspect_target(run_id, side, ifindex):
    interface = generated_interface(run_id, side)
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("diagnostic traffic requires Linux root")
    validate_namespace(run_id, side, namespace_identity("/proc/self/ns/net"),
                       namespace_identity("/proc/1/ns/net"),
                       namespace_identity("/run/netns/l2ns-" + run_id[:12]))
    result = subprocess.run(["ip", "-j", "-d", "link", "show", "dev", interface],
                            check=True, capture_output=True, timeout=5)
    if len(result.stdout) > 65536:
        raise ValueError("interface inspection output exceeded bound")
    records = json.loads(result.stdout)
    if not isinstance(records, list) or len(records) != 1:
        raise ValueError("generated interface is not unique")
    validate_link(records[0], run_id, side, ifindex)
    if socket.if_nametoindex(interface) != ifindex:
        raise ValueError("interface changed during inspection")
    return interface


def configure_socket(channel, mode):
    if mode not in ('timeout', 'nonblocking'):
        raise ValueError('invalid bounded send mode')
    # Both modes are OS-nonblocking. EAGAIN in the explicit nonblocking mode
    # aborts the trial; never hide loss with retries or relax forwarding checks.
    channel.settimeout(1.0 if mode == 'timeout' else 0.0)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--side", choices=("host", "peer"), required=True)
    parser.add_argument("--ifindex", type=int, required=True)
    parser.add_argument("--profile", choices=("mixed", "selected", "unselected"), required=True)
    parser.add_argument("--destination-mac", required=True)
    parser.add_argument("--send-mode", choices=('timeout', 'nonblocking'), default='timeout')
    parser.add_argument("--noise", action='store_true')
    args = parser.parse_args(argv)
    try:
        interface = inspect_target(args.run_id, args.side, args.ifindex)
        with open("/sys/class/net/" + interface + "/address", encoding="ascii") as address:
            source_mac = address.read(64).strip()
        frames = build_corpus(args.profile, source_mac, args.destination_mac)
        verify = lambda: inspect_target(args.run_id, args.side, args.ifindex)
        noise = None
        if args.noise:
            from diagnostic_noise import snapshot
            noise = snapshot
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as channel:
            configure_socket(channel, args.send_mode)
            channel.bind((interface, 0))
            verify()
            result = run_windows(channel.send, frames, time.monotonic_ns, verify, noise)
        result.update(run_id=args.run_id, side=args.side, ifindex=args.ifindex,
                      profile=args.profile, corpus_frames=len(frames), send_mode=args.send_mode)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print("diagnostic traffic refused or failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
