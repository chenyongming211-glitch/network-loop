"""Boundary-only sender telemetry; never changes scheduler configuration."""


def snapshot():
    return {}


def delta(before, after, elapsed_ns):
    return {}
