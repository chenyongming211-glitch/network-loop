"""Offline diagnostic schedule and conservative noise-aware comparisons."""
from statistics import median


def schedule():
    forward = ["fp_hash", "fp_metadata", "fp_clock", "fp_map", "fp_hash"]
    reverse = ["fp_hash", "fp_map", "fp_clock", "fp_metadata", "fp_hash"]
    return [list(forward if index % 2 == 0 else reverse) for index in range(5)]


def summarize(blocks):
    if not isinstance(blocks, list) or len(blocks) != 5:
        raise ValueError("exactly five complete blocks required")
    rates = []
    for rows, expected in zip(blocks, schedule()):
        if not isinstance(rows, list) or len(rows) != 5:
            raise ValueError("exactly five scheduled measurements per block required")
        current = []
        for row, profile in zip(rows, expected):
            if not isinstance(row, dict) or row.get("profile") != profile:
                raise ValueError("profile order mismatch")
            for field in ("packets", "elapsed_ns"):
                if type(row.get(field)) is not int or not 0 < row[field] <= 2**64 - 1:
                    raise ValueError("positive bounded integer measurement required")
            if not 10_000_000_000 <= row["elapsed_ns"] <= 12_000_000_000:
                raise ValueError("two complete five-second windows required")
            if row.get("duration_complete") is not True or row.get("forwarding_intact") is not True:
                raise ValueError("censored or incomplete forwarding measurement")
            for field in ("packet_drop_delta", "packet_error_delta"):
                if type(row.get(field)) is not int or row[field] != 0:
                    raise ValueError("nonzero or invalid link error delta")
            current.append(row["packets"] * 1_000_000_000 / row["elapsed_ns"])
        rates.append(current)
    anchors = [row[-1] / row[0] for row in rates]
    noise = max(0.01, *(abs(value - 1) for value in anchors))
    contrasts = [[], [], []]
    for index, row in enumerate(rates):
        hash_rate, metadata, clock, maps = (row[:4] if index % 2 == 0
                                            else [row[4], row[3], row[2], row[1]])
        for target, numerator, denominator in zip(contrasts, [metadata, clock, maps],
                                                 [hash_rate, metadata, clock]):
            target.append(numerator / denominator)
    comparisons = []
    for label, ratios in zip(("metadata/hash", "clock/metadata", "map/clock"), contrasts):
        classification = "unresolved"
        if max(ratios) < 1 - noise:
            classification = "resolved_lower_throughput"
        elif min(ratios) > 1 + noise:
            classification = "resolved_higher_throughput"
        comparisons.append({"comparison": label, "ratios": ratios,
                            "median_ratio": median(ratios), "classification": classification})
    return {"trial_count": 25, "deployment_gate_evidence": False,
            "anchor_ratios": anchors, "noise_fraction": noise, "comparisons": comparisons}
