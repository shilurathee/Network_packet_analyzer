"""Time only ML scoring, excluding PCAP parsing: --pcap PATH --runs 5."""

import argparse
import json
import platform
import statistics
import time
from pathlib import Path

from ml.detect import capture_hash, score
from scapy_scan import process_pcap


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--model", type=Path, default=Path("models/isolation_forest.joblib"))
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    packets = process_pcap(str(args.pcap))
    sha = capture_hash(args.pcap)
    timings = []
    windows = 0
    for _ in range(args.runs):
        start = time.perf_counter()
        windows = len(score(packets, args.model, capture_sha256=sha))
        timings.append(time.perf_counter() - start)
    print(json.dumps({"packets": len(packets), "windows": windows, "runs": args.runs,
                      "median_scoring_s": statistics.median(timings),
                      "machine": {"system": platform.platform(), "python": platform.python_version(),
                                  "processor": platform.processor()}}, indent=2))


if __name__ == "__main__":
    main()
