"""Extract per-source, capture-relative window statistics from packet headers."""

import numpy as np
import pandas as pd

from config import Thresholds

FEATURES = (
    "packets", "bytes", "length_mean", "length_std", "unique_ports",
    "unique_destinations", "syn_count", "syn_only_ratio", "icmp_count",
    "dns_count", "dns_length_mean", "tcp_fraction", "udp_fraction",
    "icmp_fraction", "arp_fraction", "flag_combinations",
    "interarrival_mean", "interarrival_std",
)
LOG_FEATURES = (
    "packets", "bytes", "unique_ports", "unique_destinations", "syn_count",
    "icmp_count", "dns_count", "flag_combinations",
)


def extract_features(packets: pd.DataFrame, window_seconds: int | None = None):
    """Return one row per observed source/window and its numeric feature vector.

    Windows are anchored at the first packet, matching the rule detectors.
    An ARP source is its claimed protocol address, not its Ethernet address.
    """
    window_seconds = window_seconds or Thresholds.from_env().window_seconds
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    columns = ["ipsrc", "window_start", "response_only", *FEATURES]
    if packets.empty:
        return pd.DataFrame(columns=columns)
    data = packets.copy()
    data["timestamp"] = pd.to_numeric(data["timestamp"], errors="coerce")
    data = data.dropna(subset=["timestamp"])
    if data.empty:
        return pd.DataFrame(columns=columns)
    origin = float(data["timestamp"].min())
    data["ipsrc"] = data["ipsrc"].fillna(data["arp_psrc"])
    data = data.dropna(subset=["ipsrc"])
    data = data[data["ipsrc"].astype(str) != "0.0.0.0"].copy()
    data["window_bucket"] = np.floor((data["timestamp"] - origin) / window_seconds).astype("int64")
    data["packet_length"] = pd.to_numeric(data["packet_length"], errors="coerce").fillna(0)
    data["tcpdst"] = pd.to_numeric(data["tcpdst"], errors="coerce")
    data["udpdst"] = pd.to_numeric(data["udpdst"], errors="coerce")
    records = []
    for (ip, bucket), frame in data.groupby(["ipsrc", "window_bucket"], sort=True):
        n = len(frame)
        timestamps = np.sort(frame["timestamp"].to_numpy(dtype=float))
        gaps = np.diff(timestamps)
        protocols = frame["protocol"].fillna("")
        flags = frame["tcpflags"].fillna("")
        dns = frame["udpdst"] == 53
        ports = pd.concat([frame["tcpdst"], frame["udpdst"]]).dropna()
        lengths = frame["packet_length"]
        records.append({
            "ipsrc": str(ip), "window_start": origin + int(bucket) * window_seconds,
            # A source sending only SYN+ACK responses is a responder, not an
            # initiating client. One such server among hundreds of clients
            # otherwise dominates a single global 99th-percentile cutoff.
            "response_only": bool(n >= 5 and (flags == "SA").all()),
            "packets": n, "bytes": lengths.sum(), "length_mean": lengths.mean(),
            "length_std": lengths.std(ddof=0), "unique_ports": ports.nunique(),
            "unique_destinations": frame["ipdst"].dropna().nunique(),
            "syn_count": (flags == "S").sum(), "syn_only_ratio": (flags == "S").sum() / n,
            "icmp_count": (frame["icmp_type"] == 8).sum(), "dns_count": dns.sum(),
            "dns_length_mean": lengths[dns].mean() if dns.any() else 0,
            "tcp_fraction": (protocols == "TCP").sum() / n,
            "udp_fraction": (protocols == "UDP").sum() / n,
            "icmp_fraction": (protocols == "ICMP").sum() / n,
            "arp_fraction": (protocols == "ARP").sum() / n,
            "flag_combinations": flags[flags != ""].nunique(),
            "interarrival_mean": gaps.mean() if len(gaps) else 0,
            "interarrival_std": gaps.std(ddof=0) if len(gaps) else 0,
        })
    return pd.DataFrame.from_records(records, columns=columns).fillna(0)


def model_matrix(features: pd.DataFrame):
    """Log-transform heavy counts without changing feature order or labels."""
    if not set(FEATURES).issubset(features.columns):
        raise ValueError(f"Missing ML features: {sorted(set(FEATURES) - set(features.columns))}")
    result = features.loc[:, list(FEATURES)].astype(float).copy()
    for column in LOG_FEATURES:
        result[column] = np.log1p(result[column].clip(lower=0))
    if not np.isfinite(result.to_numpy()).all():
        raise ValueError("Non-finite ML feature value")
    return result
