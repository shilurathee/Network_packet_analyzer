"""Load explainable detector thresholds and a capture-relative time window.

Inputs are optional environment overrides; output is an immutable Thresholds
value used by detectors. Defaults preserve the reference capture's six alerts.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Thresholds:
    """Keep rule cutoffs together so code and tests share one contract."""

    scan_min_ports: int = 10
    flood_min_syns: int = 50
    icmp_min: int = 20
    dns_min_size: int = 100
    arp_min_macs: int = 2
    window_seconds: int = 60

    @classmethod
    def from_env(cls):
        """Read integer overrides, rejecting invalid or nonpositive windows."""
        defaults = cls()
        values = {}
        for name in defaults.__dataclass_fields__:
            raw = os.getenv(name.upper())
            values[name] = int(raw) if raw is not None else getattr(defaults, name)
        if values["window_seconds"] <= 0:
            raise ValueError("WINDOW_SECONDS must be positive")
        return cls(**values)
