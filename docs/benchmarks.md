# Performance benchmark — owner-run measurements

Windows-11-10.0.26200-SP0; Python 3.14.7; Intel64 Family 6 Model 189 Stepping 1 GenuineIntel; 8 logical CPUs. Five runs; values below are the owner's **medians**, measured with a 100,000-row synthetic DuckDB table and a separate 100,088-packet PCAP for parsing.

| Stage | Median seconds |
|---|---:|
| DuckDB load (100,000 rows) | 0.21757320000324398 |
| SYN and scan detector | 0.004153400004724972 |
| ICMP detector | 0.0016641999973217025 |
| ARP detector | 0.001443299996026326 |
| DNS detector | 0.001469900002120994 |
| Malformed flags detector | 0.0017327000023215078 |
| Alert build | 0.021273799997288734 |
| Dashboard SQL queries | 0.0021051000003353693 |
| Dashboard AppTest load | 0.2817319000023417 |

The measured dashboard AppTest load is below the 3-second target (`dashboard_under_3s: true`). A separate single-run observation was 0.80 seconds for AppTest; it is not substituted for the five-run median.

| Parser measurement on 100,088 packets | Owner result |
|---|---:|
| Parser time, **with `tracemalloc` active** (five-run median; not clean timing) | 68.20749100000103 s |
| Peak traced Python allocation (five-run median) | 413.93397998809814 MiB |

A separate single run reported parser time of 60.60 seconds, also from the tracing-enabled implementation. **Clean parser timing requires a rerun** after the separate timing and memory passes in `tools/benchmark.py`. `tracemalloc` observes Python allocations, not all native memory. Generator wall time was 3.0257326 seconds for 1,088 output packets (`--packets 1000`) and 35.4696577 seconds for 100,088 output packets (`--packets 100000`); those are generation times, not parsing times.

## Proposed parser memory design (not implemented)

`scapy_scan.process_pcap` currently calls `rdpcap`, which holds all packets in memory before building a DataFrame. If the measured memory warrants a change, use `PcapReader` to iterate the file and build bounded batches. Append each batch to DuckDB while keeping the 15-column schema and NULL semantics. The current `process_pcap` return contract expects a complete DataFrame, so a streaming ingestion entry point would be needed rather than silently changing that function. Compare streaming and current output on `test_traffic.pcap`, retain the six-alert golden result, and remeasure memory and throughput before adopting it.
