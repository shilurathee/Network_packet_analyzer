# Performance benchmark — owner-run measurements

Windows-11-10.0.26200-SP0; Python 3.14.7; Intel64 Family 6 Model 189 Stepping 1, GenuineIntel; 8 logical CPUs. Five runs; values below are the owner's **rerun medians**, measured with a 100,000-row synthetic DuckDB table and a separate 100,088-packet PCAP for parsing. The parser timing pass runs without `tracemalloc`; a second pass measures peak traced Python allocation.

| Stage | Median seconds |
|---|---:|
| DuckDB load (100,000 rows) | 0.20729770000070857 |
| SYN and scan detector | 0.0038889000006747665 |
| ICMP detector | 0.000985600001513376 |
| ARP detector | 0.001032100000884384 |
| DNS detector | 0.0008483000001433538 |
| Malformed flags detector | 0.0008596000006946269 |
| Alert build | 0.014733899999555433 |
| Dashboard SQL queries | 0.0014900000005582115 |
| Dashboard AppTest load | 0.26696390000142856 |

The measured dashboard AppTest load is below the 3-second target (`dashboard_under_3s: true`).

| Parser measurement on 100,088 packets | Owner result |
|---|---:|
| Parser time, **without `tracemalloc`** (five-run median) | 14.604498099999546 s |
| Peak traced Python allocation (separate pass, five-run median) | 413.94189262390137 MiB |

The earlier tracing-enabled parser timing (68.20749100000103 seconds) is superseded by this clean timing; they are not directly comparable. `tracemalloc` observes Python allocations, not all native memory. Generator wall time was 3.0257326 seconds for 1,088 output packets (`--packets 1000`) and 35.4696577 seconds for 100,088 output packets (`--packets 100000`); those are generation times, not parsing times. The rerun printed GeoLite2, AppTest context and asyncio deprecation warnings, then completed with JSON; these warnings are tracked in [CHANGELOG.md](CHANGELOG.md) for Phase 7 cleanup.

## Proposed parser memory design (not implemented)

`scapy_scan.process_pcap` currently calls `rdpcap`, which holds all packets in memory before building a DataFrame. If the measured memory warrants a change, use `PcapReader` to iterate the file and build bounded batches. Append each batch to DuckDB while keeping the 15-column schema and NULL semantics. The current `process_pcap` return contract expects a complete DataFrame, so a streaming ingestion entry point would be needed rather than silently changing that function. Compare streaming and current output on `test_traffic.pcap`, retain the six-alert golden result, and remeasure memory and throughput before adopting it.
