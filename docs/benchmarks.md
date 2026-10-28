# Performance benchmark — PENDING owner measurements

Run `tools/benchmark.py` on the owner's machine and paste the **actual terminal JSON** here.
All values below are placeholders, not measurements.

| Item | Result |
|---|---|
| Machine, Python, CPU | PENDING |
| Packet rows | PENDING |
| Runs and statistic | PENDING |
| Reference PCAP parser time and rows | PENDING |
| Parser peak traced Python allocation | PENDING |
| DuckDB load | PENDING |
| Each detector query | PENDING |
| Alert build | PENDING |
| Dashboard SQL queries | PENDING |
| Dashboard AppTest data load | PENDING |
| Under 3-second dashboard target | PENDING |

Parser memory includes Python allocations tracked by `tracemalloc`; it does not measure all native memory.
If the parser shows an actual memory problem, evaluate chunked `PcapReader` in a later review.
