"""Build an isolated 18-column connections table for detector tests.

Inputs are packet-like dictionaries; the output is an in-memory DuckDB
connection, so tests never touch the user's database or network.
"""

import duckdb
import pytest

CONNECTION_COLUMNS = (
    "timestamp", "protocol", "packet_length", "ipsrc", "ipdst",
    "tcpsrc", "tcpdst", "tcpflags", "udpsrc", "udpdst", "icmp_type",
    "arp_hwsrc", "arp_psrc", "arp_hwdst", "arp_pdst", "arp_op",
    "dns_qname", "dns_qtype",
)


@pytest.fixture
def connections_db():
    """Return a factory for isolated packet tables and close them after a test."""
    connections = []

    def create(rows):
        con = duckdb.connect(":memory:")
        connections.append(con)
        con.execute("""
            CREATE TABLE connections (
                timestamp DOUBLE, protocol VARCHAR, packet_length INTEGER,
                ipsrc VARCHAR, ipdst VARCHAR, tcpsrc INTEGER, tcpdst INTEGER,
                tcpflags VARCHAR, udpsrc INTEGER, udpdst INTEGER,
                icmp_type INTEGER, arp_hwsrc VARCHAR, arp_psrc VARCHAR,
                arp_hwdst VARCHAR, arp_pdst VARCHAR, arp_op INTEGER,
                dns_qname VARCHAR, dns_qtype INTEGER
            )
        """)
        if rows:
            placeholders = ", ".join("?" for _ in CONNECTION_COLUMNS)
            con.executemany(
                f"INSERT INTO connections VALUES ({placeholders})",
                [tuple(row.get(column) for column in CONNECTION_COLUMNS) for row in rows],
            )
        return con

    yield create
    for con in connections:
        con.close()
