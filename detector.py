import duckdb

def detect_port_scan_and_syn_flood(con):
    """unique_ports == 1  -> SYN flood
       unique_ports > 1   -> Port scan
    """
    return con.execute("""
        SELECT ipsrc,
               COUNT(*) AS total_syns,
               COUNT(DISTINCT tcpdst) AS unique_ports
        FROM connections
        WHERE tcpflags = 'S'
        GROUP BY ipsrc
        HAVING total_syns > 5
        ORDER BY total_syns DESC
    """).df()


def detect_icmp_flood(con, threshold=20):
    """Same skeleton as SYN flood: count ICMP echo requests (type 8) per source."""
    return con.execute(f"""
        SELECT ipsrc,
               COUNT(*) AS icmp_count
        FROM connections
        WHERE icmp_type = 8
        GROUP BY ipsrc
        HAVING icmp_count > {threshold}
        ORDER BY icmp_count DESC
    """).df()


def detect_arp_spoofing(con):
    """If one IP (arp_psrc) is claimed by more than one MAC (arp_hwsrc),
       that's a spoofed/conflicting ARP mapping."""
    return con.execute("""
        SELECT arp_psrc,
               COUNT(DISTINCT arp_hwsrc) AS mac_count
        FROM connections
        WHERE arp_psrc IS NOT NULL
        GROUP BY arp_psrc
        HAVING mac_count > 1
        ORDER BY mac_count DESC
    """).df()


def detect_dns_tunneling(con, size_threshold=150):
    """DNS traffic (udp port 53) with abnormally large packet size -
       normal lookups are small; tunneled data inflates packet length."""
    return con.execute(f"""
        SELECT ipsrc,
               udpdst,
               packet_length
        FROM connections
        WHERE udpdst = 53
          AND packet_length > {size_threshold}
        ORDER BY packet_length DESC
    """).df()


def detect_malformed_flags(con):
    """SYN + FIN set on the same packet is never valid TCP behavior -
       LIKE catches it even if other flags (like ACK) are also present."""
    return con.execute("""
        SELECT ipsrc, ipdst, tcpflags, timestamp
        FROM connections
        WHERE tcpflags LIKE '%S%'
          AND tcpflags LIKE '%F%'
    """).df()


def run_all_detectors(db_path="test.duckdb"):
    con = duckdb.connect(db_path)

    print("\n--- Port Scan / SYN Flood ---")
    print(detect_port_scan_and_syn_flood(con))

    print("\n--- ICMP Flood ---")
    print(detect_icmp_flood(con))

    print("\n--- ARP Spoofing ---")
    print(detect_arp_spoofing(con))

    print("\n--- DNS Tunneling ---")
    print(detect_dns_tunneling(con))

    print("\n--- Malformed Flags (SYN+FIN) ---")
    print(detect_malformed_flags(con))

    con.close()


if __name__ == "__main__":
    run_all_detectors()