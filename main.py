import os
import sys
import subprocess
import argparse
import duckdb
import pandas as pd
from dotenv import load_dotenv

from scapy_scan import process_pcap, capture_live_traffic, get_network_interfaces
from alerts import build_alerts, save_alerts

DB_PATH = "test.duckdb"
DEFAULT_PCAP = "test_traffic.pcap"


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=" Network Traffic Intrusion Detection Pipeline"
    )
    parser.add_argument(
        "--mode",
        choices=["pcap", "live"],
        default=None,
        help="Traffic source mode: 'pcap' for recorded file, 'live' for real-time capture",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Shortcut to enable live network traffic capture mode",
    )
    parser.add_argument(
        "--pcap",
        type=str,
        default=DEFAULT_PCAP,
        help=f"Path to .pcap traffic file (default: '{DEFAULT_PCAP}')",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of packets to capture in live mode (default: 100, 0 for unlimited until timeout)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Capture timeout in seconds for live mode (default: 30)",
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Network interface to sniff on in live mode (default: primary interface)",
    )
    parser.add_argument(
        "--db",
        type=str,
        default=DB_PATH,
        help=f"Path to DuckDB database (default: '{DB_PATH}')",
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="Skip threat intelligence & GeoIP enrichment",
    )
    parser.add_argument(
        "--vt",
        action="store_true",
        help="Enable automated VirusTotal queries during enrichment (subject to VT rate limits)",
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Skip launching the Streamlit dashboard after analysis",
    )
    return parser.parse_args()


def prompt_user_mode():
    """Interactive mode selection prompt when run without command-line arguments."""
    print("\nSelect traffic source:")
    print("  [1] Analyze pre-recorded PCAP file (default)")
    print("  [2] Capture live network traffic")
    
    try:
        choice = input("Enter choice [1/2] (default: 1): ").strip()
    except (EOFError, KeyboardInterrupt):
        choice = "1"

    if choice == "2":
        mode = "live"
        count_str = input("Enter packet count to capture [default: 100]: ").strip()
        count = int(count_str) if count_str.isdigit() else 100

        timeout_str = input("Enter timeout in seconds [default: 30]: ").strip()
        timeout = int(timeout_str) if timeout_str.isdigit() else 30

        ifaces = get_network_interfaces()
        if ifaces:
            print("\nAvailable interfaces:")
            for idx, iface in enumerate(ifaces[:8], 1):
                print(f"  [{idx}] {iface}")
        iface_choice = input("Enter interface name or number (hit Enter for default): ").strip()
        iface = None
        if iface_choice.isdigit() and 1 <= int(iface_choice) <= len(ifaces):
            iface = ifaces[int(iface_choice) - 1]
        elif iface_choice:
            iface = iface_choice

        return mode, None, count, timeout, iface
    else:
        mode = "pcap"
        pcap_path = input(f"Enter path to .pcap file [default: {DEFAULT_PCAP}]: ").strip()
        if not pcap_path:
            pcap_path = DEFAULT_PCAP
        return mode, pcap_path, 100, 30, None


def ingest_packets(
    mode: str,
    pcap_path: str = DEFAULT_PCAP,
    count: int = 100,
    timeout: int = 30,
    iface: str = None,
    db_path: str = DB_PATH,
) -> pd.DataFrame:
    """Parse packets from either pre-recorded PCAP or live network interface, and save to DuckDB."""
    if mode == "live":
        print(f"\n[1/4] 📡 Starting LIVE capture (count={count}, timeout={timeout}s, interface={iface or 'default'})...")
        print("      (Tip: On Windows, live capture requires Npcap/WinPcap with administrative privileges)")
        try:
            df = capture_live_traffic(count=count, timeout=timeout, iface=iface)
        except PermissionError:
            print("[!] Permission Denied: Live packet capture requires Administrator/root privileges.")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Live capture error: {e}")
            sys.exit(1)
    else:
        if not os.path.exists(pcap_path):
            sample_fallback = os.path.join("tests", "data", "sample_pcap.pcap")
            if os.path.exists(sample_fallback):
                print(f"[!] Warning: '{pcap_path}' not found, falling back to '{sample_fallback}'")
                pcap_path = sample_fallback
            else:
                raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        print(f"\n[1/4]  Parsing pre-recorded traffic from '{pcap_path}'...")
        df = process_pcap(pcap_path)

    print(f"[+] Successfully extracted {len(df):,} packet records.")

    print(f"\n[2/4]  Storing connections into DuckDB ('{db_path}')...")
    con = duckdb.connect(db_path)
    con.register("df_temp", df)
    con.execute("CREATE OR REPLACE TABLE connections AS SELECT * FROM df_temp")
    con.unregister("df_temp")
    con.close()
    print("[+] Table 'connections' updated.")
    return df


def detect_and_enrich(
    db_path: str = DB_PATH,
    enrich: bool = True,
    include_vt: bool = False,
) -> pd.DataFrame:
    """Run intrusion detection rules, MITRE ATT&CK tagging, and Threat Intel."""
    print(f"\n[3/4]  Running signature detectors and MITRE ATT&CK mapping...")
    con = duckdb.connect(db_path)

    alerts_df = build_alerts(con, enrich=enrich, include_virustotal=include_vt)

    if alerts_df.empty:
        print("[i] Traffic clean. No intrusion alerts raised.")
    else:
        print(f"[+] Detected {len(alerts_df)} threat alerts across {alerts_df['ipsrc'].nunique()} unique source IPs:")
        for _, row in alerts_df.iterrows():
            geo_info = f" ({row.get('country', 'Unknown')})" if 'country' in row else ""
            print(f"    - [{row['detection_type']}] {row['ipsrc']}{geo_info}: {row['details']} | {row['mitre_technique']}")

    save_alerts(con, alerts_df)
    con.close()
    print("[+] Table 'alerts' updated in database.")
    return alerts_df


def launch_dashboard():
    """Launch the interactive Streamlit dashboard."""
    print("\n" + "=" * 60)
    print(" [4/4] Launching Streamlit Intrusion Detection Dashboard...")
    print("=" * 60)

    dashboard_file = os.path.join(os.path.dirname(__file__), "dashboard.py")
    cmd = [sys.executable, "-m", "streamlit", "run", dashboard_file]

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[+] Dashboard stopped by user.")


def main():
    load_dotenv()  # Load .env before anything reads environment variables
    print("=" * 60)
    print(" NETWORK TRAFFIC INTRUSION DETECTION PIPELINE")
    print("=" * 60)

    args = parse_arguments()

    # Determine mode: CLI flag vs interactive prompt
    if args.live:
        mode = "live"
        pcap_path = None
        count = args.count
        timeout = args.timeout
        iface = args.interface
    elif args.mode:
        mode = args.mode
        pcap_path = args.pcap
        count = args.count
        timeout = args.timeout
        iface = args.interface
    else:
        # Check if stdin is interactive (terminal)
        if sys.stdin.isatty():
            mode, pcap_path, count, timeout, iface = prompt_user_mode()
        else:
            mode = "pcap"
            pcap_path = args.pcap
            count = args.count
            timeout = args.timeout
            iface = args.interface

    # Step 1 & 2: Ingest packets (PCAP or Live) & Save to DuckDB
    ingest_packets(
        mode=mode,
        pcap_path=pcap_path or DEFAULT_PCAP,
        count=count,
        timeout=timeout,
        iface=iface,
        db_path=args.db,
    )

    # Step 3: Run Threat Detection, MITRE ATT&CK, & Threat Intel
    detect_and_enrich(
        db_path=args.db,
        enrich=not args.no_enrich,
        include_vt=args.vt,
    )

    # Step 4: Launch Dashboard
    if not args.no_dashboard:
        launch_dashboard()
    else:
        print("\n[+] Analysis complete. (--no-dashboard specified)")


if __name__ == "__main__":
    main()