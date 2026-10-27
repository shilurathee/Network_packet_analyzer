import sys
import asyncio

# Fix Windows ProactorEventLoop hang on shutdown (ConnectionResetError WinError 10054)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import duckdb
import streamlit as st

DB_PATH = "test.duckdb"

st.set_page_config(page_title="Network IDS", page_icon="🛡️", layout="wide")


import pandas as pd

@st.cache_data(ttl=5)
def run_query(sql):
    try:
        con = duckdb.connect(DB_PATH, read_only=True)
        df = con.execute(sql).df()
        con.close()
        return df
    except Exception:
        return pd.DataFrame()


import os

# ---- Sidebar: Traffic Source & Ingestion ----
st.sidebar.header("📡 Traffic Source & Capture")
traffic_mode = st.sidebar.radio(
    "Choose Analysis Mode:",
    ["Pre-recorded PCAP", "Live Network Capture"],
)

if traffic_mode == "Pre-recorded PCAP":
    st.sidebar.markdown("#### 📂 Analyze PCAP File")
    local_pcaps = [f for f in os.listdir(".") if f.endswith(".pcap")]
    selected_pcap = st.sidebar.selectbox("Select local PCAP:", local_pcaps, index=0 if local_pcaps else None)
    uploaded_pcap = st.sidebar.file_uploader("Or upload .pcap file:", type=["pcap", "cap"])

    if st.sidebar.button("Run PCAP Analysis", use_container_width=True):
        with st.spinner("Parsing packets and running detections..."):
            target_pcap = None
            if uploaded_pcap is not None:
                os.makedirs("data", exist_ok=True)
                target_pcap = os.path.join("data", uploaded_pcap.name)
                with open(target_pcap, "wb") as f:
                    f.write(uploaded_pcap.getbuffer())
            elif selected_pcap:
                target_pcap = selected_pcap

            if target_pcap:
                from scapy_scan import process_pcap
                from alerts import build_alerts, save_alerts
                df = process_pcap(target_pcap)
                con = duckdb.connect(DB_PATH)
                con.register("df_temp", df)
                con.execute("CREATE OR REPLACE TABLE connections AS SELECT * FROM df_temp")
                con.unregister("df_temp")
                alerts_df = build_alerts(con, enrich=True)
                save_alerts(con, alerts_df)
                con.close()
                st.sidebar.success(f"Analyzed {len(df):,} packets!")
                st.rerun()

elif traffic_mode == "Live Network Capture":
    st.sidebar.markdown("#### 🔴 Live Packet Sniffing")
    pkt_count = st.sidebar.number_input("Packets to capture:", min_value=10, max_value=5000, value=50, step=10)
    capture_timeout = st.sidebar.number_input("Timeout (seconds):", min_value=5, max_value=300, value=15, step=5)

    if st.sidebar.button("Start Live Capture", use_container_width=True):
        with st.spinner(f"Sniffing {pkt_count} packets (timeout {capture_timeout}s)..."):
            try:
                from scapy_scan import capture_live_traffic
                from alerts import build_alerts, save_alerts
                df = capture_live_traffic(count=int(pkt_count), timeout=int(capture_timeout))
                if not df.empty:
                    con = duckdb.connect(DB_PATH)
                    con.register("df_temp", df)
                    con.execute("CREATE OR REPLACE TABLE connections AS SELECT * FROM df_temp")
                    con.unregister("df_temp")
                    alerts_df = build_alerts(con, enrich=True)
                    save_alerts(con, alerts_df)
                    con.close()
                    st.sidebar.success(f"Captured & analyzed {len(df):,} packets!")
                    st.rerun()
                else:
                    st.sidebar.warning("No packets captured within timeout.")
            except Exception as e:
                st.sidebar.error(f"Capture failed: {e}")

st.title("🛡️ Network Intrusion Detection Dashboard")

total_df = run_query("SELECT COUNT(*) AS n FROM connections")
total_packets = total_df["n"].iloc[0] if not total_df.empty and "n" in total_df.columns else 0
alerts = run_query("SELECT * FROM alerts")

# ---- Top-line numbers ----
c1, c2, c3 = st.columns(3)
c1.metric("Packets analyzed", f"{total_packets:,}")
c2.metric("Alerts raised", len(alerts) if not alerts.empty else 0)
c3.metric("Unique attacker IPs", alerts["ipsrc"].nunique() if not alerts.empty and "ipsrc" in alerts.columns else 0)

if alerts.empty:
    st.info("No alerts found in the database. Use the sidebar to analyze a PCAP file or start a live capture!")
    st.stop()

# ---- Alerts table with filter ----
st.subheader("Alerts")
types = sorted(alerts["detection_type"].unique())
selected = st.multiselect("Filter by attack type", types, default=types)
st.dataframe(alerts[alerts["detection_type"].isin(selected)], hide_index=True)

# ---- Charts ----
left, right = st.columns(2)

with left:
    st.subheader("Alerts by attack type")
    st.bar_chart(alerts["detection_type"].value_counts())

with right:
    st.subheader("Traffic by protocol")
    proto = run_query("SELECT protocol, COUNT(*) AS packets FROM connections GROUP BY protocol")
    st.bar_chart(proto.set_index("protocol"))

# ---- Geographic Map (if enriched with lat/lon) ----
if "latitude" in alerts.columns and "longitude" in alerts.columns:
    geo_df = alerts.dropna(subset=["latitude", "longitude"])
    if not geo_df.empty:
        st.subheader("🌍 Attacker Geographic Distribution")
        st.map(geo_df[["latitude", "longitude"]])

# ---- On-Demand Threat Intelligence Deep Dive ----
st.divider()
st.subheader("🔍 Threat Intelligence Deep Dive (AbuseIPDB, GeoIP, VirusTotal)")

from enrichment import check_ip_reputation, get_ip_location, check_virustotal_ip

investigate_col1, investigate_col2 = st.columns([3, 1])
with investigate_col1:
    target_ip = st.text_input(
        "Enter IP Address to investigate:",
        value=alerts["ipsrc"].iloc[0] if not alerts.empty and alerts["ipsrc"].iloc[0] else "",
    )
with investigate_col2:
    st.write("")
    st.write("")
    run_check = st.button("Query Threat Intel")

if run_check and target_ip:
    st.write(f"### Results for `{target_ip}`")
    res_col1, res_col2, res_col3 = st.columns(3)

    with res_col1:
        st.markdown("#### 🌐 Geolocation")
        geo_info = get_ip_location(target_ip)
        st.write(f"**Country:** {geo_info.get('country_name')} ({geo_info.get('country_code')})")
        st.write(f"**City:** {geo_info.get('city')}")
        st.write(f"**Coordinates:** {geo_info.get('latitude')}, {geo_info.get('longitude')}")
        st.write(f"**Time Zone:** {geo_info.get('time_zone')}")
        st.caption(f"Provider: {geo_info.get('provider')}")

    with res_col2:
        st.markdown("#### 🚨 AbuseIPDB")
        abuse_info = check_ip_reputation(target_ip)
        score = abuse_info.get("abuse_score", 0)
        st.metric("Abuse Confidence Score", f"{score}%")
        st.write(f"**Total Reports:** {abuse_info.get('total_reports', 0)}")
        st.write(f"**ISP:** {abuse_info.get('isp', 'N/A')}")
        st.write(f"**Domain:** {abuse_info.get('domain', 'N/A')}")
        if abuse_info.get("error"):
            st.warning(abuse_info.get("error"))

    with res_col3:
        st.markdown("#### 🦠 VirusTotal")
        vt_info = check_virustotal_ip(target_ip)
        malicious = vt_info.get("malicious_count", 0)
        st.metric("Malicious Detections", f"{malicious} engines")
        st.write(f"**Suspicious:** {vt_info.get('suspicious_count', 0)}")
        st.write(f"**Reputation:** {vt_info.get('reputation', 0)}")
        st.write(f"**AS Owner:** {vt_info.get('as_owner', 'N/A')}")
        if vt_info.get("error"):
            st.warning(vt_info.get("error"))