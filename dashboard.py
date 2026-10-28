"""
dashboard.py — Streamlit front-end for the Network Traffic IDS.

What it does:
  Reads the analysed data from test.duckdb (read-only), shows metric cards,
  a filterable alerts table, protocol charts, a pydeck geographic map of
  attacker IPs (when GeoIP data is available), a dedicated per-IP VirusTotal
  button with 15-second rate limiting and 24-hour cache.duckdb caching, and
  a manual GeoIP/AbuseIPDB lookup panel.

Why it exists:
  Humans need a quick visual overview so they can triage alerts without
  reading raw SQL results.

Inputs:  test.duckdb (read-only), cache.duckdb (read-write, VT cache only),
         .env for API keys.
Outputs: Streamlit web UI served on localhost:8501.
"""

import sys
import asyncio
import time
import ipaddress

# Fix Windows ProactorEventLoop hang on shutdown (ConnectionResetError WinError 10054)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from dotenv import load_dotenv
load_dotenv()  # Phase 1.4: load env once at the dashboard entry point

import duckdb
import pandas as pd
import streamlit as st

try:
    import pydeck as pdk
    _PYDECK_AVAILABLE = True
except ImportError:
    _PYDECK_AVAILABLE = False

import os

DB_PATH = os.getenv("IDS_DB_PATH", "test.duckdb")

st.set_page_config(
    page_title="Network IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_private(ip: str) -> bool:
    """Return True for any non-globally-routable IP (private / loopback / etc.)."""
    try:
        return not ipaddress.ip_address(str(ip).strip()).is_global
    except ValueError:
        return True


@st.cache_data(ttl=5)
def run_query(sql: str) -> pd.DataFrame:
    """Execute a read-only query against the main IDS database."""
    try:
        con = duckdb.connect(DB_PATH, read_only=True)
        df = con.execute(sql).df()
        con.close()
        return df
    except Exception:
        return pd.DataFrame()


# ---------------------------------------------------------------------------
# Sidebar — Traffic Source & Ingestion
# ---------------------------------------------------------------------------
st.sidebar.header("📡 Traffic Source & Capture")
traffic_mode = st.sidebar.radio(
    "Choose Analysis Mode:",
    ["Pre-recorded PCAP", "Live Network Capture"],
)

if traffic_mode == "Pre-recorded PCAP":
    st.sidebar.markdown("#### 📂 Analyze PCAP File")
    local_pcaps = [f for f in os.listdir(".") if f.endswith(".pcap")]
    selected_pcap = st.sidebar.selectbox(
        "Select local PCAP:", local_pcaps, index=0 if local_pcaps else None
    )
    uploaded_pcap = st.sidebar.file_uploader(
        "Or upload .pcap file:", type=["pcap", "cap"]
    )

    if st.sidebar.button("Run PCAP Analysis", use_container_width=True):
        with st.spinner("Parsing packets and running detections..."):
            target_pcap = None
            if uploaded_pcap is not None:
                os.makedirs("data", exist_ok=True)
                target_pcap = os.path.join("data", uploaded_pcap.name)
                with open(target_pcap, "wb") as fh:
                    fh.write(uploaded_pcap.getbuffer())
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
    st.sidebar.caption(
        "⚠️ Live capture requires **Administrator** privileges (Npcap AdminOnly=1)."
    )
    pkt_count = st.sidebar.number_input(
        "Packets to capture:", min_value=10, max_value=5000, value=50, step=10
    )
    capture_timeout = st.sidebar.number_input(
        "Timeout (seconds):", min_value=5, max_value=300, value=15, step=5
    )

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

# ---------------------------------------------------------------------------
# Main page — Title & Top Metrics
# ---------------------------------------------------------------------------
st.title("🛡️ Network Intrusion Detection Dashboard")

total_df = run_query("SELECT COUNT(*) AS n FROM connections")
total_packets = (
    int(total_df["n"].iloc[0])
    if not total_df.empty and "n" in total_df.columns
    else 0
)
alerts = run_query("SELECT * FROM alerts")

c1, c2, c3 = st.columns(3)
c1.metric("Packets analyzed", f"{total_packets:,}")
c2.metric("Alerts raised", len(alerts) if not alerts.empty else 0)
c3.metric(
    "Unique attacker IPs",
    alerts["ipsrc"].nunique()
    if not alerts.empty and "ipsrc" in alerts.columns
    else 0,
)

if alerts.empty:
    st.info(
        "No alerts found. Use the sidebar to analyze a PCAP file or start a live capture."
    )
    st.stop()

# ---------------------------------------------------------------------------
# Alerts Table
# ---------------------------------------------------------------------------
st.subheader("Alerts")
types = sorted(alerts["detection_type"].unique())
selected = st.multiselect("Filter by attack type", types, default=types)
st.dataframe(alerts[alerts["detection_type"].isin(selected)], hide_index=True)

# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------
left, right = st.columns(2)
with left:
    st.subheader("Alerts by attack type")
    st.bar_chart(alerts["detection_type"].value_counts())
with right:
    st.subheader("Traffic by protocol")
    proto = run_query(
        "SELECT protocol, COUNT(*) AS packets FROM connections GROUP BY protocol"
    )
    if not proto.empty:
        st.bar_chart(proto.set_index("protocol"))

# ---------------------------------------------------------------------------
# Phase 1.2 — Geographic Map
# ---------------------------------------------------------------------------
st.divider()
st.subheader("🌍 Where the Attacks Come From")

geo_alerts = run_query("""
    SELECT  a.ipsrc,
            r.latitude,
            r.longitude,
            r.country,
            r.city,
            COALESCE(r.abuse_score, 0)              AS abuse_score,
            COUNT(*)                                 AS alert_count,
            STRING_AGG(DISTINCT a.detection_type, ', ') AS alert_types
    FROM    alerts           a
    LEFT JOIN ip_reputation  r ON a.ipsrc = r.ip
    WHERE   r.latitude  IS NOT NULL
      AND   r.longitude IS NOT NULL
      AND   (r.status IS NULL OR r.status != 'internal')
    GROUP BY a.ipsrc, r.latitude, r.longitude, r.country, r.city, r.abuse_score
""")

if not geo_alerts.empty and _PYDECK_AVAILABLE:
    # Colour: green (low abuse) → red (high abuse)
    def _abuse_color(score: int) -> list:
        s = int(score or 0)
        return [min(255, s * 3), max(0, 200 - s * 2), 50, 200]

    geo_alerts["color"]  = geo_alerts["abuse_score"].apply(_abuse_color)
    geo_alerts["radius"] = (geo_alerts["alert_count"] * 40_000).clip(lower=30_000)

    layer = pdk.Layer(
        "ScatterplotLayer",
        data=geo_alerts,
        get_position=["longitude", "latitude"],
        get_radius="radius",
        get_fill_color="color",
        pickable=True,
        opacity=0.8,
        stroked=True,
        filled=True,
    )
    view = pdk.ViewState(
        latitude=float(geo_alerts["latitude"].mean()),
        longitude=float(geo_alerts["longitude"].mean()),
        zoom=2,
        pitch=0,
    )
    st.pydeck_chart(
        pdk.Deck(
            layers=[layer],
            initial_view_state=view,
            tooltip={
                "text": "IP: {ipsrc}\n{country}, {city}\nAbuse Score: {abuse_score}\nAlerts: {alert_count}\nTypes: {alert_types}"
            },
            map_style="dark",
        )
    )
else:
    if not _PYDECK_AVAILABLE:
        st.warning("pydeck not installed — map unavailable. Run `pip install pydeck`.")
    else:
        st.info(
            "No public IPs with geo-coordinates found. "
            "The map appears once real (public) traffic has been analysed with GeoIP data. "
            "Test data uses private 10.x addresses."
        )
    # Fallback: bar chart of alert counts by country
    country_df = run_query("""
        SELECT COALESCE(r.country, 'Unknown') AS country, COUNT(*) AS count
        FROM   alerts a
        LEFT JOIN ip_reputation r ON a.ipsrc = r.ip
        GROUP BY country
        ORDER BY count DESC
    """)
    if not country_df.empty:
        st.subheader("Alerts by Country")
        st.bar_chart(country_df.set_index("country"))

# ---------------------------------------------------------------------------
# Phase 1.3 — VirusTotal On-Demand (dedicated button, rate-limited, cached)
# ---------------------------------------------------------------------------
st.divider()
st.subheader("🦠 VirusTotal IP Analysis")
st.caption(
    "Results are cached for 24 hours (cache.duckdb). "
    "Calls are rate-limited to one per 15 seconds. "
    "Private IPs are skipped — VirusTotal only indexes public addresses."
)

if "vt_last_call" not in st.session_state:
    st.session_state["vt_last_call"] = 0.0

all_alert_ips = (
    list(alerts["ipsrc"].dropna().unique()) if not alerts.empty else []
)

vt_col1, vt_col2 = st.columns([3, 1])
with vt_col1:
    vt_ip = st.selectbox(
        "Select a flagged IP to check:",
        options=all_alert_ips if all_alert_ips else ["No alerts available"],
        key="vt_ip_select",
    )
with vt_col2:
    st.write("")
    st.write("")
    check_vt = st.button("Check on VirusTotal", key="vt_check_btn", type="primary")

if check_vt and vt_ip and vt_ip != "No alerts available":
    try:
        ip_obj = ipaddress.ip_address(vt_ip)
    except ValueError:
        st.error(f"'{vt_ip}' is not a valid IP address.")
        ip_obj = None

    if ip_obj is not None:
        if not ip_obj.is_global:
            st.warning(
                f"**{vt_ip}** is a private/local address. "
                "VirusTotal only indexes publicly routable IPs."
            )
        else:
            from enrichment.virustotal import VTDuckDBCache, check_virustotal_ip

            _vt_db_cache = VTDuckDBCache()
            cached = _vt_db_cache.get(vt_ip)

            if cached:
                vt_result = cached
            else:
                elapsed = time.time() - float(st.session_state["vt_last_call"])
                if st.session_state["vt_last_call"] > 0 and elapsed < 15:
                    wait = int(15 - elapsed)
                    st.warning(
                        f"Please wait **{wait} more second(s)** before the next VirusTotal request."
                    )
                    vt_result = None
                else:
                    with st.spinner(f"Querying VirusTotal for {vt_ip}…"):
                        vt_result = check_virustotal_ip(vt_ip)
                    st.session_state["vt_last_call"] = time.time()

            if vt_result is not None:
                status = vt_result.get("status", "")
                if status == "no_api_key":
                    st.info(
                        "VirusTotal API key not configured. "
                        "Add `VIRUSTOTAL_API_KEY` to your `.env` file."
                    )
                elif status == "rate_limited":
                    st.warning("VirusTotal rate limit exceeded (HTTP 429). Try again in a minute.")
                elif status in ("success", "not_found") or "malicious_count" in vt_result:
                    r1, r2, r3, r4 = st.columns(4)
                    r1.metric("🔴 Malicious",  vt_result.get("malicious_count",  0))
                    r2.metric("🟡 Suspicious", vt_result.get("suspicious_count", 0))
                    r3.metric("🟢 Harmless",   vt_result.get("harmless_count",   0))
                    r4.metric("⚪ Undetected", vt_result.get("undetected_count", 0))

                    info_a, info_b = st.columns(2)
                    with info_a:
                        st.write(f"**Reputation score:** {vt_result.get('reputation', 0)}")
                        if vt_result.get("as_owner"):
                            st.write(f"**AS Owner:** {vt_result['as_owner']}")
                        if vt_result.get("last_analysis_date"):
                            st.write(f"**Last analysis:** {vt_result['last_analysis_date']}")
                    with info_b:
                        if vt_result.get("from_cache"):
                            st.caption(
                                f"📦 Cached result from {vt_result.get('cached_at', 'unknown')}"
                            )
                        st.markdown(
                            f"[🔗 View on VirusTotal]"
                            f"(https://www.virustotal.com/gui/ip-address/{vt_ip})"
                        )

                    if vt_result.get("error"):
                        st.warning(vt_result["error"])
                else:
                    if vt_result.get("error"):
                        st.error(f"Error: {vt_result['error']}")

elif check_vt and vt_ip == "No alerts available":
    st.info("Run an analysis first to populate the alerts list.")

# ---------------------------------------------------------------------------
# Manual GeoIP / AbuseIPDB Lookup (unchanged from original)
# ---------------------------------------------------------------------------
st.divider()
st.subheader("🔍 Manual IP Intelligence Lookup")

from enrichment import check_ip_reputation, get_ip_location

inv_col1, inv_col2 = st.columns([3, 1])
with inv_col1:
    target_ip = st.text_input(
        "Enter any IP address to investigate:",
        value="",
        key="manual_ip_input",
    )
with inv_col2:
    st.write("")
    st.write("")
    run_check = st.button("Query Threat Intel", key="manual_check_btn")

if run_check and target_ip:
    st.write(f"### Results for `{target_ip}`")
    res_col1, res_col2 = st.columns(2)

    with res_col1:
        st.markdown("#### 🌐 Geolocation")
        geo_info = get_ip_location(target_ip)
        st.write(f"**Country:** {geo_info.get('country_name')} ({geo_info.get('country_code')})")
        st.write(f"**City:** {geo_info.get('city')}")
        st.write(f"**Coordinates:** {geo_info.get('latitude')}, {geo_info.get('longitude')}")
        st.caption(f"Provider: {geo_info.get('provider')}")

    with res_col2:
        st.markdown("#### 🚨 AbuseIPDB")
        abuse_info = check_ip_reputation(target_ip)
        score = abuse_info.get("abuse_score", 0)
        st.metric("Abuse Confidence Score", f"{score}%")
        st.write(f"**Total Reports:** {abuse_info.get('total_reports', 0)}")
        st.write(f"**ISP:** {abuse_info.get('isp', 'N/A')}")
        if abuse_info.get("error"):
            st.warning(abuse_info.get("error"))