import duckdb
import streamlit as st

DB_PATH = "test.duckdb"

st.set_page_config(page_title="Network IDS", page_icon="🛡️", layout="wide")


@st.cache_data(ttl=10)
def run_query(sql):
    # read_only so the dashboard never locks oclear
    #r modifies your data
    con = duckdb.connect(DB_PATH, read_only=True)
    df = con.execute(sql).df()
    con.close()
    return df


st.title("🛡️ Network Intrusion Detection Dashboard")

total_packets = run_query("SELECT COUNT(*) AS n FROM connections")["n"].iloc[0]
alerts = run_query("SELECT * FROM alerts")

# ---- Top-line numbers ----
c1, c2, c3 = st.columns(3)
c1.metric("Packets analyzed", f"{total_packets:,}")
c2.metric("Alerts raised", len(alerts))
c3.metric("Unique attacker IPs", alerts["ipsrc"].nunique())

if alerts.empty:
    st.info("No alerts found. Run alerts.py first, or the traffic is clean.")
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