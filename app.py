import streamlit as st
import pandas as pd
import sqlite3
import os
import folium
from streamlit_folium import st_folium
import requests
from datetime import datetime

# --- CUSTOM MODULES (Core Application Layer) ---
try:
    from core import hash_and_store
    from network_module import deep_packet_analysis
    from threat_intel import check_file_reputation
except ImportError:
    st.error("Check that core.py, network_module.py, and threat_intel.py are in your directory.")

# --- 1. DATABASE MIGRATION (Fixes 'no such column' error) ---
def init_db():
    conn = sqlite3.connect('forensic_toolkit.db')
    cursor = conn.cursor()
    # Ensure the base table exists
    cursor.execute('''CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT)''')
    
    # Check for missing columns and add them dynamically
    cursor.execute("PRAGMA table_info(audit_logs)")
    cols = [c[1] for c in cursor.fetchall()]
    for col_name in ['filename', 'hash', 'file_path']:
        if col_name not in cols:
            cursor.execute(f"ALTER TABLE audit_logs ADD COLUMN {col_name} TEXT")
    conn.commit()
    conn.close()

init_db()
# --- 2. GLOBAL UTILITIES ---
def get_ip_location(ip_str):
    try:
        clean_ip = str(ip_str).split(':')[0].strip()
        if clean_ip.startswith(("192.", "10.", "127.", "172.")): return None
        url = f"http://ip-api.com/json/{clean_ip}"
        res = requests.get(url, timeout=5).json()
        if res.get('status') == 'success':
            return {"lat": res['lat'], "lon": res['lon'], "city": res['city'], "country": res['country'], "isp": res.get('isp')}
    except: return None
    return None

# --- 3. UI CONFIG & PROFESSIONAL STYLING ---
st.set_page_config(page_title="Forensic Lab", layout="wide", page_icon="⚖️")

st.markdown("""
    <style>
    /* Dark Gemini-style sidebar */
    [data-testid="stSidebar"] {
        background-color: #111b21;
        color: white;
    }
    /* Fix text wrapping in columns */
    .stColumn > div {
        overflow-wrap: break-word;
    }
    /* Sleek Tab Headers */
    .stTabs [data-baseweb="tab"] {
        font-weight: 600;
        font-size: 16px;
    }
    /* Buttons */
    .stButton>button {
        width: 100%;
        border-radius: 8px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- 4. SIDEBAR: CASE HISTORY & NAVIGATION ---
if not os.path.exists("cases"): os.makedirs("cases")

with st.sidebar:
    st.title("🗂️ Case History")
    
    # New Case Creation
    with st.expander("➕ New Investigation", expanded=False):
        new_case = st.text_input("Name").strip().replace(" ", "_")
        if st.button("Initialize"):
            if new_case:
                os.makedirs(os.path.join("cases", new_case), exist_ok=True)
                st.session_state.active_case = new_case
                st.rerun()

    st.markdown("---")
    
    # List all cases
    all_cases = [d for d in os.listdir("cases") if os.path.isdir(os.path.join("cases", d))]
    all_cases.sort(key=lambda x: os.path.getctime(os.path.join("cases", x)), reverse=True)
    
    if all_cases:
        selected_case = st.radio("Select Case", all_cases, label_visibility="collapsed")
        st.session_state.active_case = selected_case
    else:
        st.info("Create a case to start.")
        st.stop()

active_case = st.session_state.active_case
case_path = os.path.join("cases", active_case)

# --- 5. MAIN WORKSPACE ---
st.title(f"⚖️ Investigation: {active_case}")
st.caption(f"Case Directory: `{case_path}`")

tab1, tab2, tab3 = st.tabs(["📜 Chain of Custody & Ingestion", "🌐 Network Triage", "🔍 Threat Intel"])

# --- TAB 1: INGESTION & AUDIT LOGS ---
with tab1:
    col_ingest, col_logs = st.columns([2, 3], gap="large")
    
    with col_ingest:
        st.header("📥 Ingest Evidence")
        uploaded_file = st.file_uploader("Upload PCAP, EML, or TXT", type=['pcap', 'eml', 'txt'])
        
        if st.button("🛡️ Secure & Ingest Artifact"):
            if uploaded_file:
                target_path = os.path.join(case_path, uploaded_file.name)
                with open(target_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                
                # Logic: Hash, Log to DB, Tag to Case
                hash_and_store(target_path)
                st.success(f"Locked & Hashed: {uploaded_file.name}")
                st.rerun()

    with col_logs:
        st.header("📜 Immutable Audit Trail")
        try:
            conn = sqlite3.connect('forensic_toolkit.db')
            # Filter logs specific to this case directory
            query = "SELECT timestamp, filename, hash, file_path FROM audit_logs WHERE file_path LIKE ? ORDER BY timestamp DESC"
            logs_df = pd.read_sql_query(query, conn, params=(f'%{active_case}%',))
            
            if not logs_df.empty:
                st.dataframe(logs_df, use_container_width=True, hide_index=True)
                csv = logs_df.to_csv(index=False).encode('utf-8')
                st.download_button("📥 Export Case CSV", csv, f"{active_case}_Audit.csv")
            else:
                st.info("No evidence logs for this case yet.")
            conn.close()
        except Exception as e:
            st.error(f"DB Error: {e}")

# --- TAB 2: NETWORK TRIAGE & MAPPING ---
with tab2:
    st.header("🌐 Geographical Evidence Triage")
    
    # 1. Scan for both PCAP and EML files in the active case directory
    evidence_files = [f for f in os.listdir(case_path) if f.endswith(('.pcap', '.eml'))]
    
    if evidence_files:
        # Layout Definition: Left control pane (1.5), Right analysis viewport (3)
        col_ctrl, col_display = st.columns([1.5, 3], gap="large")
        
        with col_ctrl:
            selected_file = st.selectbox("Select Evidence File", evidence_files)
            full_path = os.path.join(case_path, selected_file)
            
            # Detect file type to toggle specialized tools
            is_pcap = selected_file.lower().endswith('.pcap')
            is_eml = selected_file.lower().endswith('.eml')

            st.markdown("---")
            if is_pcap:
                st.info("📊 **Network Mode Active**")
                if st.button("🌍 Generate Attack Map", use_container_width=True): 
                    st.session_state.map_trigger = True
                if st.button("📊 Show Packet Breakdown", use_container_width=True): 
                    st.session_state.show_packets = True
            elif is_eml:
                st.info("✉️ **Email Mode Active**")
                if st.button("🌍 Map Email Route", use_container_width=True): 
                    st.session_state.map_trigger = True
                if st.button("📜 Extract Header Metadata", use_container_width=True): 
                    st.session_state.show_eml = True

            st.markdown("---")
            if st.button("❌ Reset Viewport", use_container_width=True):
                st.session_state.map_trigger = False
                st.session_state.show_packets = False
                st.session_state.show_eml = False
                st.rerun()

        with col_display:
            # --- FEATURE 1: PCAP PACKET ANALYSIS ---
            if is_pcap and st.session_state.get('show_packets', False):
                with st.spinner("Parsing packet headers..."):
                    data = deep_packet_analysis(full_path, 1)
                    if data:
                        df_display = pd.DataFrame(data) if isinstance(data, list) else pd.DataFrame([data])
                        st.dataframe(df_display.head(20), use_container_width=True)
                    else:
                        st.warning("No readable packets found in this capture file.")

            # --- FEATURE 2: EML METADATA ANALYSIS ---
            if is_eml and st.session_state.get('show_eml', False):
                with st.spinner("Extracting email envelope structures..."):
                    try:
                        from email_module import parse_email_evidence
                        eml_data = parse_email_evidence(full_path)
                        if eml_data:
                            st.json(eml_data)
                        else:
                            st.warning("EML file structure appears corrupted or unreadable.")
                    except ImportError:
                        st.error("Missing critical backend dependency: 'email_module.py' not found.")


            # --- FEATURE 3: UNIFIED GEOLOCATION MAPPING ---
# --- MAP GENERATION BLOCK ---
            if st.session_state.get('map_trigger', False):
                with st.spinner("Resolving coordinate assets..."):
                    m = folium.Map(location=[20, 0], zoom_start=2)
                    target_ips = []
                    
                    if is_pcap:
                        connections = deep_packet_analysis(full_path, 1)
                        if connections:
                            # Forensic Choice: Map the attackers (src) or the victims (dst)
                            map_mode = st.radio("Map Perspective", ["Map Attacker Origins (Source IPs)", "Map Target Assets (Destination IPs)"], horizontal=True)
                            
                            if "Source" in map_mode:
                                # Track where the attack is coming FROM
                                target_ips = list(set([c.get('src') for c in connections if 'src' in c]))
                            else:
                                # Track who the attack is hitting
                                target_ips = list(set([c.get('dst') for c in connections if 'dst' in c]))
                    elif is_eml:
                        from email_module import parse_email_evidence
                        eml_data = parse_email_evidence(full_path)
                        if eml_data:
                            target_ips = eml_data.get("Internal_IPs", [])

                    marker_count = 0
                    for ip in target_ips:
                        loc = get_ip_location(ip)
                        if loc:
                            icon_style = 'crosshairs' if is_pcap else 'envelope'
                            color_style = 'red' if "Source" in locals().get('map_mode', '') else 'blue'
                            folium.Marker(
                                [loc['lat'], loc['lon']], 
                                popup=f"IP: {ip}", 
                                icon=folium.Icon(color=color_style, icon=icon_style)
                            ).add_to(m)
                            marker_count += 1
                    
                    if marker_count > 0:
                        st_folium(m, height=500, width=850, key=f"map_{selected_file}")
                    else:
                        st.warning("No external public internet routing paths resolved for selection.")
# --- TAB 3: THREAT INTELLIGENCE ---
with tab3:
    st.header("🔍 VirusTotal Intelligence")
    hash_input = st.text_input("Enter SHA-256 Hash")
    if st.button("Query Global Reputation"):
        if hash_input:
            # Pass the active_case name directly
            success = check_file_reputation(active_case, hash_input)
            if success:
                st.success("Result captured! View it in 'Chain of Custody' (Tab 1).")
                st.balloons() # Visual confirmation it hit the DB
            else:
                st.error("Database write failed. Check terminal for errors.")
# --- FOOTER ---
st.markdown("---")
st.caption(f"Batch-14 Forensic Toolkit | Industrial Oriented Mini Project | Active Case: {active_case}")
