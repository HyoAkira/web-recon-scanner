import streamlit as st
import subprocess
import json
import os
import shlex

# Page configuration
st.set_page_config(page_title="Threat Surface Scanner", page_icon="🔍", layout="wide")

# Light pastel theme CSS
st.markdown("""
<style>
    /* Main background */
    .stApp {
        background-color: #fcfcfc;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #f5f6f8;
        border-right: 1px solid #e0e4e8;
    }

    /* Headings */
    h1, h2, h3, h4, h5, h6 {
        color: #4a5568 !important;
    }
    
    /* Text colour */
    .stMarkdown, .stText, p {
        color: #4a5568 !important;
    }

    /* Input fields */
    .stTextInput > div > div > input,
    .stNumberInput > div > div > input {
        background-color: #ffffff;
        border: 1px solid #cbd5e0;
        border-radius: 8px;
        color: #4a5568;
    }

    /* Metric cards, tabs and expanders */
    [data-testid="stMetric"], [data-testid="stExpander"], .stTabs {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    
    [data-testid="stExpander"] {
        padding: 0;
    }
    
    .stCodeBlock {
        border-radius: 8px;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)


st.title("🔍 Search-Engine-Style Threat Surface Scan")
st.markdown("Enter a target domain or IP address, choose the scan options, then review the results.")

# Search-engine style main input
col_search, col_btn = st.columns([4, 1])
with col_search:
    target_url = st.text_input("Target IP or site URL", placeholder="e.g. example.com", label_visibility="collapsed")
with col_btn:
    run_button = st.button("Start Scan 🚀", use_container_width=True)

# Sidebar: settings and arguments
with st.sidebar:
    st.header("⚙️ Scan Settings")
    
    st.subheader("Output Arguments")
    report_file = st.text_input("Report file (--report)", value="report.txt")
    json_file = st.text_input("JSON file (--json)", value="report.json")
    
    st.subheader("Active Scan Settings")
    active_scan = st.checkbox("Active scan (--active)", value=True)
    ports = st.text_input("Ports (--ports)", value="80,443,8080")
    full_ports = st.checkbox("Scan all ports (--full-ports)", value=False)
    no_nmap = st.checkbox("Disable nmap (--no-nmap)", value=False)
    
    st.subheader("JavaScript and File Scanning")
    js_any_domain = st.checkbox("Allow JS from any domain (--js-any-domain)", value=True)
    max_js = st.number_input("Max JS files (--max-js)", min_value=1, value=5)
    max_wayback = st.number_input("Max Wayback URLs (--max-wayback)", min_value=10, value=200)

if run_button:
    if not target_url:
        st.warning("Please enter a target URL or IP.")
    else:
        st.info(f"Starting scan against {target_url}. This may take a while...")
        
        # Build the argument list
        cmd = ["python", "main.py", target_url]
        
        if report_file:
            cmd.extend(["--report", report_file])
        if json_file:
            cmd.extend(["--json", json_file])
        
        if active_scan:
            cmd.append("--active")
            if ports:
                cmd.extend(["--ports", ports])
            if full_ports:
                cmd.append("--full-ports")
            if no_nmap:
                cmd.append("--no-nmap")
                
        if js_any_domain:
            cmd.append("--js-any-domain")
            
        cmd.extend(["--max-js", str(max_js)])
        cmd.extend(["--max-wayback", str(max_wayback)])

        # Show the command that will be run
        cmd_str = " ".join(shlex.quote(c) for c in cmd)
        st.markdown("**Command run:**")
        st.code(cmd_str, language="bash")
        
        # Run the scan
        with st.spinner("Scan running, please wait... (this can take a few minutes)"):
            try:
                # Run from the script's own directory so relative paths resolve
                project_dir = os.path.dirname(os.path.abspath(__file__))
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=project_dir)
                
                if result.returncode != 0:
                    st.error("The scan failed or a required command is missing.")
                    with st.expander("Error details"):
                        st.code(result.stderr)
                else:
                    st.success("Scan completed successfully.")
                    
                    json_path = os.path.join(project_dir, json_file)
                    
                    # Read the results back from the JSON output
                    if os.path.exists(json_path):
                        with open(json_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            
                        # Render the JSON data
                        st.header("📊 Scan Results")
                        
                        st.subheader("Overview")
                        col1, col2, col3, col4 = st.columns(4)
                        col1.metric("Target domain", data.get("domain", target_url))
                        col2.metric("Open ports", len(data.get("active_scan", {}).get("open", [])))
                        col3.metric("Endpoints", len(data.get("endpoints", [])))
                        col4.metric("Subdomains", len(data.get("subdomains", [])))
                        
                        tabs = st.tabs([
                            "Basic Network", "HTTP & Security", "Vulnerabilities & Risks", 
                            "Discovery (Endpoints etc.)", "Tools & Notes", "Raw JSON"
                        ])
                        
                        with tabs[0]:
                            st.markdown("### 🌐 DNS Records")
                            st.json(data.get("dns", {}))
                            st.markdown("### 🔌 Active Scan (Open Ports)")
                            st.json(data.get("active_scan", {}))
                            st.markdown("### ℹ️ WHOIS")
                            st.text((data.get("whois") or {}).get("stdout", "No record found."))
                            
                        with tabs[1]:
                            col_h1, col_h2 = st.columns(2)
                            with col_h1:
                                st.markdown("### 📋 HTTP Headers")
                                st.json(data.get("http_headers", {}))
                            with col_h2:
                                st.markdown("### 🛡️ Security Headers")
                                st.json(data.get("security_headers", {}))
                                
                            st.markdown("### 🔀 CORS Policy")
                            st.json(data.get("cors", {}))
                            st.markdown("### 🔒 TLS/SSL Info")
                            st.json(data.get("tls", {}))
                            st.markdown("### ⚙️ Technology Fingerprint")
                            st.json(data.get("tech_fingerprint", {}))
                            
                        with tabs[2]:
                            st.markdown("### ⚠️ Risk Summary")
                            st.json(data.get("risk_summary", {}))
                            st.markdown("### 🐛 Possible CVE Matches")
                            cves = data.get("cve_matches", [])
                            if cves:
                                st.table(cves)
                            else:
                                st.info("No CVE matches found.")
                            
                        with tabs[3]:
                            st.markdown("### 📍 Discovered Endpoints")
                            st.write(data.get("endpoints", []))
                            st.markdown("### 🏢 Subdomains")
                            st.write(data.get("subdomains", []))
                            st.markdown("### 🔗 Third-Party Domains")
                            st.write(data.get("third_party", []))
                            st.markdown("### 🕰️ Wayback URLs")
                            wayback = data.get("wayback_urls", [])
                            with st.expander(f"Show {len(wayback)} Wayback URLs"):
                                st.write(wayback)
                            
                        with tabs[4]:
                            st.markdown("### 🧰 External Tool Output")
                            st.json(data.get("external_tools", {}))
                            st.markdown("### 📝 Notes")
                            notes = data.get("notes", [])
                            if notes:
                                for note in notes:
                                    st.warning(note)
                            else:
                                st.info("No notes.")
                            
                            st.markdown("### 🤖 robots.txt & sitemap.xml")
                            with st.expander("robots.txt content"):
                                st.text(data.get("robots") or "robots.txt not found.")
                            with st.expander("sitemap.xml content"):
                                st.text(data.get("sitemap") or "sitemap.xml not found.")
                                
                        with tabs[5]:
                            st.markdown("### 📄 Full report.json content")
                            st.json(data)
                            
                    else:
                        st.warning(f"The JSON output file ({json_path}) was not found. Check that the scan completed successfully.")
            except Exception as e:
                st.error(f"An error occurred: {e}")
