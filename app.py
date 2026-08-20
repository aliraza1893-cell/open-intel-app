import streamlit as st
import requests
import socket
import urllib.parse

st.set_page_config(page_title="Exposed Secrets & Threat Intel Scanner", layout="wide")

st.title("🛡️ Exposed Secrets & Threat Intel Scanner")

tab1, tab2 = st.tabs(["🔑 Cloud Secrets Finder", "📡 Threat Infrastructure Intel"])

# ==========================================
# TAB 1: Cloud Secrets Finder (New Feature)
# ==========================================
with tab1:
    st.header("Exposed Cloud Secrets & API Keys")
    secret_input = st.text_area("Paste Code / Logs / File Content to Scan for Secrets:", height=150)
    
    if st.button("Scan for Secrets"):
        if secret_input:
            st.info("Scanning for exposed API keys, credentials, and cloud secrets...")
            # Secret patterns check
            found_secrets = []
            patterns = {
                "AWS Access Key": r"AKIA[0-9A-Z]{16}",
                "Generic API Key": r"api[_-]?key[^\w\n]*['\"]?([0-9a-zA-Za-z_-]{16,})",
                "Environment Secret": r"SECRET[^\w\n]*['\"]?([0-9a-zA-Za-z_-]{16,})"
            }
            import re
            for secret_type, pattern in patterns.items():
                if re.search(pattern, secret_input, re.IGNORECASE):
                    found_secrets.append(secret_type)
            
            if found_secrets:
                for sec in found_secrets:
                    st.error(f"⚠️ Potential Secret Detected: {sec}")
            else:
                st.success("✅ No obvious secrets detected in the provided text.")
        else:
            st.warning("Please paste text to scan.")

# ==========================================
# TAB 2: Threat Infrastructure Intel (Restored Old Feature)
# ==========================================
with tab2:
    st.header("Analyze Domain / Infrastructure")
    
    target_raw = st.text_input("Enter Target Domain or URL:", placeholder="https://greensquad.pk/")
    
    if st.button("Run Intelligence Check"):
        if target_raw:
            # Clean URL to Domain
            clean_domain = target_raw.strip()
            if clean_domain.startswith(("http://", "https://")):
                clean_domain = urllib.parse.urlparse(clean_domain).netloc
            clean_domain = clean_domain.split('/')[0]
            
            st.info(f"🔍 Resolving Infrastructure for: {clean_domain}")
            
            try:
                # Resolve Domain to Target IP
                target_ip = socket.gethostbyname(clean_domain)
                st.success(f"📌 Target IP Address: {target_ip}")
                
                # Fetch GeoIP and ISP Info from ip-api
                api_url = f"http://ip-api.com/json/{target_ip}"
                geo_data = requests.get(api_url).json()
                
                if geo_data.get("status") == "success":
                    st.write("### Server Country")
                    st.title(geo_data.get("country", "N/A"))
                    
                    st.write("### Server City")
                    st.title(geo_data.get("city", "N/A"))
                    
                    st.write("### Hosting / ISP")
                    st.title(geo_data.get("isp", "N/A"))
                else:
                    st.error("Could not fetch IP Intelligence details.")
                    
            except Exception:
                st.error(f"Could not resolve Hostname for {target_raw}")
        else:
            st.warning("Please enter a Target Domain or URL.")
