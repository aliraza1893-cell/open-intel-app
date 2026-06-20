import streamlit as st
import socket
import requests
from urllib.parse import urlparse

# Web Page Styling Configuration
st.set_page_config(page_title="Network Intelligence Tool", page_icon="🛡️", layout="centered")

st.title("🛡️ Open Source Network Intelligence Tool")
st.markdown("Analyze target domains instantly to check hosting infrastructure and security layers.")

st.subheader("🌐 Scan Domain / Infrastructure")
domain_input = st.text_input("Enter Target Domain or URL:", placeholder="example.com")

if st.button("Run Intelligence Check"):
    if domain_input:
        # Clean the input to get just the domain
        clean_domain = urlparse(domain_input).netloc if "://" in domain_input else domain_input
        st.info(f"🔍 Resolving Infrastructure for: **{clean_domain}**")
        
        try:
            # Get IP Address
            ip_address = socket.gethostbyname(clean_domain)
            st.success(f"📌 Target IP Address: `{ip_address}`")
            
            # Fetch GeoIP and ISP Data
            res = requests.get(f"http://ip-api.com/json/{ip_address}").json()
            if res["status"] == "success":
                col1, col2 = st.columns(2)
                with col1:
                    st.metric(label="Server Country", value=res.get('country', 'Unknown'))
                    st.metric(label="Server City", value=res.get('city', 'Unknown'))
                with col2:
                    st.metric(label="Hosting / ISP", value=res.get('isp', 'Unknown'))
                
                # Check for Cloudflare Proxy
                if "cloudflare" in res.get('isp', '').lower():
                    st.error("⚠️ [NOTICE] Target identity is masked behind the Cloudflare network layer.")
            else:
                st.error("[-] Identity resolution failed for this IP.")
        except:
            st.error("[-] Could not resolve domain. The server might be down or invalid.")
    else:
        st.warning("Please enter a domain name first.")
