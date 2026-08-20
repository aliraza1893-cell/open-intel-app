import streamlit as st, re, requests, socket

st.set_page_config(page_title="Exposed Secrets & Threat Intel", page_icon="🛡️", layout="wide")
st.title("🛡️ Exposed Secrets & Threat Intel Scanner")

tab1, tab2 = st.tabs(["🔑 Cloud Secrets Finder", "📡 Threat Infrastructure Intel"])

with tab1:
    st.header("Search Text for Exposed Secrets")
    text_input = st.text_area("Paste Code, Logs, or Config Text here:")
    if st.button("Scan Secrets"):
        patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Generic API Key": r"[a-zA-Z0-9_-]{32,45}",
            "Environment DB URL": r"postgres://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_]+"
        }
        found = False
        for secret_type, pattern in patterns.items():
            matches = re.findall(pattern, text_input)
            if matches:
                found = True
                st.error(f"⚠️ {secret_type} Detected: {matches}")
        if not found:
            st.success("✅ No secrets detected in the provided text.")

with tab2:
    st.header("Analyze IP / Infrastructure")
    ip_input = st.text_input("Enter IP Address (e.g. 8.8.8.8):")
    if st.button("Check Threat Intel"):
        if ip_input:
            try:
                host = socket.gethostbyaddr(ip_input)[0]
                st.info(f"🌐 Hostname: {host}")
            except:
                st.warning("Could not resolve Reverse DNS.")
            res = requests.get(f"https://ipapi.co/{ip_input}/json/").json()
            if "country_name" in res:
                st.write(f"📍 **Country:** {res.get('country_name')} | **ASN:** {res.get('asn')} | **Org:** {res.get('org')}")
            else:
                st.error("Failed to fetch IP details.")
