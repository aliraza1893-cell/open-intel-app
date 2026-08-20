import streamlit as st
import re
import socket

st.set_page_config(page_title="Exposed Secrets & Threat Intel", page_icon="🛡️", layout="wide")

st.title("🛡️ Exposed Secrets & Threat Intel Scanner")

tab1, tab2 = st.tabs(["🔑 Cloud Secrets Finder", "📡 Threat Infrastructure Intel"])

with tab1:
    st.header("Search Text for Exposed Secrets")
    
    # Sample data for testing without copy-pasting
    sample_env = """# Production Server Environment Variables
PORT=8080
DB_HOST=192.168.1.50
DB_USER=root
DB_PASS=SuperSecretPassword123!

# Cloud Services Setup
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Telegram Bot Config
TELEGRAM_BOT_TOKEN=123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ"""

    if st.button("📋 Load Sample Config (.env Data)"):
        st.session_state['input_text'] = sample_env

    input_data = st.text_area(
        "Paste Code, Logs, or Config Text here:", 
        value=st.session_state.get('input_text', ''),
        height=200
    )
    
    if st.button("Scan Secrets"):
        if input_data:
            # Regex Patterns
            aws_keys = re.findall(r'AKIA[0-9A-Z]{16}', input_data)
            telegram_tokens = re.findall(r'\d{9,10}:[A-Za-z0-9_-]{35}', input_data)
            
            found = False
            if aws_keys:
                st.error(f"⚠️ **AWS Access Key Detected:** `{aws_keys}`")
                found = True
            if telegram_tokens:
                st.warning(f"⚠️ **Telegram Bot Token Detected:** `{telegram_tokens}`")
                found = True
                
            if not found:
                st.success("✅ No sensitive secrets detected in the text!")
        else:
            st.info("Please paste text or click 'Load Sample Config'.")

with tab2:
    st.header("Analyze IP / Domain Infrastructure")
    target_ip = st.text_input("Enter Target IP Address:", "8.8.8.8")
    
    if st.button("Check Threat Intel"):
        if target_ip:
            try:
                hostname = socket.gethostbyaddr(target_ip)[0]
                st.info(f"🌐 **Reverse DNS / Hostname:** `{hostname}`")
            except Exception as e:
                st.warning(f"Could not resolve Hostname for {target_ip}")
