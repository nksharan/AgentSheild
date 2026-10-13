import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import streamlit as st

from fraud_agent.agent import assess

EXAMPLES = {
    "Bank KYC SMS": "SMS from +91 98XXXXXX21: Dear Customer, your SBI account will be blocked today. Update KYC: http://sbi-kyc-update.in.net",
    "Fake delivery email": "Email from support@parcel-track-help.com: Your package is delayed. Pay a small redelivery fee immediately to release it: https://bit.ly/track-now",
    "Job scam": "WhatsApp message: Earn $400 a day by completing tasks. Pay $150 upfront and we will show you how. Reply now and don't tell anyone.",
    "Genuine message": "Hello, your order is confirmed and will arrive tomorrow. No payment or verification is needed.",
}

st.set_page_config(page_title="AgentShield", page_icon="🛡️", layout="wide")

st.title("🛡️ AgentShield")
st.caption("AI scam detector for SMS, email, chats, and suspicious links.")

with st.sidebar:
    st.header("Controls")
    st.write("Paste a message or choose a sample below.")
    selected_example = st.selectbox("Example messages", ["Custom", *list(EXAMPLES.keys())])
    st.info("The detector checks urgency, payment requests, OTP asks, URL risk, and impersonation patterns.")

text_value = EXAMPLES[selected_example] if selected_example != "Custom" else ""
message = st.text_area("Message to analyze", value=text_value, height=220, placeholder="Paste SMS, email, chat, or social message here...")

if st.button("Analyze message", use_container_width=True):
    if not message.strip():
        st.warning("Please enter a message first.")
    else:
        with st.spinner("Analyzing for scam indicators..."):
            try:
                result = assess(message)
            except Exception as exc:
                st.error(f"Analysis failed: {exc}")
            else:
                col1, col2, col3 = st.columns(3)
                col1.metric("Verdict", result.verdict)
                col2.metric("Risk score", f"{result.risk_score}/100")
                col3.metric("Scam type", result.scam_type)

                st.subheader("Key findings")
                if result.red_flags:
                    for flag in result.red_flags:
                        st.markdown(f"- {flag}")
                else:
                    st.write("No strong scam indicators were detected.")

                st.subheader("Recommended action")
                st.write(result.recommended_action)

                with st.expander("Detailed assessment"):
                    st.json(result.model_dump())
