import streamlit as st
import pandas as pd
import joblib
import json
import warnings

warnings.filterwarnings("ignore")

# ---------- Page Config ----------
st.set_page_config(
    page_title="Phishing Detection System",
    page_icon="🛡️",
    layout="centered"
)

# ---------- Load Model & Data ----------
@st.cache_resource
def load_artifacts():
    model = joblib.load("phishing_model.pkl")
    with open("model_columns.json") as f:
        columns = json.load(f)
    with open("safe_sample.json") as f:
        safe_sample = json.load(f)
    return model, columns, safe_sample

model, columns, safe_sample = load_artifacts()

# ---------- Feature Extraction ----------
def build_features(url: str) -> pd.DataFrame:
    sample = dict(safe_sample)  # start from a real "safe" baseline row

    sample['qty_dot_url'] = url.count('.')
    sample['qty_hyphen_url'] = url.count('-')
    sample['qty_underline_url'] = url.count('_')
    sample['qty_slash_url'] = url.count('/')
    sample['qty_at_url'] = url.count('@')
    sample['length_url'] = len(url)
    sample['domain_length'] = len(url.split('/')[2]) if len(url.split('/')) > 2 else 0
    sample['tls_ssl_certificate'] = 1 if url.startswith('https') else 0

    input_df = pd.DataFrame([sample])
    input_df = input_df[columns]  # ensure correct column order
    return input_df


def get_risk_level(score: int):
    if score <= 30:
        return "🟢 LOW RISK"
    elif score <= 60:
        return "🟡 MEDIUM RISK"
    else:
        return "🔴 HIGH RISK"


def get_reasons(sample: dict):
    reasons = []
    if sample.get('qty_hyphen_url', 0) > 2:
        reasons.append("⚠️ Too many hyphens in URL")
    if sample.get('tls_ssl_certificate', 0) == 0:
        reasons.append("⚠️ No SSL certificate (not https)")
    if sample.get('directory_length', 0) > 10:
        reasons.append("⚠️ Suspicious directory length")
    if sample.get('qty_dot_url', 0) > 4:
        reasons.append("⚠️ Too many dots in URL")
    if sample.get('length_url', 0) > 75:
        reasons.append("⚠️ URL is too long")
    if not reasons:
        reasons.append("✅ No suspicious patterns found")
    return reasons


# ---------- UI ----------
st.title("🛡️ Intelligent Phishing Detection System")
st.markdown(
    "Enter any URL to check if it is **Safe** or a **Phishing attempt**. "
    "Powered by Machine Learning (Random Forest) with **~97% accuracy**."
)

url = st.text_input("🔗 Enter URL", placeholder="e.g. https://www.google.com")

col1, col2 = st.columns([1, 3])
with col1:
    check = st.button("🔍 Analyze URL", type="primary")

if check:
    if not url.strip():
        st.warning("Pehle koi URL to daalo!")
    else:
        raw_features = dict(safe_sample)
        raw_features['qty_dot_url'] = url.count('.')
        raw_features['qty_hyphen_url'] = url.count('-')
        raw_features['qty_underline_url'] = url.count('_')
        raw_features['qty_slash_url'] = url.count('/')
        raw_features['qty_at_url'] = url.count('@')
        raw_features['length_url'] = len(url)
        raw_features['domain_length'] = len(url.split('/')[2]) if len(url.split('/')) > 2 else 0
        raw_features['tls_ssl_certificate'] = 1 if url.startswith('https') else 0

        input_df = build_features(url)
        pred = model.predict(input_df)[0]
        prob = model.predict_proba(input_df)[0]

        risk_score = int(prob[1] * 100)
        risk_level = get_risk_level(risk_score)
        reasons = get_reasons(raw_features)

        st.divider()

        if pred == 0:
            st.success(f"✅ SAFE URL — Confidence: {prob[0]*100:.2f}%")
        else:
            st.error(f"⚠️ PHISHING DETECTED! — Confidence: {prob[1]*100:.2f}%")

        st.metric("Risk Score", f"{risk_score}/100", risk_level)

        st.subheader("📋 Analysis Details")
        for r in reasons:
            st.write(r)

st.divider()
st.caption("Examples: https://www.google.com | https://sbi-secure-login-verify.xyz/account | http://free-iphone-winner.click/claim")
