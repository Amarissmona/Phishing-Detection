import streamlit as st
import pandas as pd
import joblib
import json
import re
from urllib.parse import urlparse
import warnings

warnings.filterwarnings("ignore")

# ---------- Page Config ----------
st.set_page_config(
    page_title="Phishing Detection System",
    page_icon="🛡️",
    layout="centered"
)

# ---------- Load Model ----------
@st.cache_resource
def load_artifacts():
    model = joblib.load("phishing_model.pkl")
    with open("model_columns.json") as f:
        columns = json.load(f)
    return model, columns

model, columns = load_artifacts()

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rebrand.ly", "shorte.st", "bl.ink", "tiny.cc"
}

SYMBOLS = {
    "dot": ".", "hyphen": "-", "underline": "_", "slash": "/",
    "questionmark": "?", "equal": "=", "at": "@", "and": "&",
    "exclamation": "!", "space": " ", "tilde": "~", "comma": ",",
    "plus": "+", "asterisk": "*", "hashtag": "#", "dollar": "$",
    "percent": "%",
}

KNOWN_TLDS = ["com", "net", "org", "info", "biz", "xyz", "click", "top",
              "gq", "tk", "ml", "ga", "cf", "in", "co", "io", "site",
              "online", "shop", "app", "live", "icu", "buzz"]


def count_symbols(text: str, prefix: str) -> dict:
    text = text or ""
    return {f"qty_{name}_{prefix}": text.count(char) for name, char in SYMBOLS.items()}


def is_ip(host: str) -> bool:
    if not host:
        return False
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))


def count_tlds(text: str) -> int:
    text = text.lower()
    return sum(text.count("." + t) for t in KNOWN_TLDS)


def build_features(url: str):
    """Extracts the ~99 lexical (URL-string based) features the model was trained on.
    Uses -1 as a sentinel where a URL component (directory/file/params) is absent,
    matching the encoding used in the original training dataset."""
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.split("@")[-1].split(":")[0]
    path = parsed.path or ""

    stripped_path = path.strip("/")
    if "/" in stripped_path:
        directory = "/" + stripped_path.rsplit("/", 1)[0]
    else:
        directory = ""
    file_part = stripped_path.rsplit("/", 1)[-1] if stripped_path else ""
    params = parsed.query or ""

    features = {}
    features.update(count_symbols(url, "url"))
    features["qty_tld_url"] = count_tlds(url)
    features["length_url"] = len(url)

    features.update(count_symbols(domain, "domain"))
    features["qty_vowels_domain"] = sum(domain.lower().count(v) for v in "aeiou")
    features["domain_length"] = len(domain)
    features["domain_in_ip"] = 1 if is_ip(domain) else 0
    features["server_client_domain"] = 1 if ("server" in domain.lower() or "client" in domain.lower()) else 0

    if directory:
        features.update(count_symbols(directory, "directory"))
        features["directory_length"] = len(directory)
    else:
        features.update({f"qty_{n}_directory": -1 for n in SYMBOLS})
        features["directory_length"] = -1

    if file_part:
        features.update(count_symbols(file_part, "file"))
        features["file_length"] = len(file_part)
    else:
        features.update({f"qty_{n}_file": -1 for n in SYMBOLS})
        features["file_length"] = -1

    if params:
        features.update(count_symbols(params, "params"))
        features["params_length"] = len(params)
        features["tld_present_params"] = 1 if re.search(r"\.(com|net|org|xyz|info)", params.lower()) else 0
        features["qty_params"] = len(params.split("&"))
    else:
        features.update({f"qty_{n}_params": -1 for n in SYMBOLS})
        features["params_length"] = -1
        features["tld_present_params"] = -1
        features["qty_params"] = -1

    features["email_in_url"] = 1 if re.search(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", url, re.IGNORECASE) else 0
    features["url_shortened"] = 1 if domain.lower() in SHORTENERS else 0
    features["tls_ssl_certificate"] = 1 if url.lower().startswith("https") else 0

    return features, url, domain


def get_risk_level(score: int):
    if score <= 30:
        return "🟢 LOW RISK"
    elif score <= 60:
        return "🟡 MEDIUM RISK"
    else:
        return "🔴 HIGH RISK"


def get_reasons(feat: dict, domain: str):
    reasons = []
    if feat.get("qty_hyphen_domain", 0) >= 2:
        reasons.append("⚠️ Multiple hyphens in domain name")
    if feat.get("tls_ssl_certificate", 0) == 0:
        reasons.append("⚠️ No HTTPS / SSL not used")
    if feat.get("domain_in_ip", 0) == 1:
        reasons.append("⚠️ Domain is a raw IP address")
    if feat.get("qty_at_url", 0) > 0:
        reasons.append("⚠️ '@' symbol found in URL (redirect trick)")
    if feat.get("url_shortened", 0) == 1:
        reasons.append("⚠️ URL uses a known shortening service")
    if feat.get("length_url", 0) > 75:
        reasons.append("⚠️ URL is unusually long")
    if feat.get("qty_dot_url", 0) > 4:
        reasons.append("⚠️ Excessive number of dots in URL")
    if feat.get("directory_length", -1) > 50:
        reasons.append("⚠️ Very long/complex directory path")
    if not reasons:
        reasons.append("✅ No suspicious patterns found")
    return reasons


# ---------- UI ----------
st.title("🛡️ Intelligent Phishing Detection System")
st.markdown(
    "Enter any URL to check if it is **Safe** or a **Phishing attempt**. "
    "Powered by Machine Learning (Random Forest, ~93% accuracy) analyzing URL structure."
)

url_input = st.text_input("🔗 Enter URL", placeholder="e.g. https://www.google.com")

col1, col2 = st.columns([1, 3])
with col1:
    check = st.button("🔍 Analyze URL", type="primary")

if check:
    if not url_input.strip():
        st.warning("Pehle koi URL to daalo!")
    else:
        feat, full_url, domain = build_features(url_input)
        row = {c: feat.get(c, 0) for c in columns}
        input_df = pd.DataFrame([row])[columns]

        pred = model.predict(input_df)[0]
        prob = model.predict_proba(input_df)[0]

        risk_score = int(prob[1] * 100)
        risk_level = get_risk_level(risk_score)
        reasons = get_reasons(feat, domain)

        st.divider()

        if pred == 0:
            st.success(f"✅ SAFE URL — Confidence: {prob[0]*100:.2f}%")
        else:
            st.error(f"⚠️ PHISHING DETECTED! — Confidence: {prob[1]*100:.2f}%")

        st.metric("Risk Score", f"{risk_score}/100", risk_level)

        st.subheader("📋 Analysis Details")
        for r in reasons:
            st.write(r)

        with st.expander("🔬 Technical details"):
            st.json({
                "url_analyzed": full_url,
                "domain": domain,
                "length_url": feat["length_url"],
                "domain_length": feat["domain_length"],
                "tls_ssl_certificate": feat["tls_ssl_certificate"],
                "domain_in_ip": feat["domain_in_ip"],
                "url_shortened": feat["url_shortened"],
                "qty_dot_url": feat["qty_dot_url"],
                "qty_hyphen_domain": feat["qty_hyphen_domain"],
            })

st.divider()
st.caption("Examples: https://www.google.com | https://sbi-secure-login-verify.xyz/account | http://192.168.1.1/login | http://free-iphone-winner.click/claim")
