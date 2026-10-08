import joblib
import pandas as pd
import streamlit as st

from features import extract_features
from live_checks import run_live_checks

st.set_page_config(page_title="Phishing URL Detector", page_icon="🛡️", layout="centered")


# ---------- Load model ----------
@st.cache_resource
def load_bundle():
    return joblib.load("phishing_model.pkl")


bundle = load_bundle()
model, FEATURES = bundle["model"], bundle["features"]

# Risk cut-offs (you can tune these)
DANGEROUS_AT = 0.7
SUSPICIOUS_AT = 0.4
LEVELS = ["Safe", "Suspicious", "Dangerous"]


# ---------- Helper functions ----------
def predict(url: str):
    """Returns (phishing probability, extracted features) for one URL."""
    feats = extract_features(url)
    row = pd.DataFrame([feats])[FEATURES]
    prob = float(model.predict_proba(row)[0, 1])
    return prob, feats


def risk_level(prob: float) -> str:
    if prob >= DANGEROUS_AT:
        return "Dangerous"
    if prob >= SUSPICIOUS_AT:
        return "Suspicious"
    return "Safe"


def raise_to(level: str, minimum: str) -> str:
    """Returns the higher of two risk levels."""
    return LEVELS[max(LEVELS.index(level), LEVELS.index(minimum))]


def get_red_flags(url: str, feats: dict) -> list:
    """Turns raw URL features into plain-English warnings."""
    flags = []
    if url.strip().lower().startswith("http://"):
        flags.append("The link does not use HTTPS, so the connection is not encrypted.")
    if feats["length_url"] > 75:
        flags.append("The URL is unusually long, which is often used to hide the real destination.")
    if feats["qty_at_url"] > 0:
        flags.append("The URL contains an '@' symbol, which can be used to disguise the real site.")
    if feats["domain_in_ip"] == 1:
        flags.append("The link uses an IP address instead of a normal domain name.")
    if feats["qty_hyphen_domain"] >= 2:
        flags.append("The domain name has many hyphens, a common trick in fake websites.")
    if feats["qty_dot_domain"] >= 4:
        flags.append("The domain has many sub-domains, which can imitate a trusted brand.")
    if feats["url_shortened"] == 1:
        flags.append("This is a shortened link, so the real destination is hidden.")
    if feats["email_in_url"] == 1:
        flags.append("An email address is embedded in the URL.")
    if feats["qty_params"] >= 4:
        flags.append("The URL has many query parameters, which can be used to track or trick users.")
    return flags


def apply_live_checks(level: str, live: dict):
    """Adjusts the risk level using live checks. Returns (level, flags, unverified)."""
    flags = []
    unverified = False

    if not live["dns_ok"]:
        flags.append("This domain does not exist (DNS lookup failed). The link may be fake, mistyped or taken down.")
        return raise_to(level, "Suspicious"), flags, True

    age = live["age_days"]
    if age is None:
        unverified = True
    elif age < 30:
        flags.append(f"The domain is very new (only {age} days old). Most phishing sites are created recently.")
        level = raise_to(level, "Suspicious")
    elif age < 180:
        flags.append(f"The domain is fairly new ({age} days old).")

    if live["ssl_valid"] is False:
        flags.append("The website's HTTPS certificate is invalid or does not match the domain.")
        level = raise_to(level, "Suspicious")
    elif live["ssl_valid"] is None:
        unverified = True

    return level, flags, unverified


def check_row(label: str, status: str, detail: str):
    st.markdown(f"**{label}:** {status} {detail}")


# ---------- Page ----------
st.title("🛡️ Phishing URL Detector")
st.caption("Paste a link and find out if it looks safe. Combines an ML model (URL patterns) with live checks (DNS, SSL, domain age).")

tab1, tab2, tab3 = st.tabs(["Single URL", "Batch (CSV)", "About"])

# ---------- Tab 1: single URL ----------
with tab1:
    url = st.text_input(
        "Enter a URL",
        placeholder="http://secure-login.paypa1-verify.com/account/update",
    )

    if st.button("Check URL", type="primary") and url.strip():
        prob, feats = predict(url)

        with st.spinner("Running live checks (DNS, SSL, domain age)..."):
            live = run_live_checks(url)

        level, live_flags, unverified = apply_live_checks(risk_level(prob), live)

        # Verdict + recommended actions
        if level == "Dangerous":
            st.error("🔴 Dangerous: this URL is very likely a phishing link. Do not open it.")
            st.markdown(
                """
**What you should do:**
- Do **not** click the link or enter any password, OTP or card details.
- If it came in an email or message, delete it and report it as spam/phishing.
- If you already clicked it, change your passwords immediately and enable two-factor authentication.
- If you entered banking details, contact your bank right away.
                """
            )
        elif level == "Suspicious":
            st.warning("🟡 Suspicious: this URL has some risky signs. Be careful and verify the source.")
            st.markdown(
                """
**What you should do:**
- Do not enter any personal information on this site.
- Type the official website address directly in your browser instead of using this link.
- Check the sender by contacting the company through its official channel.
                """
            )
        else:
            st.success("🟢 Low risk: no suspicious patterns were found in this URL.")
            st.markdown(
                """
**Stay careful:**
- This is only an automated check and is not a guarantee that the site is genuine.
- Avoid sharing passwords or OTPs unless you are sure it is the official website.
                """
            )
            if unverified:
                st.info("Some live checks could not be completed, so treat this result with extra caution.")

        st.metric("Model risk score", f"{prob:.0%}")
        st.progress(min(prob, 1.0))

        # Live check results
        st.subheader("Live checks")
        if live["dns_ok"]:
            check_row("Domain exists", "✅", f"(resolves to {live['ip']})")
        else:
            check_row("Domain exists", "❌", "(DNS lookup failed)")

        if live["ssl_valid"] is True:
            check_row("HTTPS certificate", "✅", f"(valid, {live['ssl_days_left']} days left)")
        elif live["ssl_valid"] is False:
            check_row("HTTPS certificate", "❌", "(invalid or mismatched)")
        else:
            check_row("HTTPS certificate", "❔", "(could not check)")

        if live["age_days"] is not None:
            years = live["age_days"] / 365
            check_row("Domain age", "✅" if live["age_days"] >= 180 else "⚠️",
                      f"({live['age_days']} days, about {years:.1f} years)")
        else:
            check_row("Domain age", "❔", "(could not find WHOIS data)")

        # Why was it flagged?
        flags = live_flags + get_red_flags(url, feats)
        if flags:
            st.subheader("Why this looks risky")
            for fl in flags:
                st.markdown(f"- ⚠️ {fl}")

        # Technical details hidden by default
        with st.expander("Technical details (for developers)"):
            st.write("Features extracted from the URL:")
            st.dataframe(pd.Series(feats, name="value"), use_container_width=True)

            st.write("Top features the model relies on:")
            imp = pd.Series(model.feature_importances_, index=FEATURES).nlargest(10)
            st.bar_chart(imp)

# ---------- Tab 2: batch CSV ----------
with tab2:
    st.write("Upload a CSV file that has a column named **url**.")
    st.caption("Batch mode uses the ML model only (live checks would be too slow for many URLs).")
    file = st.file_uploader("CSV file", type="csv")
    if file:
        data = pd.read_csv(file)
        if "url" not in data.columns:
            st.error("The CSV must contain a 'url' column.")
        else:
            probs = [predict(u)[0] for u in data["url"].astype(str)]
            data["risk_score"] = [round(p, 3) for p in probs]
            data["verdict"] = [risk_level(p) for p in probs]
            st.dataframe(data, use_container_width=True)
            st.download_button(
                "Download results",
                data.to_csv(index=False),
                "results.csv",
                "text/csv",
            )

# ---------- Tab 3: about ----------
with tab3:
    st.markdown(
        """
**How it works:** The app uses two layers of checking.

1. **ML model:** extracts 70+ lexical features from the URL (special character counts, lengths,
   IP-in-domain, shorteners, etc.) and a Random Forest returns a phishing probability.
2. **Live checks:** confirms the domain really exists (DNS), that its HTTPS certificate is valid,
   and how old the domain is (WHOIS). Very new or non-existent domains raise the risk level.

| Model risk score | Verdict |
|---|---|
| 70% or more | 🔴 Dangerous |
| 40% to 70% | 🟡 Suspicious |
| Below 40% | 🟢 Low risk |

**Limitations:** The app does not read the page content or check blocklists, so a well-made
fake site on an older domain can still slip through. Treat it as a screening tool, not a final verdict.
        """
    )
