import re
from urllib.parse import urlparse

import cv2
import numpy as np
import streamlit as st

from ml_engine import get_ml_result


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="ScamLens AI",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# SCAM DETECTION RULES
# =========================================================

SCAM_PATTERNS = {
    "Urgency / Pressure": [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\bact now\b",
        r"within \d+ (minutes?|hours?)",
        r"account.*(blocked|suspended|closed|locked)",
        r"\blast warning\b",
        r"\bfinal notice\b"
    ],

    "Credential / OTP Theft": [
        r"\bpassword\b",
        r"\botp\b",
        r"\bpin\b",
        r"\bcvv\b",
        r"\bverification code\b",
        r"\brecovery code\b",
        r"verify.*account",
        r"login.*link"
    ],

    "Payment / UPI Fraud": [
        r"\bupi\b",
        r"\bpayment\b",
        r"\btransfer\b",
        r"\bqr code\b",
        r"\brefund\b",
        r"\bprocessing fee\b",
        r"\bgift card\b",
        r"\bpay now\b",
        r"\bscan.*qr\b"
    ],

    "Prize / Reward Bait": [
        r"\bwon\b",
        r"\bwinner\b",
        r"\bprize\b",
        r"\blottery\b",
        r"\bcashback\b",
        r"\bfree reward\b",
        r"\bclaim.*reward\b"
    ],

    "Impersonation": [
        r"\bbank\b",
        r"\bpolice\b",
        r"\bcustoms\b",
        r"\bgovernment\b",
        r"\bcustomer care\b",
        r"\bceo\b",
        r"\bmanager\b",
        r"\btech support\b",
        r"\bofficial support\b"
    ],

    "Investment / Crypto Scam": [
        r"\bcrypto\b",
        r"\bbitcoin\b",
        r"\binvestment\b",
        r"\bguaranteed return\b",
        r"\bdouble your money\b",
        r"\bhigh return\b",
        r"\btrading profit\b"
    ],

    "Job / Task Scam": [
        r"\bwork from home\b",
        r"\beasy income\b",
        r"\bpart.?time job\b",
        r"\bregistration fee\b",
        r"\btask earning\b",
        r"\bdaily income\b"
    ],

    "Secrecy / Isolation": [
        r"\bdo not tell\b",
        r"\bkeep this confidential\b",
        r"\bsecret\b",
        r"don.?t call",
        r"\bdo not contact\b"
    ]
}


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "rb.gy",
    "cutt.ly",
    "is.gd"
}


SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".work",
    ".support",
    ".live",
    ".info"
}


# =========================================================
# URL ANALYSIS
# =========================================================

def extract_urls(text):
    return re.findall(
        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
        text,
        flags=re.I
    )


def analyze_url(url):
    raw = url if "://" in url else "https://" + url

    try:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
    except Exception:
        return 15, ["Malformed or unreadable URL"]

    score = 0
    reasons = []

    if host in SHORTENERS:
        score += 18
        reasons.append(
            "Shortened URL hides the final destination"
        )

    if "@" in raw:
        score += 20
        reasons.append(
            "@ symbol may hide the real destination"
        )

    if host.count("-") >= 3:
        score += 10
        reasons.append(
            "Domain contains unusually many hyphens"
        )

    if re.fullmatch(
        r"\d{1,3}(\.\d{1,3}){3}",
        host
    ):
        score += 18
        reasons.append(
            "Uses a raw IP address instead of a normal domain"
        )

    if any(
        host.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    ):
        score += 20
        reasons.append(
            "Domain ending is commonly abused in disposable campaigns"
        )

    if len(host) > 35:
        score += 7
        reasons.append(
            "Unusually long domain name"
        )

    if "xn--" in host:
        score += 18
        reasons.append(
            "Punycode domain may be attempting a lookalike-domain attack"
        )

    if host.count(".") >= 4:
        score += 8
        reasons.append(
            "Domain uses an unusual number of subdomains"
        )

    return score, reasons


# =========================================================
# EXPLAINABLE RULE ENGINE
# =========================================================

def analyze_rules(text):
    lower = text.lower()

    score = 0
    findings = []

    for label, patterns in SCAM_PATTERNS.items():
        hits = []

        for pattern in patterns:
            if re.search(
                pattern,
                lower,
                flags=re.I
            ):
                hits.append(pattern)

        if hits:
            points = min(
                20,
                7 + 4 * len(hits)
            )

            score += points
            findings.append(
                (label, points)
            )

    urls = extract_urls(text)
    url_reasons = []

    for url in urls[:5]:
        points, reasons = analyze_url(url)

        score += points

        for reason in reasons:
            url_reasons.append(
                f"{url}: {reason}"
            )

    # Sensitive credentials + action
    if (
        re.search(
            r"\b(otp|pin|cvv|password|verification code)\b",
            lower
        )
        and
        re.search(
            r"\b(send|share|enter|provide|tell|reply)\b",
            lower
        )
    ):
        score += 20

        findings.append(
            (
                "Sensitive authentication information requested",
                20
            )
        )

    # Urgency + risky action
    if (
        re.search(
            r"\b(urgent|immediately|now|today)\b",
            lower
        )
        and
        re.search(
            r"\b(pay|transfer|click|verify|share|scan)\b",
            lower
        )
    ):
        score += 15

        findings.append(
            (
                "Urgency combined with a risky action",
                15
            )
        )

    # Authority + sensitive request
    if (
        re.search(
            r"\b(bank|police|government|support)\b",
            lower
        )
        and
        re.search(
            r"\b(otp|password|payment|transfer)\b",
            lower
        )
    ):
        score += 12

        findings.append(
            (
                "Authority impersonation combined with sensitive request",
                12
            )
        )

    score = min(
        100,
        score
    )

    return (
        score,
        findings,
        urls,
        url_reasons
    )


# =========================================================
# HYBRID AI ENGINE
# =========================================================

def analyze_hybrid(text):
    rule_score, findings, urls, url_reasons = (
        analyze_rules(text)
    )

    ml_result = get_ml_result(text)

    ml_probability = ml_result["probability"]
    ml_percentage = ml_result["percentage"]
    ml_label = ml_result["label"]

    ml_score = round(
        ml_probability * 100
    )

    # 70% explainable security engine
    # 30% machine-learning classifier
    hybrid_score = round(
        (rule_score * 0.70)
        +
        (ml_score * 0.30)
    )

    # Important:
    # Strong URL evidence should not become artificially low
    # just because the text classifier sees only a URL.
    if url_reasons:
        hybrid_score = max(
            hybrid_score,
            min(rule_score, 45)
        )

    hybrid_score = min(
        100,
        max(0, hybrid_score)
    )

    return {
        "score": hybrid_score,
        "rule_score": rule_score,
        "ml_score": ml_score,
        "ml_percentage": ml_percentage,
        "ml_label": ml_label,
        "findings": findings,
        "urls": urls,
        "url_reasons": url_reasons
    }


# =========================================================
# RISK LEVEL
# =========================================================

def risk_band(score):
    if score >= 75:
        return (
            "CRITICAL RISK",
            "🚨",
            "Do not click links, send money, reply, or share credentials."
        )

    if score >= 50:
        return (
            "HIGH RISK",
            "🔴",
            "Multiple scam indicators detected. Verify independently before taking any action."
        )

    if score >= 20:
        return (
            "SUSPICIOUS",
            "⚠️",
            "Warning signals were detected. Verify the sender, domain and request independently."
        )

    return (
        "LOWER RISK",
        "✅",
        "No strong scam pattern was detected, but unexpected requests should still be verified."
    )


# =========================================================
# QR DECODER
# =========================================================

def decode_qr(uploaded_file):
    data = np.frombuffer(
        uploaded_file.getvalue(),
        dtype=np.uint8
    )

    image = cv2.imdecode(
        data,
        cv2.IMREAD_COLOR
    )

    if image is None:
        return ""

    detector = cv2.QRCodeDetector()

    # Try multiple QR codes
    try:
        ok, decoded_info, points, _ = (
            detector.detectAndDecodeMulti(image)
        )

        if ok:
            values = [
                item.strip()
                for item in decoded_info
                if item and item.strip()
            ]

            if values:
                return "\n".join(values)

    except Exception:
        pass

    # Try single QR
    value, points, _ = (
        detector.detectAndDecode(image)
    )

    if value:
        return value.strip()

    return ""


# =========================================================
# REPORT UI
# =========================================================

def show_report(content, source):
    result = analyze_hybrid(content)

    score = result["score"]
    rule_score = result["rule_score"]
    ml_percentage = result["ml_percentage"]
    ml_label = result["ml_label"]
    findings = result["findings"]
    urls = result["urls"]
    url_reasons = result["url_reasons"]

    label, icon, action = risk_band(score)

    st.divider()

    st.subheader(
        "🛡️ ScamLens Risk Report"
    )

    st.caption(
        f"Analyzed source: {source}"
    )

    col1, col2, col3 = st.columns(
        [1, 1.2, 2.5]
    )

    col1.metric(
        "Hybrid Risk Score",
        f"{score}/100"
    )

    col2.metric(
        "Verdict",
        f"{icon} {label}"
    )

    col3.info(action)

    st.progress(
        score / 100
    )

    # -----------------------------------------------------
    # MACHINE LEARNING
    # -----------------------------------------------------

    st.subheader(
        "🤖 Machine Learning Analysis"
    )

    ml1, ml2, ml3 = st.columns(3)

    ml1.metric(
        "ML Scam Probability",
        f"{ml_percentage}%"
    )

    ml2.metric(
        "ML Assessment",
        ml_label
    )

    ml3.metric(
        "Explainable Engine",
        f"{rule_score}/100"
    )

    st.caption(
        "Hybrid detection combines a local TF-IDF + "
        "Logistic Regression classifier with explainable "
        "fraud rules and URL forensics."
    )

    # -----------------------------------------------------
    # EVIDENCE
    # -----------------------------------------------------

    st.subheader(
        "🔎 Evidence detected"
    )

    if not findings and not url_reasons:
        st.success(
            "No strong explainable warning signals were detected."
        )

    else:
        for name, points in findings:
            st.write(
                f"• **{name}** (+{points} rule points)"
            )

        for reason in url_reasons:
            st.write(
                f"• **Suspicious URL:** {reason}"
            )

    # -----------------------------------------------------
    # URLS
    # -----------------------------------------------------

    if urls:
        st.subheader(
            "🔗 URLs found"
        )

        for url in urls[:5]:
            st.code(url)

    # -----------------------------------------------------
    # SAFETY ACTIONS
    # -----------------------------------------------------

    st.subheader(
        "✅ Recommended safety actions"
    )

    st.markdown(
        """
1. **Do not click links or call numbers contained in the suspicious message.**
2. Find the organization's official website independently.
3. **Never share OTP, PIN, CVV, passwords or recovery codes.**
4. Verify payment or identity requests through another trusted channel.
5. Check the exact domain before logging in.
6. Preserve screenshots and transaction evidence if fraud is suspected.
"""
    )


# =========================================================
# MAIN UI
# =========================================================

st.markdown(
    "# 🛡️ ScamLens AI"
)

st.caption(
    "Hybrid ML + explainable scam, impersonation, fraud & QR-link screening"
)


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:
    st.header(
        "About ScamLens"
    )

    st.write(
        "Built for ForgeHacks 2026 — AI + Cybersecurity."
    )

    st.write(
        "ScamLens combines a local machine-learning "
        "classifier, explainable fraud rules, URL "
        "forensics and QR decoding."
    )

    st.markdown(
        """
### 🧠 Detection Stack

- TF-IDF text features
- Logistic Regression classifier
- Explainable scam rules
- URL forensics
- QR payload analysis
- Hybrid risk scoring
"""
    )

    st.info(
        "Prototype safety assistant — a low score does not guarantee that content is safe."
    )


# =========================================================
# TABS
# =========================================================

text_tab, qr_tab = st.tabs(
    [
        "💬 Message / URL",
        "📷 QR Image Scanner"
    ]
)


# =========================================================
# MESSAGE / URL TAB
# =========================================================

with text_tab:
    left, right = st.columns(
        [1.15, 0.85]
    )

    with left:
        st.subheader(
            "🔍 Analyze suspicious content"
        )

        sample = (
            "URGENT SECURITY ALERT: "
            "Your bank account has been suspended. "
            "Verify immediately at "
            "http://secure-bank-support.xyz/login "
            "and enter your password and OTP."
        )

        if "input_text" not in st.session_state:
            st.session_state.input_text = ""

        text = st.text_area(
            "Paste a suspicious message, email or URL",
            key="input_text",
            height=220,
            placeholder=sample
        )

        button1, button2 = st.columns(2)

        if button1.button(
            "Load scam example",
            use_container_width=True
        ):
            st.session_state.input_text = sample
            st.rerun()

        analyze_clicked = button2.button(
            "Analyze risk",
            type="primary",
            use_container_width=True
        )

    with right:
        st.subheader(
            "🧠 Detection Engine"
        )

        st.markdown(
            """
- 🤖 TF-IDF + Logistic Regression ML
- ⏱️ Urgency & social engineering
- 🔐 OTP/password theft
- 💳 Payment & UPI fraud
- 🎁 Prize/reward scams
- 🏦 Authority impersonation
- 📈 Investment & crypto scams
- 💼 Fake job/task scams
- 🔗 Suspicious URL forensics
- 🕵️ Secrecy & isolation tactics
- ⚡ Hybrid risk scoring
"""
        )

    if analyze_clicked:
        if not text.strip():
            st.warning(
                "Paste a message, email or URL first."
            )

        else:
            show_report(
                text,
                "Message / URL"
            )


# =========================================================
# QR SCANNER
# =========================================================

with qr_tab:
    st.subheader(
        "📷 Scan a suspicious QR code"
    )

    st.write(
        "Upload a PNG, JPG or JPEG image containing a QR code. "
        "ScamLens decodes its payload locally and sends the "
        "decoded content through the same hybrid detection engine."
    )

    uploaded_file = st.file_uploader(
        "Upload QR image",
        type=[
            "png",
            "jpg",
            "jpeg"
        ]
    )

    if uploaded_file is not None:
        st.image(
            uploaded_file,
            caption="Uploaded image",
            width=360
        )

        if st.button(
            "Scan QR & analyze",
            type="primary"
        ):
            decoded_content = decode_qr(
                uploaded_file
            )

            if not decoded_content:
                st.error(
                    "No readable QR code was detected. "
                    "Try a clearer, larger or less-cropped image."
                )

            else:
                st.success(
                    "QR code decoded successfully."
                )

                st.markdown(
                    "**Decoded content**"
                )

                st.code(
                    decoded_content
                )

                show_report(
                    decoded_content,
                    "QR image"
                )


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.caption(
    "ScamLens AI • ForgeHacks 2026 • "
    "Hybrid ML + explainable fraud screening prototype — "
    "always independently verify high-impact requests."
)