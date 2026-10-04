# ScamLens AI 🛡️

**AI + Cybersecurity | ForgeHacks 2026**

ScamLens AI is an explainable scam, impersonation, and fraud screening assistant. Users paste a suspicious message, email, or URL and receive a 0–100 risk score, the evidence behind that score, and concrete verification steps.

## Why it matters
Modern scams exploit urgency, impersonation, malicious links, payment pressure, and credential theft. AI-generated content makes these attacks cheaper and more convincing. ScamLens is designed to make the first safety decision simple: **Is this suspicious, why, and what should I do next?**

## Current MVP
- Social-engineering and scam-pattern detection
- Credential/OTP/password request detection
- Payment/refund/reward-bait detection
- Suspicious URL structural analysis
- Explainable risk score
- Action-oriented safety guidance
- Streamlit web interface

## Architecture
`User input → text/URL preprocessing → scam-signal detectors → weighted risk engine → explainable verdict → recommended actions`

The MVP deliberately exposes the evidence used by the risk engine rather than returning an opaque label. A future model-assisted layer can classify novel language and impersonation patterns while the deterministic signals remain available for explainability.

## Run locally
```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Demo input
```text
URGENT: Your bank account will be suspended. Verify now at http://secure-bank-support.xyz/login and share the OTP to restore access.
```

## Responsible use
ScamLens is a prototype decision-support tool. A low risk score does not prove that a message or website is legitimate. Users should independently verify high-impact requests involving money, identity, or account access.

## ForgeHacks prompt
AI + Cybersecurity: build an AI-powered solution that helps people recognize, prevent, verify, or respond to scams, impersonation, and fraud enabled by AI or modern technologies.
