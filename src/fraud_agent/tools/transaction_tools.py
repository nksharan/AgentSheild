import re


URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
HIGH_RISK_WORDS = {
    "otp",
    "one time password",
    "verify account",
    "update kyc",
    "click here",
    "gift card",
    "crypto",
    "wire transfer",
    "upi",
    "urgent",
    "immediate",
    "limited time",
    "suspended",
    "blocked",
    "security alert",
    "login now",
    "share code",
    "bank details",
    "rto",
    "parcel",
    "reward",
    "lottery",
    "prize",
    "job offer",
    "remote access",
    "anydesk",
    "teamviewer",
}


def scan_text(text: str) -> dict:
    msg = (text or "").strip()
    lower = msg.lower()
    urls = URL_RE.findall(msg)
    signals = []
    risk_terms = []

    for term in sorted(HIGH_RISK_WORDS, key=len, reverse=True):
        if term in lower:
            risk_terms.append(term)

    if risk_terms:
        signals.append(f"high-risk language: {', '.join(risk_terms[:5])}")
    if any(k in lower for k in ["urgent", "immediately", "today only", "expires soon", "blocked", "suspended"]):
        signals.append("pressure and urgency")
    if any(k in lower for k in ["gift card", "crypto", "wire transfer", "upi", "please pay", "send amount"]):
        signals.append("payment requested in non-reversible method")
    if any(k in lower for k in ["otp", "password", "cvv", "pin", "verify code", "security code"]):
        signals.append("credential or OTP request")
    if any(k in lower for k in ["click here", "download", "install", "remote access", "anydesk", "teamviewer"]):
        signals.append("action request with link or app install")
    if any(k in lower for k in ["secrets", "never tell anyone", "do not disconnect", "do not share"]):
        signals.append("isolation or secrecy pressure")

    return {
        "text": msg,
        "urls": urls,
        "signals": signals,
        "risk_terms": risk_terms,
    }


def analyze_url(url: str) -> dict:
    u = (url or "").strip().lower()
    if not u:
        return {"url": url, "is_suspicious": False, "reasons": []}

    reasons = []
    suspicious = False

    if any(token in u for token in ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly"]):
        reasons.append("URL shortener")
        suspicious = True
    if re.search(r"\d+\.\d+\.\d+\.\d+", u):
        reasons.append("IP-address host")
        suspicious = True
    if re.search(r"(?:paypa1|micros0ft|g00gle|facebo0k|arnazon|sbi-kyc|apple-id|bankofamerica)\b", u):
        reasons.append("lookalike or typo-domain pattern")
        suspicious = True
    if any(domain in u for domain in [".in.net", ".xyz", ".ru", ".info", ".tk"]):
        reasons.append("uncommon or abused TLD")
        suspicious = True
    if re.search(r"(?:login|verify|secure|update).*(?:php|aspx|cgi|auth)", u):
        reasons.append("credential-harvesting path")
        suspicious = True

    return {"url": url, "is_suspicious": suspicious, "reasons": reasons}


def check_sender(sender: str, claimed_brand: str = "") -> dict:
    sender = (sender or "").strip()
    claimed_brand = (claimed_brand or "").strip()
    lower_sender = sender.lower()
    reasons = []

    if not sender:
        return {"sender": sender, "is_impersonation": False, "reasons": []}

    if "@gmail.com" in lower_sender or "@yahoo.com" in lower_sender or "@outlook.com" in lower_sender:
        reasons.append("generic free email is used as a sender")
    if claimed_brand and claimed_brand.lower() not in lower_sender and "bank" in claimed_brand.lower():
        reasons.append(f"sender does not match the claimed brand: {claimed_brand}")
    if lower_sender.startswith("+91") or lower_sender.isdigit():
        reasons.append("personal number used as business sender")

    is_impersonation = bool(reasons)
    return {"sender": sender, "claimed_brand": claimed_brand, "is_impersonation": is_impersonation, "reasons": reasons}
