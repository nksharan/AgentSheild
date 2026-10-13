import re

from .config import GOOGLE_API_KEY, MODEL, TEMPERATURE
from .schemas import ScamAssessment
from .tools.transaction_tools import analyze_url, check_sender, scan_text


def build_agent():
    """Return a lightweight function-compatible interface for the app."""
    return {"model": MODEL, "temperature": TEMPERATURE, "api_key_present": bool(GOOGLE_API_KEY)}


def _detect_channel(content: str) -> str:
    lower = content.lower()
    if "sms from" in lower or "sms:" in lower:
        return "sms"
    if "email from" in lower or "@" in lower:
        return "email"
    if "dm from" in lower or "instagram" in lower or "whatsapp" in lower or "telegram" in lower:
        return "social_media"
    if "chat" in lower:
        return "chat"
    if "http" in lower or "www." in lower:
        return "web_link"
    return "unknown"


def _detect_scam_type(signals: list[str]) -> str:
    text = " ".join(signals).lower()
    if any(k in text for k in ["gift card", "crypto", "wire transfer", "upi", "payment requested"]):
        return "investment_crypto_scam"
    if any(k in text for k in ["bank", "kyc", "blocked", "suspended", "security alert"]):
        return "bank_kyc_scam"
    if any(k in text for k in ["delivery", "parcel", "rto", "shipment"]):
        return "delivery_scam"
    if any(k in text for k in ["job", "salary", "task", "remote", "work from home"]):
        return "job_task_scam"
    if any(k in text for k in ["lottery", "prize", "winner"]):
        return "prize_lottery_scam"
    if any(k in text for k in ["anydesk", "teamviewer", "remote access"]):
        return "tech_support_scam"
    return "other"


def _build_recommendation(verdict: str, signals: list[str]) -> str:
    if verdict == "SCAM":
        return "Do not click, call, or share codes. Verify the sender through their official app or website before acting."
    if verdict == "SUSPICIOUS":
        return "Treat this as unverified. Contact the business through a known official channel and avoid taking action immediately."
    return "This looks legitimate based on the current message. Still verify before sharing sensitive information."


def assess(content: str) -> ScamAssessment:
    raw = (content or "").strip()
    if not raw:
        return ScamAssessment(
            verdict="SAFE",
            risk_score=0,
            scam_type="none",
            channel="unknown",
            impersonated_entity=None,
            red_flags=[],
            recommended_action="Please provide a message to assess.",
        )

    scan = scan_text(raw)
    flags = list(scan["signals"])
    url_checks = [analyze_url(url) for url in scan.get("urls", [])]
    url_flags = []
    for item in url_checks:
        if item.get("is_suspicious"):
            url_flags.append(f"URL suspicious: {item['url']} - {', '.join(item['reasons'])}")
    if url_flags:
        flags.extend(url_flags)

    channel = _detect_channel(raw)
    impersonated_entity = None
    sender_match = re.search(r"(?:from|sent by|sender)\s*[:\-]?\s*(.+)", raw, re.IGNORECASE)
    if sender_match:
        sender = sender_match.group(1).strip().splitlines()[0]
        if sender:
            sender_result = check_sender(sender, claimed_brand="")
            if sender_result.get("is_impersonation"):
                impersonated_entity = sender
                flags.append(f"Sender mismatch: {sender}")

    score = 0
    if "payment requested in non-reversible method" in " ".join(flags).lower():
        score += 35
    if "credential or OTP request" in " ".join(flags).lower():
        score += 25
    if "pressure and urgency" in " ".join(flags).lower():
        score += 15
    if "URL suspicious" in " ".join(flags).lower():
        score += 20
    if "high-risk language" in " ".join(flags).lower():
        score += 10
    if "isolation or secrecy pressure" in " ".join(flags).lower():
        score += 10
    score = min(score, 100)

    if score >= 70:
        verdict = "SCAM"
    elif score >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    scam_type = _detect_scam_type(flags)
    if verdict == "SAFE" and not flags:
        scam_type = "none"

    return ScamAssessment(
        verdict=verdict,
        risk_score=score,
        scam_type=scam_type,
        channel=channel,
        impersonated_entity=impersonated_entity,
        red_flags=list(dict.fromkeys(flags))[:8],
        recommended_action=_build_recommendation(verdict, flags),
    )
