import re
from urllib.parse import urlsplit

from langchain.tools import tool

# Official domains per brand. A brand name appearing in any other domain is a lookalike.
BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"},
    "office365": {"office.com", "microsoft.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "usps": {"usps.com"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com"},
    "ups": {"ups.com"},
    "irs": {"irs.gov"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"},
    "hdfc": {"hdfcbank.com", "hdfc.bank.in"},
    "icici": {"icicibank.com", "icici.bank.in"},
    "indiapost": {"indiapost.gov.in"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "royalmail": {"royalmail.com"},
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "t.ly", "s.id",
}
SUSPICIOUS_TLDS = {
    "top", "xyz", "icu", "click", "link", "live", "shop", "buzz", "cfd", "sbs", "rest",
    "quest", "cyou", "monster", "online", "site", "support", "help", "info", "vip", "cc",
}
MULTI_PART_SUFFIXES = {"co.uk", "co.in", "gov.in", "com.au", "co.jp", "com.br", "gov.uk", "org.uk"}
CREDENTIAL_PATH_WORDS = {"login", "signin", "verify", "secure", "update", "account", "wallet", "unlock", "suspend", "kyc", "redeliver"}
FREE_MAIL = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "aol.com",
    "protonmail.com", "proton.me", "icloud.com", "yandex.com", "mail.ru", "rediffmail.com",
}
# Digits and letter pairs scammers swap in for lookalike letters (paypa1, arnazon).
HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("4", "a")]
URL_RE = re.compile(r"(?:https?://|www\.)\S+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}/\S*", re.I)
PHONE_RE = re.compile(r"(?:\+\d{1,3}[\s-]?)?\(?\d{3,5}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}")

# (category, weight, patterns) — phrasing seen repeatedly in reported phishing/smishing campaigns.
TEXT_SIGNALS = [
    ("urgency", 15, [
        r"\burgent\b", r"\bimmediately\b", r"within \d+ ?(hours?|hrs|minutes?)", r"\bact now\b",
        r"final (notice|warning|reminder)", r"last (chance|warning)", r"expires? today", r"\bpay now\b",
        r"\btonight\b", r"before it'?s too late",
    ]),
    ("account_threat", 20, [
        r"(account|card|number|sim|service|connection|id)\s+(has been |will be |is |was )?(suspended|blocked|locked|limited|deactivated|disconnected|closed|restricted)",
        r"returned to (the )?sender",
        r"unusual (sign-?in|activity|login)", r"password (expires?|expired)",
    ]),
    ("authority_or_legal_threat", 25, [
        r"\barrest(ed)?\b", r"\bwarrant\b", r"legal action", r"\bpolice\b", r"\bcbi\b", r"\bnarcotics\b",
        r"\bcustoms\b", r"money laundering", r"digital arrest", r"\bcourt\b", r"\bpenalty\b",
    ]),
    ("credential_or_otp_request", 30, [
        r"verify your (account|identity|details)", r"confirm your (identity|details|account|information)",
        r"(?<!never )(?<!not )(share|send|tell|provide) (us |me )?(the |your )?(otp|code|pin|password|cvv)",
        r"(submit|enter|update|provide) your (bank|card|account) details",
        r"update (your )?(kyc|pan|aadhaar)", r"\bkyc\b", r"login details",
    ]),
    ("unusual_payment_method", 30, [
        r"gift ?cards?", r"(itunes|google play|steam|amazon) cards?", r"\bbitcoin\b", r"\bbtc\b", r"\busdt\b",
        r"crypto wallet", r"wire transfer", r"western union", r"upi pin",
        r"(processing|registration|release|customs|delivery|redelivery|clearance|shipping|unpaid) (fee|charge)",
        r"scan (this|the) qr( code)? to receive",
    ]),
    ("too_good_to_be_true", 25, [
        r"you('ve| have)? won", r"\bwinner\b", r"\blottery\b", r"claim your (prize|reward|gift)",
        r"guaranteed (returns?|profit)", r"double your", r"\bgiveaway\b", r"free (iphone|gift)",
        r"earn (rs\.?|₹|\$)?\s?\d[\d,]* (per|a|every) (day|hour|task)", r"daily (income|profit)",
        r"part[- ]time job", r"work from home", r"eligible for a (tax )?refund",
    ]),
    ("move_off_platform", 15, [
        r"\btelegram\b", r"whatsapp me", r"\bdm me\b", r"text me (on|at)", r"add me on",
    ]),
    ("secrecy", 20, [
        r"don'?t tell (anyone|your family)", r"keep (this|it) (confidential|secret)", r"do not disconnect",
    ]),
    ("remote_access", 30, [
        r"\banydesk\b", r"\bteamviewer\b", r"quick ?support", r"remote access", r"screen ?shar",
    ]),
    ("generic_greeting", 5, [
        r"dear (customer|user|client|member|valued|sir|madam|account holder)",
    ]),
]
PROTECTIVE_PATTERNS = [
    r"(do not|don'?t|never) share", r"we will never ask", r"if (this was not you|you did not)",
]


def _registered_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _official_brand(domain: str) -> str | None:
    for brand, domains in BRAND_DOMAINS.items():
        if any(domain == d or domain.endswith("." + d) for d in domains):
            return brand
    return None


def _domain_signals(host: str) -> tuple[int, list[str]]:
    """Lookalike/impersonation checks shared by URL and sender analysis."""
    score, signals = 0, []
    registered = _registered_domain(host)
    if _official_brand(host):
        return 0, []

    tokens = re.split(r"[.-]", host)
    for brand in BRAND_DOMAINS:
        hit = any(t == brand or (len(brand) >= 5 and (t.startswith(brand) or t.endswith(brand))) for t in tokens)
        if hit:
            score += 40
            signals.append(f"uses brand name '{brand}' but is not an official {brand} domain")
            break

    for label in registered.split(".")[0].split("-"):
        normalized = label
        for fake, real in HOMOGLYPHS:
            normalized = normalized.replace(fake, real)
        typosquat = next((b for b in BRAND_DOMAINS if len(b) >= 5 and label != b
                          and (normalized == b or _levenshtein(label, b) == 1)), None)
        if typosquat:
            score += 40
            signals.append(f"typosquat of '{typosquat}' ({label})")
            break

    if "xn--" in host:
        score += 30
        signals.append("punycode domain (possible homograph attack)")
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 15
        signals.append(f"TLD .{tld} is heavily abused for phishing")
    return score, signals


@tool
def analyze_url(url: str) -> dict:
    """Check a single link for phishing indicators without visiting it.

    Detects brand lookalikes, typosquats, IP-address hosts, URL shorteners,
    abused TLDs, punycode and credential-harvesting paths.

    Args:
        url: The link exactly as it appears in the message.
    """
    raw = url.strip().rstrip(".,)")
    parts = urlsplit(raw if "://" in raw else "http://" + raw)
    host = (parts.hostname or "").lower()
    if not host:
        return {"url": url, "score": 0, "signals": ["could not parse URL"]}

    official = _official_brand(host)
    score, signals = _domain_signals(host)
    if re.fullmatch(r"[\d.]+", host):
        score += 35
        signals.append("host is a raw IP address")
    if host in URL_SHORTENERS:
        score += 15
        signals.append("URL shortener hides the real destination")
    if "@" in parts.netloc:
        score += 25
        signals.append("'@' in URL — browser ignores everything before it")
    if host.count(".") >= 4:
        score += 10
        signals.append("unusually deep subdomain chain")
    if parts.scheme == "http" and not official:
        score += 10
        signals.append("not using HTTPS")
    path_words = set(re.split(r"[/\-_.?=&]", parts.path.lower() + " " + parts.query.lower()))
    if not official and path_words & CREDENTIAL_PATH_WORDS:
        score += 10
        signals.append(f"credential-harvesting path words: {sorted(path_words & CREDENTIAL_PATH_WORDS)}")
    if official:
        signals.append(f"domain belongs to {official}")

    return {
        "url": url,
        "host": host,
        "registered_domain": _registered_domain(host),
        "official_brand": official,
        "score": min(score, 100),
        "signals": signals,
    }


@tool
def scan_text(text: str) -> dict:
    """Scan message text for social-engineering language used in real scams.

    Returns matched red-flag categories, any links and phone numbers found,
    and whether the text contains protective language typical of genuine notices.

    Args:
        text: The full message, email body, or post content.
    """
    lowered = text.lower()
    score, matches = 0, {}
    for category, weight, patterns in TEXT_SIGNALS:
        found = [m.group(0) for p in patterns if (m := re.search(p, lowered))]
        if found:
            matches[category] = found
            score += weight

    protective = any(re.search(p, lowered) for p in PROTECTIVE_PATTERNS)
    if protective:
        score -= 15

    letters = [c for c in text if c.isalpha()]
    if len(letters) > 20 and sum(c.isupper() for c in letters) / len(letters) > 0.5:
        score += 5
        matches["shouting"] = ["mostly uppercase"]
    if text.count("!") >= 3:
        score += 5
        matches.setdefault("shouting", []).append("multiple exclamation marks")

    return {
        "score": max(0, min(score, 100)),
        "red_flags": matches,
        "urls": URL_RE.findall(text),
        "phone_numbers": [p.strip() for p in PHONE_RE.findall(text) if len(re.sub(r"\D", "", p)) >= 10],
        "protective_language": protective,
    }


@tool
def check_sender(sender: str, claimed_brand: str = "") -> dict:
    """Check whether a sender address, number or handle fits the organisation it claims to be.

    Args:
        sender: Email address (optionally with display name), phone number, SMS sender ID, or social handle.
        claimed_brand: Organisation the message claims to come from, e.g. "paypal", "sbi". Empty if none.
    """
    claimed = re.sub(r"[^a-z]", "", claimed_brand.lower())
    score, signals = 0, []
    email = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", sender)

    if email:
        domain = email.group(1).lower()
        if domain in FREE_MAIL and claimed and claimed not in {"google", "microsoft", "apple"}:
            score += 40
            signals.append(f"claims to be {claimed_brand} but sends from free mailbox {domain}")
        elif claimed in BRAND_DOMAINS and _official_brand(domain) != claimed:
            score += 35
            signals.append(f"domain {domain} is not an official {claimed_brand} domain")
        dscore, dsignals = _domain_signals(domain)
        score += dscore
        signals += dsignals
        if _official_brand(domain):
            signals.append(f"sender domain belongs to {_official_brand(domain)}")
    elif re.fullmatch(r"[A-Z]{2}-[A-Z0-9]{5,6}(-[A-Z])?", sender.strip()):
        signals.append("registered business SMS sender ID (DLT header)")
    elif re.search(r"\d{7,}", sender):
        if claimed:
            score += 20
            signals.append(f"{claimed_brand} messages normally come from a short code or sender ID, not a personal number")
        if sender.strip().startswith("+") and not sender.strip().startswith(("+1", "+91", "+44")):
            score += 10
            signals.append("international number")
    elif sender.startswith("@"):
        handle = sender.lower()
        if claimed and claimed in handle and re.search(r"(support|help|official|team|giveaway|\d{2,})", handle):
            score += 30
            signals.append(f"handle imitates {claimed_brand} with filler words/digits")

    return {"sender": sender, "score": min(score, 100), "signals": signals}
