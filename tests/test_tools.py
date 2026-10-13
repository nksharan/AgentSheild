from fraud_agent.tools import analyze_url, check_sender, scan_text


def test_brand_lookalike_url_scores_high():
    out = analyze_url.invoke({"url": "https://usps-redelivery-info.top/track"})
    assert out["score"] >= 50
    assert any("usps" in s for s in out["signals"])


def test_typosquat_url_detected():
    out = analyze_url.invoke({"url": "http://paypa1-resolution.com/secure/verify"})
    assert any("typosquat" in s for s in out["signals"])


def test_ip_host_url_flagged():
    out = analyze_url.invoke({"url": "http://192.168.44.10/netflix/login"})
    assert any("IP address" in s for s in out["signals"])


def test_official_url_is_clean():
    out = analyze_url.invoke({"url": "https://www.amazon.in/gp/your-account/order-history"})
    assert out["score"] == 0
    assert out["official_brand"] == "amazon"


def test_short_brand_name_does_not_match_inside_words():
    out = analyze_url.invoke({"url": "https://groups.example.org/startups"})
    assert not any("ups" in s for s in out["signals"])


def test_scam_text_flags_categories_and_extracts_links():
    out = scan_text.invoke({"text": "Dear Customer, your account will be blocked today. Update your KYC immediately: "
                                    "http://sbi-kyc-update.in.net/yono"})
    assert {"urgency", "account_threat", "credential_or_otp_request"} <= out["red_flags"].keys()
    assert out["urls"] == ["http://sbi-kyc-update.in.net/yono"]


def test_genuine_otp_text_scores_low():
    out = scan_text.invoke({"text": "123456 is your OTP for txn of INR 499 at AMAZON. Do not share OTP with anyone."})
    assert out["protective_language"]
    assert out["score"] < 35


def test_brand_from_free_mailbox_flagged():
    out = check_sender.invoke({"sender": "irs-refund-notice@gmail.com", "claimed_brand": "IRS"})
    assert out["score"] >= 40


def test_official_sender_is_clean():
    out = check_sender.invoke({"sender": "Amazon.in <shipment-tracking@amazon.in>", "claimed_brand": "amazon"})
    assert out["score"] == 0


def test_dlt_sender_id_recognised():
    out = check_sender.invoke({"sender": "VM-HDFCBK", "claimed_brand": "hdfc"})
    assert out["score"] == 0
