"""Few-shot examples modelled on real, widely reported scam campaigns.

Wording mirrors actual messages; numbers, names and links are made up.
Legitimate examples are included so the model learns what *not* to flag.
"""

FEW_SHOT_EXAMPLES = [
    {
        "input": "SMS from +1 (305) 555-0147:\nUSPS: Your package is on hold due to an incomplete address. "
                 "Update within 24 hours or it will be returned: https://usps-redelivery-info.top/track",
        "output": {
            "verdict": "SCAM", "risk_score": 95, "scam_type": "delivery_scam", "channel": "sms",
            "impersonated_entity": "USPS",
            "red_flags": ["link host usps-redelivery-info.top is not usps.com", ".top TLD is heavily abused",
                          "24-hour deadline", "sent from a personal 10-digit number"],
            "recommended_action": "Do not tap the link. Track parcels only at usps.com; forward the text to 7726 (SPAM).",
        },
    },
    {
        "input": "SMS from 98XXXXXX21:\nDear Customer, your SBI YONO account will be blocked today. "
                 "Please update your PAN/KYC immediately by clicking http://sbi-kyc-update.in.net/yono",
        "output": {
            "verdict": "SCAM", "risk_score": 96, "scam_type": "bank_kyc_scam", "channel": "sms",
            "impersonated_entity": "State Bank of India",
            "red_flags": ["KYC/PAN update request via link", "account blocking threat with same-day deadline",
                          "domain sbi-kyc-update.in.net is not an official SBI domain", "personal mobile number, not a bank sender ID"],
            "recommended_action": "Ignore the link. Banks never ask for KYC through SMS links; report at cybercrime.gov.in or call 1930.",
        },
    },
    {
        "input": "Email from \"Microsoft 365\" <no-reply@micros0ft-office-support.com>\nSubject: Password expires today\n"
                 "Your Office 365 password expires today. Keep your current password: https://micros0ft-office-support.com/login",
        "output": {
            "verdict": "SCAM", "risk_score": 94, "scam_type": "phishing", "channel": "email",
            "impersonated_entity": "Microsoft",
            "red_flags": ["sender and link use typosquat domain micros0ft-office-support.com",
                          "password-expiry pretext with same-day deadline", "login page on a non-Microsoft domain"],
            "recommended_action": "Do not sign in. Report as phishing and check account status directly at account.microsoft.com.",
        },
    },
    {
        "input": "WhatsApp from +62 812 5550 1932:\nHello! I'm Priya from a digital marketing agency. Part-time job: like YouTube "
                 "videos and earn Rs 150 per task, 3000-5000 daily income. Contact our receptionist on Telegram @HR_Ananya_Work",
        "output": {
            "verdict": "SCAM", "risk_score": 92, "scam_type": "job_task_scam", "channel": "chat",
            "impersonated_entity": None,
            "red_flags": ["unsolicited part-time job offer", "pay-per-like task model", "unrealistic daily income",
                          "moves conversation to Telegram", "international number"],
            "recommended_action": "Block and report. These 'task' jobs pay small amounts first, then demand deposits you never get back.",
        },
    },
    {
        "input": "X (Twitter) post by @ElonMusk_Giveaway_2026:\nTo celebrate, I'm giving back 5,000 BTC! Send 0.1-20 BTC to the "
                 "address below and I will DOUBLE YOUR BTC instantly. Event ends tonight! https://tesla-btc-event.live",
        "output": {
            "verdict": "SCAM", "risk_score": 99, "scam_type": "investment_crypto_scam", "channel": "social_media",
            "impersonated_entity": "Elon Musk / Tesla",
            "red_flags": ["'send crypto and get double back' giveaway", "impersonation handle with filler words and digits",
                          "deadline 'tonight'", ".live domain unrelated to Tesla"],
            "recommended_action": "Do not send anything. Crypto transfers are irreversible; report the account.",
        },
    },
    {
        "input": "Instagram DM from a friend's account:\nOMG is this you in this video?? 😳 bit.ly/3xVd8kQ",
        "output": {
            "verdict": "SCAM", "risk_score": 85, "scam_type": "account_takeover", "channel": "social_media",
            "impersonated_entity": "a friend (compromised account)",
            "red_flags": ["classic 'is this you in this video' lure", "shortened link hides destination",
                          "out-of-character message from a known contact"],
            "recommended_action": "Do not open the link; it usually leads to a fake login page. Tell your friend via another channel.",
        },
    },
    {
        "input": "Phone call followed by WhatsApp from +91 7XXXXXX310 (profile photo: police logo):\nThis is Mumbai Cyber Crime. A FedEx parcel "
                 "in your name contains narcotics and fake passports. You are under digital arrest. Do not disconnect "
                 "the video call and don't tell your family. Transfer funds to RBI verification account for clearance.",
        "output": {
            "verdict": "SCAM", "risk_score": 99, "scam_type": "government_impersonation", "channel": "chat",
            "impersonated_entity": "Police / FedEx / RBI",
            "red_flags": ["'digital arrest' does not exist in Indian law", "narcotics-in-parcel pretext",
                          "demands secrecy and continuous video call", "asks to transfer money for 'verification'"],
            "recommended_action": "Hang up. No agency arrests over video call or asks for money; call 1930 or report at cybercrime.gov.in.",
        },
    },
    {
        "input": "SMS from VM-HDFCBK:\n123456 is your OTP for txn of INR 2,499.00 at AMAZON on HDFC Bank card xx4321. "
                 "Valid for 10 mins. Do not share OTP with anyone. If not you, call the number on the back of your card.",
        "output": {
            "verdict": "SAFE", "risk_score": 8, "scam_type": "none", "channel": "sms",
            "impersonated_entity": None,
            "red_flags": [],
            "recommended_action": "Genuine bank OTP format from a registered sender ID. Use it only if you started this payment; never read it out to a caller.",
        },
    },
    {
        "input": "Email from \"Amazon.in\" <shipment-tracking@amazon.in>\nSubject: Your Amazon.in order #408-1234567-1234567 has shipped\n"
                 "Hello Rahul, your package will arrive Thursday. Track it in Your Orders: https://www.amazon.in/gp/your-account/order-history",
        "output": {
            "verdict": "SAFE", "risk_score": 5, "scam_type": "none", "channel": "email",
            "impersonated_entity": None,
            "red_flags": [],
            "recommended_action": "Looks genuine: official amazon.in sender and link, no payment or credential request.",
        },
    },
    {
        "input": "SMS from +1 (929) 555-0188:\nHi Emma, it's Linda. Are we still on for golf this Saturday?",
        "output": {
            "verdict": "SUSPICIOUS", "risk_score": 45, "scam_type": "pig_butchering", "channel": "sms",
            "impersonated_entity": None,
            "red_flags": ["'wrong number' opener from an unknown contact, a common start of long-con investment scams"],
            "recommended_action": "If you don't know them, don't reply. If they keep chatting and later mention crypto or trading, it's a scam.",
        },
    },
    {
        "input": "SMS from +91 8XXXXXX455:\nDear Consumer, your electricity power will be disconnected tonight at 9:30 PM "
                 "because your previous month bill was not updated. Please immediately contact our electricity officer 9876500000.",
        "output": {
            "verdict": "SCAM", "risk_score": 93, "scam_type": "government_impersonation", "channel": "sms",
            "impersonated_entity": "Electricity board",
            "red_flags": ["disconnection threat 'tonight'", "asks to call a personal mobile 'officer'",
                          "no consumer number or official sender ID"],
            "recommended_action": "Don't call the number; scammers ask you to install remote-access apps. Check dues on your utility's official app.",
        },
    },
]
