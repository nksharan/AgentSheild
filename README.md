# AgentShield — Scam Detection Agent

LangChain agent that checks SMS, emails, chat messages, social-media posts and web links
for scams. It combines deterministic red-flag tools with a prompt built from real-world
scam campaigns and returns a structured verdict.

## Setup (Windows)
```powershell
.venv\Scripts\Activate.ps1
cp .env.example .env   # then add GOOGLE_API_KEY (from aistudio.google.com)
```

## Run
```powershell
python -m fraud_agent.main "SMS from +91 98XXXXXX21: Dear Customer, your SBI account will be blocked today. Update KYC: http://sbi-kyc-update.in.net"
Get-Content message.txt | python -m fraud_agent.main     # longer emails via stdin
python -m fraud_agent.evaluate                            # score on data/samples/eval_messages.jsonl
pytest
```

Output:
```json
{
  "verdict": "SCAM",
  "risk_score": 96,
  "scam_type": "bank_kyc_scam",
  "channel": "sms",
  "impersonated_entity": "State Bank of India",
  "red_flags": ["..."],
  "recommended_action": "..."
}
```

Prefix content with its source (`SMS from ...`, `Email from ...`, `Instagram DM from ...`)
so the agent can check the sender.

## How it works
- **Tools** (`tools/content_tools.py`), no network access:
  - `scan_text`: urgency, threats, OTP/KYC requests, gift-card/crypto/fee payments, job/prize lures, secrecy, remote-access apps; recognises protective wording like "never share your OTP".
  - `analyze_url`: brand lookalikes, typosquats (`paypa1`), IP hosts, shorteners, abused TLDs, punycode, credential-harvesting paths.
  - `check_sender`: free-mailbox brand impersonation, off-brand domains, personal numbers vs. registered SMS sender IDs (e.g. `VM-HDFCBK`), imposter handles.
- **Prompt** (`prompts.py`): a list of scam types, rules to avoid false positives, and few-shot examples (`examples.py`) taken from real campaigns: USPS/Royal Mail smishing, SBI KYC, Microsoft 365 phishing, task-job scams, crypto giveaways, "is this you" DMs, digital arrest, electricity disconnection, wrong-number openers, plus genuine OTP and order emails.
- **Structured output** (`schemas.py`): `ScamAssessment` via `create_agent(response_format=...)`.

## Growing the eval set
`data/samples/eval_messages.jsonl` is a held-out set (not used in the prompt). To test at
scale, convert public corpora to the same `{"id", "label", "content"}` format into `data/raw/`:
UCI SMS Spam Collection, the Nazario phishing email corpus, and PhishTank/OpenPhish URL feeds.
Keep few-shot examples and eval data separate so accuracy isn't inflated.

## Layout
```
src/fraud_agent/
  agent.py        # builds the agent; assess() returns ScamAssessment
  prompts.py      # system prompt + rendered few-shot examples
  examples.py     # real-world-style few-shot examples
  schemas.py      # structured output model
  evaluate.py     # accuracy on a labelled JSONL file
  main.py         # CLI entry point
  tools/          # scan_text, analyze_url, check_sender
data/samples/     # held-out eval set (committed)
data/raw, data/processed   # large datasets (git-ignored)
tests/            # pytest (agent tests skip without GOOGLE_API_KEY)
```
