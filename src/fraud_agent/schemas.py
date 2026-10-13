from typing import Literal

from pydantic import BaseModel, Field

ScamType = Literal[
    "none",
    "phishing",
    "delivery_scam",
    "bank_kyc_scam",
    "tech_support_scam",
    "government_impersonation",
    "job_task_scam",
    "investment_crypto_scam",
    "pig_butchering",
    "romance_scam",
    "prize_lottery_scam",
    "account_takeover",
    "marketplace_scam",
    "other",
]


class ScamAssessment(BaseModel):
    verdict: Literal["SAFE", "SUSPICIOUS", "SCAM"]
    risk_score: int = Field(ge=0, le=100)
    scam_type: ScamType
    channel: Literal["sms", "email", "social_media", "chat", "web_link", "unknown"]
    impersonated_entity: str | None = Field(None, description="Brand, agency or person being imitated, if any.")
    red_flags: list[str] = Field(description="Concrete evidence, each traceable to the content or a tool result.")
    recommended_action: str = Field(description="One or two sentences telling the recipient what to do.")
