from typing import Literal

from pydantic import BaseModel, Field


class ScamAssessment(BaseModel):
    verdict: Literal["SAFE", "SUSPICIOUS", "SCAM"]
    risk_score: int = Field(ge=0, le=100)
    scam_type: str
    channel: str
    impersonated_entity: str | None = None
    red_flags: list[str] = Field(default_factory=list)
    recommended_action: str
