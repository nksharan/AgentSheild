import os

import pytest

from fraud_agent import config  # noqa: F401  loads .env
from fraud_agent.agent import build_agent

pytestmark = pytest.mark.skipif(
    not os.getenv("GOOGLE_API_KEY"), reason="GOOGLE_API_KEY not set"
)


def _ask(query: str):
    agent = build_agent()
    return agent.invoke({"messages": [{"role": "user", "content": query}]})["messages"]


def test_agent_flags_obvious_fraud():
    messages = _ask(
        "Customer C123 paid $7200 for gift_cards in country NG at hour 3. "
        "They made 6 transactions in the last hour. Is this fraud?"
    )
    tool_calls = [tc["name"] for m in messages for tc in getattr(m, "tool_calls", [])]
    assert "score_transaction" in tool_calls
    assert "FRAUD" in messages[-1].text.upper()


def test_agent_passes_normal_transaction():
    messages = _ask(
        "Customer C9 spent $40 on grocery in US at hour 14. "
        "They made 1 transaction in the last hour. Is this fraud?"
    )
    assert "LEGIT" in messages[-1].text.upper()
