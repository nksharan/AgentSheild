import json
import os
from pathlib import Path

import pytest

from fraud_agent.agent import assess, build_agent
from fraud_agent.config import MODEL

pytestmark = pytest.mark.skipif(
    MODEL.startswith("google_genai:") and not os.getenv("GOOGLE_API_KEY"), reason="GOOGLE_API_KEY not set"
)

EVAL_FILE = Path(__file__).resolve().parents[1] / "data" / "samples" / "eval_messages.jsonl"
# Clear-cut cases only; the full set is scored with `python -m fraud_agent.evaluate`.
CASES = [json.loads(line) for line in EVAL_FILE.read_text(encoding="utf-8").splitlines()
         if line.strip() and json.loads(line)["id"] in {"e02", "e04", "e07", "s01", "s02"}]


@pytest.fixture(scope="module")
def agent():
    return build_agent()


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_agent_verdict(agent, case):
    assert assess(case["content"], agent).verdict == case["label"]
