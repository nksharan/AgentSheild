import json
import re

from langchain.agents import create_agent
from langchain.chat_models import init_chat_model

from .config import MODEL, TEMPERATURE, TOOL_CALLING
from .prompts import SYSTEM_PROMPT
from .schemas import ScamAssessment
from .tools import TOOLS, analyze_url, check_sender, scan_text
from .tools.content_tools import BRAND_DOMAINS

SENDER_RE = re.compile(r"^[^\n:]*?\bfrom\s+(.+?)\s*:?\s*$", re.I | re.M)
PRECOMPUTED_NOTE = (
    "\n\n## Tool results\nThe tools have already been run for you; their results follow the "
    "content in the user message. Do not call tools — answer with the assessment only."
)


def _build_model():
    kwargs = {}
    if MODEL.startswith("ollama:"):
        # Local models: skip "thinking" output (slow on CPU) and raise Ollama's 4k default context.
        kwargs = {"reasoning": False, "num_ctx": 8192}
    return init_chat_model(MODEL, temperature=TEMPERATURE, **kwargs)


def build_agent():
    """Tool-calling agent, or (for models without reliable tool calling) a schema-constrained model."""
    model = _build_model()
    if TOOL_CALLING:
        return create_agent(model, tools=TOOLS, system_prompt=SYSTEM_PROMPT, response_format=ScamAssessment)
    return model.with_structured_output(ScamAssessment)


def gather_evidence(content: str) -> dict:
    """Run every tool up front, mirroring what the tool-calling agent would do."""
    text = scan_text.invoke({"text": content})
    evidence = {"scan_text": text, "analyze_url": [analyze_url.invoke({"url": u}) for u in text["urls"]]}

    if sender := SENDER_RE.search(content.split("\n", 1)[0]):
        squashed = re.sub(r"[^a-z]", "", content.lower())
        words = set(re.findall(r"[a-z]+", content.lower()))
        claimed = next((b for b in BRAND_DOMAINS if (b in squashed if len(b) >= 5 else b in words)), "")
        evidence["check_sender"] = check_sender.invoke({"sender": sender.group(1), "claimed_brand": claimed})
    return evidence


def assess(content: str, agent=None) -> ScamAssessment:
    """Assess one message/email/post/link and return the structured result."""
    agent = agent or build_agent()
    if TOOL_CALLING:
        result = agent.invoke({"messages": [{"role": "user", "content": content}]})
        return result["structured_response"]

    evidence = json.dumps(gather_evidence(content), ensure_ascii=False, indent=1)
    return agent.invoke([
        {"role": "system", "content": SYSTEM_PROMPT + PRECOMPUTED_NOTE},
        {"role": "user", "content": f"Content to assess:\n{content}\n\nTool results:\n{evidence}"},
    ])
