from langchain.agents import create_agent
from langchain.chat_models import init_chat_model

from .config import MODEL, TEMPERATURE
from .prompts import SYSTEM_PROMPT
from .tools import TOOLS


def build_agent():
    model = init_chat_model(MODEL, temperature=TEMPERATURE)
    return create_agent(model, tools=TOOLS, system_prompt=SYSTEM_PROMPT)
