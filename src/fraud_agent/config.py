import os

from dotenv import load_dotenv

load_dotenv()

MODEL = os.getenv("MODEL", "ollama:qwen3:4b")
TEMPERATURE = float(os.getenv("TEMPERATURE", "0"))
# Small local models often can't do native tool calls; with this off, tools run in Python
# first and the model only produces the structured verdict. Set TOOL_CALLING=1 for models
# that support it (Gemini, qwen3, llama3.1).
TOOL_CALLING = os.getenv("TOOL_CALLING", "0" if MODEL.startswith("ollama:") else "1") == "1"
