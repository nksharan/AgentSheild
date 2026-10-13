# Fraud Detection Agent

LangChain agent that assesses transactions for fraud using tool calls.

## Setup (Windows)
```powershell
.venv\Scripts\Activate.ps1
cp .env.example .env   # then add GOOGLE_API_KEY (from aistudio.google.com)
```

## Run
```powershell
python -m fraud_agent.main "Customer C9 spent $40 on grocery in US at hour 14"
pytest
```

## Layout
```
src/fraud_agent/
  agent.py        # builds the agent (create_agent)
  config.py       # env-driven settings
  prompts.py      # system prompt
  main.py         # CLI entry point
  tools/          # @tool functions the agent can call
data/raw, data/processed   # datasets (git-ignored)
notebooks/                 # exploration
tests/                     # pytest
```
