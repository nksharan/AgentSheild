import sys

from .agent import build_agent

DEFAULT_QUERY = (
    "Customer C123 paid $7200 for gift_cards in country NG at hour 3. "
    "They made 6 transactions in the last hour. Is this fraud?"
)


def main() -> None:
    query = " ".join(sys.argv[1:]) or DEFAULT_QUERY
    agent = build_agent()
    result = agent.invoke({"messages": [{"role": "user", "content": query}]})
    print(result["messages"][-1].content)


if __name__ == "__main__":
    main()
