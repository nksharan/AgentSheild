"""Score the agent on a labelled JSONL file: one {"id", "label", "content"} object per line.

    python -m fraud_agent.evaluate data/samples/eval_messages.jsonl
"""

import json
import sys
from collections import Counter
from pathlib import Path

from .agent import assess, build_agent

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "data" / "samples" / "eval_messages.jsonl"


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PATH
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    agent = build_agent()
    confusion, misses = Counter(), []

    for row in rows:
        result = assess(row["content"], agent)
        confusion[(row["label"], result.verdict)] += 1
        mark = "ok " if result.verdict == row["label"] else "XX "
        print(f"{mark}{row['id']:<5} expected={row['label']:<10} got={result.verdict:<10} risk={result.risk_score:>3} type={result.scam_type}")
        if result.verdict != row["label"]:
            misses.append((row["id"], result.red_flags))

    correct = sum(n for (exp, got), n in confusion.items() if exp == got)
    missed_scams = sum(n for (exp, got), n in confusion.items() if exp == "SCAM" and got == "SAFE")
    false_alarms = sum(n for (exp, got), n in confusion.items() if exp == "SAFE" and got == "SCAM")
    print(f"\naccuracy {correct}/{len(rows)}  scams marked SAFE: {missed_scams}  safe marked SCAM: {false_alarms}")
    for row_id, flags in misses:
        print(f"  {row_id}: {flags}")


if __name__ == "__main__":
    main()
