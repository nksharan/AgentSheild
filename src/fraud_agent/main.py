import json
import sys

from .agent import assess

DEFAULT_TEXT = (
    "SMS from +91 98XXXXXX21: Dear Customer, your SBI account will be blocked today. "
    "Update KYC: http://sbi-kyc-update.in.net"
)


def main() -> None:
    content = " ".join(sys.argv[1:]) or DEFAULT_TEXT
    result = assess(content)
    print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
