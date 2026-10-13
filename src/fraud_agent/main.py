import sys

from .agent import assess

DEFAULT_QUERY = (
    "SMS from +44 7700 900123:\n"
    "Royal Mail: Your parcel could not be delivered. A £1.45 redelivery fee is due. "
    "Pay within 24 hours: https://royalmail-redelivery.xyz/pay"
)


def main() -> None:
    content = " ".join(sys.argv[1:]) or (sys.stdin.read() if not sys.stdin.isatty() else DEFAULT_QUERY)
    print(assess(content).model_dump_json(indent=2))


if __name__ == "__main__":
    main()
