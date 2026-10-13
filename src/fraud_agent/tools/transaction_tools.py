from langchain.tools import tool

HIGH_RISK_COUNTRIES = {"NG", "RU", "KP", "IR"}


@tool
def score_transaction(amount: float, country: str, merchant_category: str, hour: int) -> dict:
    """Rule-based risk score for a single transaction.

    Args:
        amount: Transaction amount in USD.
        country: ISO-2 country code of the transaction.
        merchant_category: Merchant category, e.g. "electronics", "gift_cards".
        hour: Hour of day (0-23) the transaction happened.
    """
    score, signals = 0, []
    if amount > 5000:
        score += 40
        signals.append("amount > 5000")
    elif amount > 1000:
        score += 20
        signals.append("amount > 1000")
    if country.upper() in HIGH_RISK_COUNTRIES:
        score += 30
        signals.append(f"high-risk country {country}")
    if merchant_category.lower() in {"gift_cards", "crypto", "wire_transfer"}:
        score += 20
        signals.append(f"high-risk merchant category {merchant_category}")
    if 0 <= hour < 5:
        score += 10
        signals.append("unusual hour")
    return {"score": min(score, 100), "signals": signals}


@tool
def check_velocity(customer_id: str, txn_count_last_hour: int) -> dict:
    """Flag customers making many transactions in a short window.

    Args:
        customer_id: Customer identifier.
        txn_count_last_hour: Number of transactions by this customer in the last hour.
    """
    flagged = txn_count_last_hour >= 5
    return {"customer_id": customer_id, "flagged": flagged, "count": txn_count_last_hour}
