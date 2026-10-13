from fraud_agent.tools import check_velocity, score_transaction


def test_high_risk_transaction_scores_high():
    out = score_transaction.invoke(
        {"amount": 7200, "country": "NG", "merchant_category": "gift_cards", "hour": 3}
    )
    assert out["score"] == 100


def test_normal_transaction_scores_zero():
    out = score_transaction.invoke(
        {"amount": 25, "country": "US", "merchant_category": "grocery", "hour": 14}
    )
    assert out["score"] == 0


def test_velocity_flag():
    assert check_velocity.invoke({"customer_id": "C1", "txn_count_last_hour": 6})["flagged"]
