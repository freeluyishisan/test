from backend.app.strategy.edge import decide_yes_no


def test_strong_yes_candidate() -> None:
    decision = decide_yes_no(model_yes_probability=0.68, yes_market_price=0.51)
    assert decision.edge == 0.17
    assert decision.action == "BUY_YES_CANDIDATE"
    assert decision.suggested_size_usdc > 0


def test_no_trade_when_edge_small() -> None:
    decision = decide_yes_no(model_yes_probability=0.56, yes_market_price=0.53)
    assert decision.action == "NO_TRADE"
    assert decision.suggested_size_usdc == 0


def test_reverse_candidate() -> None:
    decision = decide_yes_no(model_yes_probability=0.35, yes_market_price=0.50)
    assert decision.action == "BUY_NO_CANDIDATE"
