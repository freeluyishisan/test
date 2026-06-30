from dataclasses import dataclass


@dataclass(frozen=True)
class EdgeDecision:
    model_probability: float
    market_price: float
    edge: float
    level: str
    action: str
    suggested_size_usdc: float
    reason: str


def clamp_probability(value: float) -> float:
    return max(0.01, min(0.99, value))


def calculate_edge(model_probability: float, market_price: float) -> float:
    return clamp_probability(model_probability) - clamp_probability(market_price)


def suggested_size(bankroll_usdc: float, edge: float, max_trade_size_usdc: float) -> float:
    """Conservative first version. Not full Kelly."""
    if edge < 0.08:
        return 0.0
    raw_size = bankroll_usdc * min(edge * 0.5, 0.02)
    return round(min(raw_size, max_trade_size_usdc), 2)


def decide_yes_no(
    *,
    model_yes_probability: float,
    yes_market_price: float,
    bankroll_usdc: float = 1000.0,
    min_edge: float = 0.08,
    strong_edge: float = 0.12,
    max_trade_size_usdc: float = 20.0,
) -> EdgeDecision:
    edge = calculate_edge(model_yes_probability, yes_market_price)

    if edge >= strong_edge:
        level = "strong"
        action = "BUY_YES_CANDIDATE"
    elif edge >= min_edge:
        level = "candidate"
        action = "SMALL_BUY_YES_CANDIDATE"
    elif edge <= -strong_edge:
        level = "strong_reverse"
        action = "BUY_NO_CANDIDATE"
    elif edge <= -min_edge:
        level = "reverse_candidate"
        action = "SMALL_BUY_NO_CANDIDATE"
    else:
        level = "watch"
        action = "NO_TRADE"

    size = suggested_size(bankroll_usdc, abs(edge), max_trade_size_usdc)
    if action == "NO_TRADE":
        size = 0.0

    return EdgeDecision(
        model_probability=clamp_probability(model_yes_probability),
        market_price=clamp_probability(yes_market_price),
        edge=round(edge, 4),
        level=level,
        action=action,
        suggested_size_usdc=size,
        reason=f"model={model_yes_probability:.1%}, market={yes_market_price:.1%}, edge={edge:+.1%}",
    )
