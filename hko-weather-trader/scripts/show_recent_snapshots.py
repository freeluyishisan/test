from backend.app.db.sqlite_store import load_recent_snapshots


def main() -> None:
    rows = load_recent_snapshots("hk_hko_daily_high", hours=24)
    print(f"recent snapshots: {len(rows)}")
    for row in rows[-30:]:
        print(
            f"#{row['id']} {row['observed_at']} "
            f"temp={row['current_temp_c']} high={row['today_high_c']} "
            f"s10={row['recent_slope_10m']} s30={row['recent_slope_30m']} s60={row['recent_slope_60m']}"
        )


if __name__ == "__main__":
    main()
