from pathlib import Path
from typing import List, Dict, Any


def _to_url(subdomain: str) -> str:
    return f"https://{subdomain}"


def export_targets(
    risk_scoring: List[Dict[str, Any]],
    output_dir: Path,
) -> dict:
    """
    Export prioritized targets for pentesting tools.
    """
    output_dir.mkdir(exist_ok=True)

    exports = {}

    # -------------------------------------------------
    # All targets (ordered by score)
    # -------------------------------------------------
    all_targets = [_to_url(item["subdomain"]) for item in risk_scoring]
    path_all = output_dir / "targets-all.txt"
    path_all.write_text("\n".join(all_targets), encoding="utf-8")
    exports["all"] = path_all

    # -------------------------------------------------
    # Critical only
    # -------------------------------------------------
    critical = [
        _to_url(item["subdomain"])
        for item in risk_scoring
        if item.get("level") == "CRITICAL"
    ]
    path_critical = output_dir / "targets-critical.txt"
    path_critical.write_text("\n".join(critical), encoding="utf-8")
    exports["critical"] = path_critical

    # -------------------------------------------------
    # High only
    # -------------------------------------------------
    high = [
        _to_url(item["subdomain"])
        for item in risk_scoring
        if item.get("level") == "HIGH"
    ]
    path_high = output_dir / "targets-high.txt"
    path_high.write_text("\n".join(high), encoding="utf-8")
    exports["high"] = path_high

    # -------------------------------------------------
    # Top 10
    # -------------------------------------------------
    top10 = [_to_url(item["subdomain"]) for item in risk_scoring[:10]]
    path_top10 = output_dir / "targets-top10.txt"
    path_top10.write_text("\n".join(top10), encoding="utf-8")
    exports["top10"] = path_top10

    # -------------------------------------------------
    # Targets with login detected
    # -------------------------------------------------
    login_targets = [
        _to_url(item["subdomain"])
        for item in risk_scoring
        if "login_detected" in item.get("signals", [])
    ]

    path_login = output_dir / "targets-login.txt"
    path_login.write_text("\n".join(login_targets), encoding="utf-8")
    exports["login"] = path_login
    
    return exports
