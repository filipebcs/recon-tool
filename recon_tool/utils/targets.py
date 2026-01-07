from pathlib import Path
from typing import List, Dict, Any


def _to_url(subdomain: str) -> str:
    return f"https://{subdomain}"


from typing import List, Dict, Any
from pathlib import Path

def export_targets(
    domain: str,
    risk_scoring: List[Dict[str, Any]],
    output_dir: Path,
) -> dict:
    """
    Export prioritized targets for pentesting tools.
    """
    output_dir.mkdir(exist_ok=True)

    safe_domain = domain.strip().lower().replace(".", "-")

    exports = {}

    # -------------------------------------------------
    # All targets (ordered by score)
    # -------------------------------------------------
    all_targets = [_to_url(item["subdomain"]) for item in risk_scoring]
    path_all = output_dir / f"targets-all-{safe_domain}.txt"
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
    path_critical = output_dir / f"targets-critical-{safe_domain}.txt"
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
    path_high = output_dir / f"targets-high-{safe_domain}.txt"
    path_high.write_text("\n".join(high), encoding="utf-8")
    exports["high"] = path_high

    # -------------------------------------------------
    # Top 10
    # -------------------------------------------------
    top10 = [_to_url(item["subdomain"]) for item in risk_scoring[:10]]
    path_top10 = output_dir / f"targets-top10-{safe_domain}.txt"
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
    path_login = output_dir / f"targets-login-{safe_domain}.txt"
    path_login.write_text("\n".join(login_targets), encoding="utf-8")
    exports["login"] = path_login

    return exports
