from typing import Dict, Any, List


SENSITIVE_KEYWORDS = {
    "admin": 30,
    "vpn": 30,
    "internal": 30,
    "dev": 20,
    "test": 20,
    "stage": 20,
    "staging": 20,
    "old": 15,
    "legacy": 15,
    "beta": 15,
}

SENSITIVE_TECH = {
    "jenkins": 25,
    "kibana": 25,
    "grafana": 25,
    "tomcat": 25,
    "php": 10,
    "java": 10,
}


def score_subdomain(
    subdomain: str,
    origin: str,
    http_info: Dict[str, Any],
    technologies: List[Dict[str, Any]],
    shodan_info: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Calculate risk score for a single subdomain.
    """
    score = 0
    signals: List[str] = []

    name = subdomain.lower()

    # -------------------------------------------------
    # Name-based signals
    # -------------------------------------------------
    for keyword, points in SENSITIVE_KEYWORDS.items():
        if keyword in name:
            score += points
            signals.append(f"keyword:{keyword}")

    # -------------------------------------------------
    # Origin
    # -------------------------------------------------
    if origin == "passive":
        score += 15
        signals.append("passive_discovery")
    else:
        score += 5
        signals.append("active_discovery")

    # -------------------------------------------------
    # HTTP exposure
    # -------------------------------------------------
    if http_info.get("reachable"):
        score += 10
        signals.append("http_reachable")

    # -------------------------------------------------
    # Technology fingerprint
    # -------------------------------------------------
    for tech in technologies:
        name = tech.get("technology", "").lower()
        confidence = tech.get("confidence", "low")

        if name in SENSITIVE_TECH:
            points = SENSITIVE_TECH[name]

            # confidence-aware scoring
            if confidence == "medium":
                points += 5
            elif confidence == "high":
                points += 10

            score += points
            signals.append(f"tech:{name}")

    # -------------------------------------------------
    # Shodan signals
    # -------------------------------------------------
    if shodan_info.get("found"):
        ports = shodan_info.get("data", {}).get("ports", [])
        if any(p > 1024 for p in ports):
            score += 10
            signals.append("high_ports_open")

    # -------------------------------------------------
    # Normalize
    # -------------------------------------------------
    score = min(score, 100)

    # -------------------------------------------------
    # Risk level
    # -------------------------------------------------
    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "subdomain": subdomain,
        "score": score,
        "level": level,
        "signals": signals,
    }
