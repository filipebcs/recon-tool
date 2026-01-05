from typing import Dict, Any, List

TECH_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cloudflare"],
    },
    "nginx": {
        "headers": ["nginx"],
    },
    "apache": {
        "headers": ["apache"],
    },
    "php": {
        "headers": ["x-powered-by: php"],
    },
    "java": {
        "headers": ["x-powered-by: servlet", "jsp"],
    },
    "tomcat": {
        "headers": ["apache-coyote"],
    },
    "grafana": {
        "headers": ["grafana"],
        "cookies": ["grafana_session"],
    },
    "jenkins": {
        "headers": ["x-jenkins"],
    },
}


def fingerprint_technologies_by_subdomain(
    http_by_subdomain: Dict[str, Dict[str, Any]]
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Fingerprint technologies per subdomain using HTTP headers/cookies.
    """
    results: Dict[str, List[Dict[str, Any]]] = {}

    for subdomain, http_info in http_by_subdomain.items():
        if not http_info.get("reachable"):
            continue

        headers = {
            k.lower(): v.lower()
            for k, v in http_info.get("headers", {}).items()
        }

        cookies = " ".join(
            http_info.get("headers", {}).get("Set-Cookie", "").lower()
        )

        detected = []

        for tech, sig in TECH_SIGNATURES.items():
            evidence = []

            # Header-based detection
            for h in sig.get("headers", []):
                if any(h in f"{k}:{v}" for k, v in headers.items()):
                    evidence.append("header")

            # Cookie-based detection
            for c in sig.get("cookies", []):
                if c in cookies:
                    evidence.append("cookie")

            if evidence:
                detected.append({
                    "technology": tech,
                    "evidence": list(set(evidence)),
                    "confidence": "medium" if len(evidence) > 1 else "low",
                })

        if detected:
            results[subdomain] = detected

    return results
