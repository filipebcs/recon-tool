from typing import Dict, Any, Optional
import requests

from recon_tool.utils.logger import setup_logger

logger = setup_logger("http-subdomain")


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]


def _check_url(url: str, timeout: int = 6) -> Optional[Dict[str, Any]]:
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "recon-tool"},
        )

        headers = {k: v for k, v in resp.headers.items()}

        missing_headers = [
            h for h in SECURITY_HEADERS if h not in headers
        ]

        login_detected = any(
            x in resp.text.lower()
            for x in ["login", "sign in", "password"]
        )

        return {
            "url": url,
            "status": resp.status_code,
            "final_url": resp.url,
            "headers": headers,
            "missing_headers": missing_headers,
            "login_detected": login_detected,
        }

    except requests.RequestException:
        return None


def http_enrich_subdomain(subdomain: str) -> Dict[str, Any]:
    """
    Try HTTPS first, then HTTP.
    """
    https_url = f"https://{subdomain}"
    http_url = f"http://{subdomain}"

    https_result = _check_url(https_url)
    if https_result:
        logger.info(f"HTTPS OK: {subdomain}")
        return {"reachable": True, "scheme": "https", **https_result}

    http_result = _check_url(http_url)
    if http_result:
        logger.info(f"HTTP OK: {subdomain}")
        return {"reachable": True, "scheme": "http", **http_result}

    return {"reachable": False}
