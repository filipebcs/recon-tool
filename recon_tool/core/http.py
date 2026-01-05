import requests
from typing import Dict, Any

from recon_tool.utils.logger import setup_logger

logger = setup_logger("http")


def http_recon(domain: str, scheme: str = "https") -> Dict[str, Any]:
    """
    Perform basic HTTP reconnaissance.
    """
    url = f"{scheme}://{domain}"
    result: Dict[str, Any] = {
        "url": url,
        "reachable": False,
        "status_code": None,
        "headers": {},
        "redirects": [],
        "error": None,
    }

    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True,
            verify=False,
        )

        result["reachable"] = True
        result["status_code"] = response.status_code
        result["headers"] = dict(response.headers)
        result["redirects"] = [r.url for r in response.history]

        logger.info(f"HTTP {response.status_code} on {url}")

    except requests.RequestException as exc:
        result["error"] = str(exc)
        logger.warning(f"HTTP recon failed for {url}: {exc}")

    return result
