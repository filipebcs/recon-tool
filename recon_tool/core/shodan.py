import os
from typing import Dict, Any

import shodan

from recon_tool.utils.logger import setup_logger

logger = setup_logger("shodan")


def get_shodan_client() -> shodan.Shodan:
    """
    Initialize Shodan client using API key from environment.
    """
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise RuntimeError("SHODAN_API_KEY not set in environment")

    return shodan.Shodan(api_key)


def shodan_host_lookup(ip: str) -> Dict[str, Any]:
    """
    Query Shodan for host information by IP.
    """
    result: Dict[str, Any] = {
        "ip": ip,
        "found": False,
        "data": {},
        "error": None,
    }

    try:
        client = get_shodan_client()
        host = client.host(ip)

        result["found"] = True
        result["data"] = {
            "organization": host.get("org"),
            "isp": host.get("isp"),
            "country": host.get("country_name"),
            "asn": host.get("asn"),
            "os": host.get("os"),
            "ports": host.get("ports"),
            "hostnames": host.get("hostnames"),
            "tags": host.get("tags"),
            "vulns": list(host.get("vulns", [])),
            "services": [
                {
                    "port": s.get("port"),
                    "transport": s.get("transport"),
                    "product": s.get("product"),
                    "version": s.get("version"),
                    "banner": s.get("banner"),
                }
                for s in host.get("data", [])
            ],
        }

        logger.info(f"Shodan data found for {ip}")

    except shodan.exception.APIError as exc:
        result["error"] = str(exc)
        logger.warning(f"Shodan API error for {ip}: {exc}")

    except Exception as exc:
        result["error"] = str(exc)
        logger.error(f"Unexpected Shodan error for {ip}: {exc}")

    return result
