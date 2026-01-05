from typing import List, Set

import requests
import ipaddress

from recon_tool.core.shodan import get_shodan_client
from recon_tool.core.shodan import shodan_host_lookup
from recon_tool.utils.logger import setup_logger


logger = setup_logger("passive-subdomains")


def passive_from_shodan(ip: str, domain: str) -> List[str]:
    """
    Extract subdomains from Shodan host data.
    """
    results: Set[str] = set()

    shodan_data = shodan_host_lookup(ip)

    if not shodan_data.get("found"):
        return []

    hostnames = shodan_data.get("data", {}).get("hostnames", [])

    for hostname in hostnames:
        hostname = hostname.lower().strip()
        if hostname.endswith(domain):
            results.add(hostname)

    if results:
        logger.info(f"Found {len(results)} passive subdomains via Shodan")

    return sorted(results)


def passive_from_dns_records(dns_info: dict, domain: str) -> List[str]:
    """
    Extract subdomains from DNS records (NS, MX).
    """
    results: Set[str] = set()

    records = dns_info.get("records", {})

    for record_type in ["NS", "MX"]:
        for entry in records.get(record_type, []):
            entry = entry.lower().strip().rstrip(".")
            if entry.endswith(domain):
                results.add(entry)

    if results:
        logger.info(f"Found {len(results)} passive subdomains via DNS records")

    return sorted(results)


def passive_from_ct_logs(domain: str) -> list[str]:
    """
    Extract subdomains from Certificate Transparency logs via crt.sh
    """
    results: set[str] = set()

    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return []

        data = response.json()

        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.lower().strip()
                name = name.lstrip("*.")  # remove wildcard
                if name.endswith(domain):
                    results.add(name)

        if results:
            logger.info(f"Found {len(results)} passive subdomains via CT logs")

    except Exception as exc:
        logger.warning(f"CT logs enumeration failed: {exc}")

    return sorted(results)


def passive_from_cidr(cidr: str, domain: str, limit: int = 100) -> list[str]:
    """
    Enumerate subdomains by searching hosts inside a CIDR block via Shodan.
    """
    results: set[str] = set()

    try:
        # Validate CIDR
        ipaddress.ip_network(cidr, strict=False)

        client = get_shodan_client()
        query = f"net:{cidr} hostname:{domain}"

        search = client.search(query, limit=limit)

        for match in search.get("matches", []):
            for hostname in match.get("hostnames", []):
                hostname = hostname.lower().strip()
                if hostname.endswith(domain):
                    results.add(hostname)

        if results:
            logger.info(f"Found {len(results)} passive subdomains via CIDR {cidr}")

    except Exception as exc:
        logger.warning(f"CIDR enumeration failed ({cidr}): {exc}")

    return sorted(results)


def passive_from_asn(asn: str, domain: str, limit: int = 100) -> list[str]:
    """
    Enumerate subdomains from the same ASN using Shodan search.
    """
    results: set[str] = set()

    try:
        client = get_shodan_client()
        query = f"asn:{asn} hostname:{domain}"

        search = client.search(query, limit=limit)

        for match in search.get("matches", []):
            for hostname in match.get("hostnames", []):
                hostname = hostname.lower().strip()
                if hostname.endswith(domain):
                    results.add(hostname)

        if results:
            logger.info(f"Found {len(results)} passive subdomains via ASN {asn}")

    except Exception as exc:
        logger.warning(f"ASN enumeration failed ({asn}): {exc}")

    return sorted(results)


def collect_passive_subdomains(
    domain: str,
    ip: str | None,
    dns_info: dict,
    asn_info: dict | None = None,
) -> list[str]:
    results: set[str] = set()

    # Shodan hostnames
    if ip:
        results.update(passive_from_shodan(ip, domain))

    # DNS records
    results.update(passive_from_dns_records(dns_info, domain))

    # CT logs
    results.update(passive_from_ct_logs(domain))

    # ASN-wide enumeration
    if asn_info and asn_info.get("asn"):
        results.update(passive_from_asn(asn_info["asn"], domain))

    # CIDR enumeration (NEW)
    if asn_info and asn_info.get("network", {}).get("cidr"):
        results.update(
            passive_from_cidr(
                asn_info["network"]["cidr"],
                domain,
            )
        )

    return sorted(results)

