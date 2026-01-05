"""
dns.py
------
DNS-level reconnaissance utilities.

Responsibilities:
- Retrieve common DNS records (A, AAAA, MX, NS, TXT)
- Attempt zone transfer (AXFR)
"""

from __future__ import annotations

from typing import Dict, Any, List

import dns.resolver
import dns.query
import dns.zone
import dns.exception


def _query_record(domain: str, record_type: str) -> List[str]:
    """
    Generic DNS query helper using explicit resolvers.
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [
        "8.8.8.8",     # Google
        "1.1.1.1",     # Cloudflare
        "9.9.9.9",     # Quad9
    ]
    resolver.timeout = 3
    resolver.lifetime = 5

    try:
        answers = resolver.resolve(domain, record_type)
        return [str(rdata).strip() for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return []



def get_basic_records(domain: str) -> Dict[str, Any]:
    """
    Retrieve common DNS records for a domain.
    """
    return {
        "A": _query_record(domain, "A"),
        "AAAA": _query_record(domain, "AAAA"),
        "MX": _query_record(domain, "MX"),
        "NS": _query_record(domain, "NS"),
        "TXT": _query_record(domain, "TXT"),
    }


def attempt_zone_transfer(domain: str, nameservers: List[str]) -> Dict[str, Any]:
    """
    Attempt DNS zone transfer (AXFR) against given name servers.
    """
    results: Dict[str, Any] = {}

    for ns in nameservers:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            results[ns] = [str(name) for name in zone.nodes.keys()]
        except Exception:
            results[ns] = "Zone transfer failed"

    return results


def collect_dns_info(domain: str) -> Dict[str, Any]:
    """
    Orchestrates DNS reconnaissance.
    """
    result: Dict[str, Any] = {
        "records": {},
        "zone_transfer": {},
    }

    records = get_basic_records(domain)
    result["records"] = records

    nameservers = records.get("NS", [])
    if nameservers:
        result["zone_transfer"] = attempt_zone_transfer(domain, nameservers)

    return result
