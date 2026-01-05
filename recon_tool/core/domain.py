"""
domain.py
---------
Domain-level reconnaissance utilities.

Responsibilities:
- WHOIS lookup
- Domain to IP resolution
- ASN and organization lookup

All functions return structured dictionaries
to facilitate JSON export and later analysis.
"""

from __future__ import annotations

import socket
from typing import Dict, Any

import whois
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError


def resolve_ip(domain: str) -> str | None:
    """
    Resolve the main IPv4 address of a domain.

    :param domain: Domain name (e.g., example.com)
    :return: IPv4 address or None
    """
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def get_whois(domain: str) -> Dict[str, Any]:
    """
    Perform WHOIS lookup for a domain.

    :param domain: Domain name
    :return: Parsed WHOIS data
    """
    try:
        w = whois.whois(domain)
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "updated_date": str(w.updated_date),
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "org": w.org,
            "country": w.country,
        }
    except Exception as exc:
        return {
            "error": f"WHOIS lookup failed: {exc}"
        }


def get_asn_info(ip: str) -> Dict[str, Any]:
    """
    Retrieve ASN and organization data for an IP address.

    :param ip: IPv4 address
    :return: ASN information
    """
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()

        return {
            "asn": res.get("asn"),
            "asn_description": res.get("asn_description"),
            "asn_country_code": res.get("asn_country_code"),
            "network": {
                "name": res["network"].get("name"),
                "cidr": res["network"].get("cidr"),
                "country": res["network"].get("country"),
            }
        }

    except IPDefinedError:
        return {
            "error": "IP is private or reserved"
        }
    except Exception as exc:
        return {
            "error": f"ASN lookup failed: {exc}"
        }


def collect_domain_info(domain: str) -> Dict[str, Any]:
    """
    Orchestrates all domain-level reconnaissance steps.

    :param domain: Target domain
    :return: Consolidated domain information
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "ip": None,
        "whois": {},
        "asn": {},
    }

    ip = resolve_ip(domain)
    result["ip"] = ip

    result["whois"] = get_whois(domain)

    if ip:
        result["asn"] = get_asn_info(ip)

    return result
