from typing import List

import dns.resolver
import random
import string


from recon_tool.utils.concurrency import run_parallel
from recon_tool.utils.logger import setup_logger

logger = setup_logger("subdomains")


def detect_dns_wildcard(domain: str) -> set[str]:
    """
    Detect DNS wildcard by resolving random subdomains.
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

    wildcard_ips: set[str] = set()

    for _ in range(3):
        random_label = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=12)
        )
        test_domain = f"{random_label}.{domain}"

        try:
            answers = resolver.resolve(test_domain, "A")
            for rdata in answers:
                wildcard_ips.add(rdata.to_text())
        except Exception:
            pass

    if wildcard_ips:
        logger.info(f"DNS wildcard detected for {domain}: {wildcard_ips}")

    return wildcard_ips



def _resolve_subdomain(subdomain: str, wildcard_ips: set[str]) -> str | None:
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = 3
        resolver.lifetime = 5

        answers = resolver.resolve(subdomain, "A")

        ips = {r.to_text() for r in answers}

        if wildcard_ips and ips.issubset(wildcard_ips):
            return None  # wildcard false positive

        return subdomain
    except Exception:
        return None


def enumerate_subdomains(
    domain: str,
    wordlist: list[str],
    max_workers: int = 10,
) -> list[str]:
    """
    Enumerate subdomains using DNS resolution.
    """
    wildcard_ips = detect_dns_wildcard(domain)
    
    targets = [f"{word}.{domain}" for word in wordlist]

    results = run_parallel(
        lambda sub: _resolve_subdomain(sub, wildcard_ips),
        targets,
        max_workers=max_workers,
    )

    found = [r for r in results if r]

    logger.info(f"Found {len(found)} active subdomains (after wildcard filtering)")

    return found
