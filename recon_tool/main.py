"""
main.py
-------
Entry point for the reconnaissance tool.

Responsibilities:
- Load environment variables
- Parse CLI arguments
- Orchestrate recon modules
- Save consolidated JSON output
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

from dotenv import load_dotenv

from recon_tool.core.domain import collect_domain_info
from recon_tool.core.dns import collect_dns_info
from recon_tool.core.subdomains import enumerate_subdomains
from recon_tool.core.http import http_recon
from recon_tool.core.tech import fingerprint_technologies_by_subdomain
from recon_tool.core.shodan import shodan_host_lookup
from recon_tool.core.passive_subdomains import collect_passive_subdomains
from recon_tool.core.scoring import score_subdomain
from recon_tool.core.http_subdomain import http_enrich_subdomain

from recon_tool.utils.wordlist import load_wordlist
from recon_tool.utils.targets import export_targets
from recon_tool.utils.naming import normalize_domain
from recon_tool.utils.concurrency import run_parallel
from recon_tool.utils.validators import is_valid_hostname
from recon_tool.utils.logger import setup_logger

from recon_tool.report.markdown import generate_markdown_report
from recon_tool.report.html import generate_html_report


# ---------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BASE_DIR / ".env")  # Load .env if present

logger = setup_logger("main")

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Domain reconnaissance tool for pentesting"
    )

    parser.add_argument(
        "--domain",
        required=True,
        help="Target domain (e.g. example.com)",
    )

    parser.add_argument(
        "--wordlist",
        nargs="*",
        default=["www", "mail", "api", "dev", "test", "admin"],
        help="Subdomain wordlist",
    )
    
    parser.add_argument(
        "--subdomain-wordlist",
        action="append",
        help="Path to subdomain wordlist file (can be used multiple times)",
    )

    parser.add_argument(
        "--subdomain-workers",
        type=int,
        default=10,
        help="Number of threads for subdomain enumeration",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------

def run_recon(args: argparse.Namespace) -> dict:
    domain = args.domain
    logger.info(f"Starting recon for domain: {domain}")

    result: dict = {
        "target": domain,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "domain": {},
        "dns": {},
        "passive_subdomains": [],
        "subdomains": [],
        "http": {},
        "technologies": [],
        "shodan": {},
    }

    # -----------------------------------------------------------------
    # Domain / ASN / WHOIS
    # -----------------------------------------------------------------
    result["domain"] = collect_domain_info(domain)

    # -----------------------------------------------------------------
    # DNS
    # -----------------------------------------------------------------
    result["dns"] = collect_dns_info(domain)

    # -----------------------------------------------------------------
    # Passive subdomain enumeration (NEW)
    # -----------------------------------------------------------------
    result["passive_subdomains"] = collect_passive_subdomains(
        domain=domain,
        ip=result["domain"].get("ip"),
        dns_info=result["dns"],
        asn_info=result["domain"].get("asn"),
    )

    # -----------------------------------------------------------------
    # Active subdomain enumeration (bruteforce)
    # -----------------------------------------------------------------
    subdomain_words = set(args.wordlist)

    if args.subdomain_wordlist:
        for wl in args.subdomain_wordlist:
            subdomain_words.update(load_wordlist(wl))

    active_subdomains = enumerate_subdomains(
        domain,
        sorted(subdomain_words),
        max_workers=args.subdomain_workers,
    )

    # Merge passive + active (deduplicated + validated)
    merged_subdomains = set(result["passive_subdomains"]) | set(active_subdomains)

    result["subdomains"] = [
        s for s in merged_subdomains
        if is_valid_hostname(s)
    ]

    # -----------------------------------------------------------------
    # HTTP enrichment per subdomain
    # -----------------------------------------------------------------
    logger.info("Starting HTTP enrichment per subdomain")

    http_results = run_parallel(
        http_enrich_subdomain,
        result["subdomains"],
        max_workers=10,
    )

    result["http_by_subdomain"] = {
        sub: info
        for sub, info in zip(result["subdomains"], http_results)
    }

    # -----------------------------------------------------------------
    # HTTP Recon
    # -----------------------------------------------------------------
    http_info = http_recon(domain)
    result["http"] = http_info

    # -----------------------------------------------------------------
    # Technology fingerprint
    # -----------------------------------------------------------------
    result["tech_by_subdomain"] = fingerprint_technologies_by_subdomain(
        result.get("http_by_subdomain", {})
    )

    # -----------------------------------------------------------------
    # Shodan
    # -----------------------------------------------------------------
    ip = result["domain"].get("ip")
    if ip:
        result["shodan"] = shodan_host_lookup(ip)

    logger.info("Recon finished successfully")

    # -------------------------------------------------
    # Risk scoring
    # -------------------------------------------------
    scored = []

    passive_set = set(result.get("passive_subdomains", []))
    technologies = result.get("technologies", [])
    http_by_subdomain = result.get("http_by_subdomain", {})
    shodan_info = result.get("shodan", {})
    tech_by_subdomain = result.get("tech_by_subdomain", {})

    for sub in result.get("subdomains", []):
        origin = "passive" if sub in passive_set else "active"

        scored.append(
            score_subdomain(
                subdomain=sub,
                origin=origin,
                http_info=http_by_subdomain.get(sub, {}),
                technologies=tech_by_subdomain.get(sub, []),
                shodan_info=shodan_info,
            )
        )

    result["risk_scoring"] = sorted(
        scored, key=lambda x: x["score"], reverse=True
    )
    
    return result


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    try:
        recon_data = run_recon(args)
        
        safe_domain = normalize_domain(args.domain)

        domain_output_dir = OUTPUT_DIR / safe_domain
        domain_output_dir.mkdir(parents=True, exist_ok=True)

        output_file = domain_output_dir / f"recon-{safe_domain}.json"

        with output_file.open("w", encoding="utf-8") as f:
            json.dump(recon_data, f, indent=2, ensure_ascii=False)

        logger.info(f"Results saved to {output_file}")
        print(f"[+] Recon completed. Output: {output_file}")

        report_path = generate_markdown_report(recon_data, domain_output_dir)
        
        logger.info(f"Markdown report saved to {report_path}")
        print(f"[+] Markdown report generated: {report_path}")
        
        html_path = generate_html_report(recon_data, domain_output_dir)

        logger.info(f"HTML report saved to {html_path}")
        print(f"[+] HTML report generated: {html_path}")
        
        # -------------------------------------------------
        # Export pentest targets (prioritized lists)
        # -------------------------------------------------
        exports = export_targets(
            domain=args.domain,
            risk_scoring=recon_data.get("risk_scoring", []),
            output_dir=domain_output_dir,
        )

        for name, path in exports.items():
            logger.info(f"Targets exported ({name}): {path}")
            print(f"[+] Targets exported ({name}): {path}")

    except KeyboardInterrupt:
        logger.warning("Execution interrupted by user")
        sys.exit(1)

    except Exception as exc:
        logger.exception(f"Fatal error: {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()
