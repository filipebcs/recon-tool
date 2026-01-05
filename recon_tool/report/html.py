from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


def generate_html_report(data: Dict[str, Any], output_dir: Path) -> Path:
    domain = data.get("target", "unknown")

    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(["html"]),
    )

    template = env.get_template("report.html")

    risk_scoring = data.get("risk_scoring", [])
    tech_by_subdomain = data.get("tech_by_subdomain", {})
    
    passive = set(data.get("passive_subdomains", []))

    scored_rows = []
    for item in risk_scoring:
        sub = item.get("subdomain")

        scored_rows.append({
            "name": sub,
            "origin": "passive" if sub in passive else "active",
            "score": item.get("score", 0),
            "level": item.get("level", "LOW"),
            "signals": item.get("signals", []),
            "technologies": [
                t.get("technology")
                for t in tech_by_subdomain.get(sub, [])
            ],
        })

    levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for row in scored_rows:
        lvl = row.get("level", "LOW")
        levels[lvl] = levels.get(lvl, 0) + 1

    summary = {
        "total_subdomains": len(scored_rows),
        "passive_subdomains": len([r for r in scored_rows if r["origin"] == "passive"]),
        "active_subdomains": len([r for r in scored_rows if r["origin"] == "active"]),
        "technologies": sorted({
            t.get("technology")
            for techs in tech_by_subdomain.values()
            for t in techs
        }),
        "critical": levels["CRITICAL"],
        "high": levels["HIGH"],
        "medium": levels["MEDIUM"],
        "low": levels["LOW"],
    }


    html = template.render(
        domain=domain,
        timestamp=datetime.utcnow().isoformat() + "Z",
        summary=summary,
        subdomains=scored_rows,
        technologies=data.get("technologies", []),
        shodan=data.get("shodan", {}),
    )

    safe_domain = domain.replace(".", "_")
    report_path = output_dir / f"recon-{safe_domain}.html"
    report_path.write_text(html, encoding="utf-8")
    return report_path
