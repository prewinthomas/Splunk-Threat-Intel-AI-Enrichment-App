#!/usr/bin/env python3
"""
summarizer.py — Generates human‑readable summaries for IOC campaigns,
including dynamic 'Recommended actions' based on tags and IOC type.
"""

import datetime

def _fmt_time(ts):
    try:
        return datetime.datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d")
    except Exception:
        return str(ts) if ts else "unknown"

def recommended_actions(tags, ioc_type):
    """
    Return a list of recommended actions based on tags and IOC type.
    """
    actions = []
    tags_lower = [t.lower() for t in tags]

    # Brute force / SSH scanning
    if "brute_force" in tags_lower or "ssh_scanner" in tags_lower:
        actions.append("Block offending IPs or ranges at the network perimeter")
        actions.append("Enforce key-based SSH authentication and disable password logins")
        actions.append("Implement rate-limiting or fail2ban for SSH services")

    # Phishing infrastructure
    if "phishing_host" in tags_lower:
        actions.append("Block associated domains and IPs at email and web gateways")
        actions.append("Submit takedown requests to hosting providers")
        actions.append("Educate users on identifying phishing attempts")

    # Malware command-and-control
    if "malware_c2" in tags_lower:
        actions.append("Block C2 IPs/domains at the firewall and IDS/IPS")
        actions.append("Hunt for beaconing traffic in network logs")
        actions.append("Reimage or isolate any infected endpoints")

    # Generic AbuseIPDB hit
    if "abuseipdb_hit" in tags_lower and not actions:
        actions.append("Block reported IPs at the firewall")
        actions.append("Monitor for repeated abuse reports from the same ASN")

    # IOC type-specific tips
    if ioc_type == "url":
        actions.append("Use a secure web proxy to block malicious URLs")
    elif ioc_type == "domain":
        actions.append("Add domains to DNS sinkhole or blocklist")

    # Fallback if nothing matched
    if not actions:
        actions.append("Investigate related infrastructure and apply appropriate blocks")
        actions.append("Monitor for similar activity in the future")

    return actions


def summarize(campaign, infra=None, tag_limit=10):
    """
    Generate a descriptive summary for a campaign, including dynamic recommendations.
    - infra: optional override for infrastructure string (root_domain/hostname/value)
    - tag_limit: maximum number of tags to display
    """
    ioc_count = campaign.get("ioc_count", len(campaign.get("iocs", [])))
    asn_count = len(campaign.get("asns", []))
    country_count = len(campaign.get("countries", []))
    tags = campaign.get("tags", []) or []
    risk_levels = campaign.get("risk_levels", []) or []
    first_seen = _fmt_time(campaign.get("first_seen"))
    last_seen = _fmt_time(campaign.get("last_seen"))

    # Pick infrastructure string
    infra_str = infra or campaign.get("root_domain") or campaign.get("hostname")
    if not infra_str and campaign.get("iocs"):
        infra_str = campaign["iocs"][0]
    if not infra_str:
        infra_str = "unknown"

    # Limit tags
    display_tags = tags[:tag_limit] if isinstance(tags, list) else tags

    description = (
        f"This campaign is built around infrastructure at {infra_str}, "
        f"comprising {ioc_count} related indicator(s) across "
        f"{asn_count} distinct ASNs and {country_count} hosting countries. "
        f"Observed tags include: {', '.join(display_tags) if display_tags else 'none'}. "
        f"Risk levels span: {', '.join(risk_levels) if risk_levels else 'none'}. "
        f"Activity observed from {first_seen} to {last_seen}."
    )

    # Get tailored recommendations
    actions = recommended_actions(tags, campaign.get("type", ""))
    actions_text = "\n- " + "\n- ".join(actions)

    return f"{description}\n\n**Recommended actions:**{actions_text}"
