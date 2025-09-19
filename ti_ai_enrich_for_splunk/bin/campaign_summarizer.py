#!/usr/bin/env python3
import hashlib
import time
import csv
import os
from cache import KvCache
from summarizer import summarize
from graph_builder import edges_from_campaign
from insights import graph_insights

# === Load actor profiles from CSV lookup ===
def load_actor_profiles():
    profiles = []
    lookup_path = os.path.join(
        os.environ.get("SPLUNK_HOME", "."),
        "etc", "apps", "YOUR_APP_NAME", "lookups", "actor_profiles.csv"
    )
    try:
        with open(lookup_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                profiles.append(row)
    except FileNotFoundError:
        pass
    return profiles

# === Attribute campaign based on actor_profiles.csv ===
def attribute_campaign(campaign_data, profiles):
    asns = set(campaign_data.get("asns", []))
    countries = set(campaign_data.get("countries", []))
    tags = set(campaign_data.get("tags", []))
    root_domain = campaign_data.get("root_domain", "")

    for profile in profiles:
        match = False
        evidence = []

        # ASN match
        profile_asns = set(profile.get("asns", "").split(";")) if profile.get("asns") else set()
        if asns & profile_asns:
            match = True
            evidence.append(f"asn={list(asns & profile_asns)[0]}")

        # Country match
        profile_countries = set(profile.get("countries", "").split(";")) if profile.get("countries") else set()
        if countries & profile_countries:
            match = True
            evidence.append(f"country={list(countries & profile_countries)[0]}")

        # Tag match
        profile_tags = set(profile.get("tags", "").split(";")) if profile.get("tags") else set()
        if tags & profile_tags:
            match = True
            evidence.append(f"tag={list(tags & profile_tags)[0]}")

        # TLD match
        profile_tlds = set(profile.get("tlds", "").split(";")) if profile.get("tlds") else set()
        for tld in profile_tlds:
            if root_domain and root_domain.endswith(tld):
                match = True
                evidence.append(f"tld={tld}")
                break

        if match:
            return f"Attribution hint: {profile.get('actor')} (confidence: {profile.get('confidence', 'unknown')}). Evidence: {', '.join(evidence)}"

    return None

# === Build campaigns from enriched events ===
def build_campaigns(enriched_events, session_key=None):
    campaigns = {}
    profiles = load_actor_profiles()

    for evt in enriched_events:
        # Normalise tags to list
        tags = evt.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]
        elif tags is None:
            tags = []

        asn = evt.get("asn")
        country = evt.get("country")
        root_domain = evt.get("root_domain") or evt.get("hostname") or ""

        # Normalize campaign ID parts
        cid_source = f"{asn or ''}|{country or ''}|{root_domain or ''}"
        cid = hashlib.sha1(cid_source.encode()).hexdigest()

        if cid not in campaigns:
            campaigns[cid] = {
                "_key": cid,
                "root_domain": root_domain,
                "iocs": set(),
                "tags": set(),
                "categories": set(),
                "risk_levels": set(),
                "asns": set(),
                "countries": set(),
                "ioc_count": 0,
                "first_seen": evt.get("first_seen", int(time.time())),
                "last_seen": evt.get("last_seen", int(time.time())),
                "last_updated": int(time.time()),
                "campaign_summary": ""
            }

        c = campaigns[cid]
        c["iocs"].add(evt.get("value"))
        c["tags"].update(tags)

        # Extract AbuseIPDB categories from tags
        for t in tags:
            if t in ("Brute-Force", "Web Spam", "Port Scan") or t.lower().startswith("category:"):
                c["categories"].add(t)

        if evt.get("risk_level"):
            c["risk_levels"].add(evt.get("risk_level"))
        if asn:
            c["asns"].add(asn)
        if country:
            c["countries"].add(country)

        c["ioc_count"] = len(c["iocs"])
        c["last_updated"] = max(c["last_updated"], evt.get("last_seen", int(time.time())))

        # Update time range
        c["first_seen"] = min(c["first_seen"], evt.get("first_seen", int(time.time())))
        c["last_seen"] = max(c["last_seen"], evt.get("last_seen", int(time.time())))

    # Finalise campaigns
    for cid, c in campaigns.items():
        # Convert sets to lists for KV Store
        c["iocs"] = list(c["iocs"])
        c["tags"] = list(c["tags"])
        c["categories"] = list(c["categories"])
        c["risk_levels"] = list(c["risk_levels"])
        c["asns"] = list(c["asns"])
        c["countries"] = list(c["countries"])

        # Build summary
        infra = c.get("root_domain") or (c["iocs"][0] if c["iocs"] else "")
        summary_text = summarize(c, infra=infra, tag_limit=10)  # pass infra and tag limit

        if c["categories"]:
            summary_text += f"\n\nCategories observed: {', '.join(c['categories'])}"
        hint = attribute_campaign(c, profiles)
        if hint:
            summary_text += f"\n\n{hint}"
        c["campaign_summary"] = summary_text

    # Save to KV Store if session_key provided
    if session_key:
        campaign_kv = KvCache(session_key, "campaign_cache")
        for cid, data in campaigns.items():
            campaign_kv.upsert(cid, data)

    return campaigns
