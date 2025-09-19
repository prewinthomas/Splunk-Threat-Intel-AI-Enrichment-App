#!/usr/bin/env python3
from collections import Counter

def tokenize(s):
    return {x.strip().lower() for x in s.split(";") if x.strip()} if isinstance(s, str) else set()

def jaccard(a, b):
    a, b = set(a), set(b)
    return (len(a & b) / len(a | b)) if (a or b) else 0.0

def score_campaign_against_actor(campaign, actor_profile):
    asns = set(campaign.get("asns", []))
    countries = set(campaign.get("countries", []))
    tags = set(campaign.get("tags", []))
    tlds = {("." + i.split(".")[-1]) for i in campaign.get("iocs", []) if "." in i and ":" not in i}

    pa = {
        "asns": tokenize(actor_profile.get("asns")),
        "countries": tokenize(actor_profile.get("countries")),
        "tags": tokenize(actor_profile.get("tags")),
        "tlds": tokenize(actor_profile.get("tlds")),
    }

    s_asn  = jaccard(asns, pa["asns"])
    s_ctry = jaccard(countries, pa["countries"])
    s_tags = jaccard(tags, pa["tags"])
    s_tlds = jaccard(tlds, pa["tlds"])

    score = 0.35*s_tags + 0.30*s_asn + 0.20*s_ctry + 0.15*s_tlds

    ev = []
    if s_tags > 0:  ev.append(f"tag overlap {round(s_tags,2)}")
    if s_asn > 0:   ev.append(f"ASN overlap {round(s_asn,2)}")
    if s_ctry > 0:  ev.append(f"country overlap {round(s_ctry,2)}")
    if s_tlds > 0:  ev.append(f"TLD overlap {round(s_tlds,2)}")

    return score, ", ".join(ev) if ev else "no overlap"

def attribute_campaign(campaign, actor_profiles, min_hint=0.45):
    best = None
    for ap in actor_profiles:
        s, ev = score_campaign_against_actor(campaign, ap)
        if not best or s > best["score"]:
            best = {"actor": ap["actor"], "score": s, "evidence": ev}
    if best and best["score"] >= min_hint:
        conf = "low"
        if best["score"] >= 0.7: conf = "high"
        elif best["score"] >= 0.55: conf = "medium"
        best["confidence"] = conf
        return best
    return None
