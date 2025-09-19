#!/usr/bin/env python3
import time, hashlib

def _hid(*parts):
    return hashlib.sha1(":".join(str(p) for p in parts).encode()).hexdigest()

def edge(src_type, src, rel, dst_type, dst, evidence=None, weight=1.0, t=None):
    t = int(t or time.time())
    return {
        "_key": _hid(src_type, src, rel, dst_type, dst),
        "src_type": src_type, "src": src,
        "rel": rel,
        "dst_type": dst_type, "dst": dst,
        "first_seen": t, "last_seen": t,
        "weight": float(weight),
        "evidence": evidence or {}
    }

def node(ntype, value, labels=None, attrs=None, t=None):
    t = int(t or time.time())
    return {
        "_key": _hid(ntype, value),
        "type": ntype, "value": value,
        "labels": labels or [],
        "attrs": attrs or {},
        "first_seen": t, "last_seen": t
    }

def edges_from_enriched(evt):
    out = []
    v = evt.get("value")
    t = evt.get("_time") or time.time()
    ioc_type = evt.get("type", "ioc")
    risk = evt.get("risk_level", "unknown")

    # IOC → ASN
    if evt.get("asn"):
        out.append(edge(ioc_type, v, "ioc_to_asn", "asn", evt["asn"],
                        {"source": "enrichment", "risk": risk}, t=t))

    # IOC → Country
    if evt.get("country"):
        out.append(edge(ioc_type, v, "ioc_to_country", "country", evt["country"],
                        {"source": "enrichment", "risk": risk}, t=t))

    # IOC → Hostname
    if evt.get("hostname"):
        out.append(edge(ioc_type, v, "ioc_to_hostname", "hostname", evt["hostname"],
                        {"source": "enrichment", "risk": risk}, t=t))

    # IOC → Root Domain
    if evt.get("root_domain"):
        out.append(edge(ioc_type, v, "ioc_to_domain", "domain", evt["root_domain"],
                        {"source": "enrichment", "risk": risk}, t=t))

    # IOC → Tags
    for tag in evt.get("tags", []):
        out.append(edge(ioc_type, v, "ioc_to_tag", "tag", tag,
                        {"source": "scoring", "risk": risk}, t=t, weight=0.5))

    return out

def edges_from_campaign(cid, campaign):
    out = []
    t = time.time()
    # IOC → Campaign
    for ioc in campaign.get("iocs", []):
        out.append(edge("ioc", ioc, "ioc_to_campaign", "campaign", cid,
                        {"source": "campaign_builder"}, t=t))
    # Campaign → ASN
    for asn in campaign.get("asns", []):
        out.append(edge("campaign", cid, "campaign_to_asn", "asn", asn,
                        {"source": "campaign_agg"}, t=t, weight=1.5))
    # Campaign → Country
    for ctry in campaign.get("countries", []):
        out.append(edge("campaign", cid, "campaign_to_country", "country", ctry,
                        {"source": "campaign_agg"}, t=t, weight=1.2))
    # Campaign → Tag
    for tag in campaign.get("tags", []):
        out.append(edge("campaign", cid, "campaign_to_tag", "tag", tag,
                        {"source": "campaign_agg"}, t=t, weight=1.0))
    return out
