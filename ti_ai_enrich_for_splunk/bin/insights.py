#!/usr/bin/env python3
from collections import Counter, defaultdict

def graph_insights(edges_for_campaign):
    rels = defaultdict(list)
    for e in edges_for_campaign:
        rels[(e["src_type"], e["rel"], e["dst_type"])].append(e)

    insights = []

    asn_edges = rels.get(("campaign", "clusters_on", "asn"), [])
    if asn_edges:
        asns = [e["dst"] for e in asn_edges]
        top, n = Counter(asns).most_common(1)[0]
        insights.append(f"Infrastructure concentrates on {top} ({n}/{len(asns)} ASN links).")

    ctry_edges = rels.get(("campaign", "hosts_in", "country"), [])
    if ctry_edges:
        ctry = [e["dst"] for e in ctry_edges]
        top, n = Counter(ctry).most_common(1)[0]
        insights.append(f"Hosting skewed toward {top} ({n}/{len(ctry)} country links).")

    tag_edges = rels.get(("campaign", "characterized_by", "tag"), [])
    tags = [e["dst"] for e in tag_edges]
    if tags:
        top_tags = ", ".join([t for t,_ in Counter(tags).most_common(3)])
        insights.append(f"Dominant tags: {top_tags}.")

    return insights
