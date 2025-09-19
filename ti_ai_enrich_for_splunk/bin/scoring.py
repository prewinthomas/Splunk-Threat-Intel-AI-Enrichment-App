#!/usr/bin/env python3

def score(data):
    """
    Calculate a risk score, risk level, and tags from enrichment sources.

    Updated rules:
      - AbuseIPDB: use actual confidence (0–100).
      - GreyNoise: malicious classification = 90.
      - OTX: pulse_count > 20 = 90, 1–20 = 70.
      - URLHaus: online/malicious = 80.
      - Final score = max of all feed scores (not average).
    """

    sources = data.get('sources', {})
    scores = []   # list of numeric scores
    tags = set()

    # --- Detection logic per feed ---
    for feed, result in sources.items():
        if not isinstance(result, dict):
            continue

        if feed == 'otx':
            pulse_count = result.get('pulse_count', 0)
            if pulse_count > 0:
                if pulse_count > 20:
                    scores.append(90)
                else:
                    scores.append(70)
                tags.add('otx_hit')

        elif feed == 'abuseipdb':
            score_val = None
            if 'data' in result and isinstance(result['data'], dict):
                score_val = result['data'].get('abuseConfidenceScore')
            else:
                score_val = result.get('abuseConfidenceScore')

            if score_val is not None and score_val > 0:
                scores.append(int(score_val))
                tags.add('abuseipdb_hit')

        elif feed == 'greynoise':
            if result.get('classification') == 'malicious':
                scores.append(90)
                tags.add('greynoise_hit')

        elif feed == 'urlhaus':
            if result.get('url_status') in ('online', 'malicious'):
                scores.append(80)
                tags.add('urlhaus_hit')

    # --- Scoring logic ---
    if not scores:
        total_score = 0
    else:
        total_score = max(scores)

    # --- Risk level thresholds ---
    if total_score >= 90:
        risk_level = 'critical'
    elif total_score >= 70:
        risk_level = 'high'
    elif total_score >= 40:
        risk_level = 'medium'
    elif total_score > 0:
        risk_level = 'low'
    else:
        risk_level = 'none'

    return int(total_score), risk_level, list(tags)
