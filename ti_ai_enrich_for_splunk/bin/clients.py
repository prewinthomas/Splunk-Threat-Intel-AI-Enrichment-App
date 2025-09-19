#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Threat intelligence client wrappers for external APIs:
- AbuseIPDB
- GreyNoise
- URLHaus
- AlienVault OTX
"""

import requests
import logging

dlog = logging.getLogger("clients")
dlog.setLevel(logging.DEBUG)

# === AbuseIPDB ===
def query_abuseipdb(ip, api_key, max_age_days=90):
    """
    Query AbuseIPDB check endpoint for an IP.
    Returns JSON with categories preserved.
    """
    if not api_key:
        return {"error": "no abuseipdb api key"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": max_age_days}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        dlog.debug(f"AbuseIPDB query failed for {ip}: {e}")
        return {"error": str(e)}

# === GreyNoise ===
def query_greynoise(ip, api_key):
    """
    Query GreyNoise community or enterprise API for an IP.
    """
    if not api_key:
        return {"error": "no greynoise api key"}
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"key": api_key, "Accept": "application/json"}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        dlog.debug(f"GreyNoise query failed for {ip}: {e}")
        return {"error": str(e)}

# === URLHaus ===
def query_urlhaus(url_value, api_key=None):
    """
    Query URLHaus for a URL.
    API key not required for public lookup.
    """
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        resp = requests.post(api_url, data={"url": url_value}, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        dlog.debug(f"URLHaus query failed for {url_value}: {e}")
        return {"error": str(e)}

# === AlienVault OTX ===
def query_otx(value, api_key, ioc_type):
    """
    Query AlienVault OTX for an IP, domain, or URL.
    Uses the /full endpoint to include pulses, tags, passive DNS, related indicators, etc.
    """
    if not api_key:
        return {"error": "no otx api key"}
    base = "https://otx.alienvault.com/api/v1/indicators"
    if ioc_type == "ip":
        endpoint = f"{base}/IPv4/{value}/general"
    elif ioc_type == "domain":
        endpoint = f"{base}/domain/{value}/general"
    elif ioc_type == "url":
        endpoint = f"{base}/url/{value}/general"
    else:
        return {"error": f"unsupported ioc_type {ioc_type}"}
    headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}
    try:
        resp = requests.get(endpoint, headers=headers, timeout=20)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        dlog.debug(f"OTX query failed for {value}: {e}")
        return {"error": str(e)}
