#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, time, logging, re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# ---------- Logging ----------
LOG_PATH = os.path.join(os.environ.get("SPLUNK_HOME", "."), "var", "log", "splunk", "enrichioc.log")
dlog = logging.getLogger("enrichioc_detailed")
dlog.setLevel(logging.DEBUG)
if not dlog.handlers:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    fh = logging.FileHandler(LOG_PATH, mode='a', encoding='utf-8')
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    dlog.addHandler(fh)
dlog.info("=== enrich_ioc_core.py loaded ===")

# ---------- Safe imports ----------
def _safe_imports():
    mods = {}
    try:
        from api_keys import get_api_keys; mods["get_api_keys"] = get_api_keys
    except: pass
    try:
        from cache import KvCache; mods["KvCache"] = KvCache
    except: pass
    try:
        from clients import query_abuseipdb, query_greynoise, query_urlhaus, query_otx
        mods.update({"query_abuseipdb": query_abuseipdb,
                     "query_greynoise": query_greynoise,
                     "query_urlhaus": query_urlhaus,
                     "query_otx": query_otx})
    except: pass
    try:
        from scoring import score; mods["score"] = score
    except: pass
    try:
        from campaign_summarizer import build_campaigns; mods["build_campaigns"] = build_campaigns
    except: pass
    try:
        from graph_builder import edges_from_enriched, node
        mods.update({"edges_from_enriched": edges_from_enriched, "node": node})
    except: pass
    try:
        from kv_utils import upsert_many; mods["upsert_many"] = upsert_many
    except: pass
    return mods

MODS = _safe_imports()

# ---------- Helpers ----------
def dig(d, path, default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur

def normalize_tags(val):
    if val is None: return []
    if isinstance(val, str): return [val.strip()] if val.strip() else []
    if isinstance(val, (list, tuple, set)):
        return [str(item).strip() for item in val if item and str(item).strip()]
    return []

def merge_unique_tags(dst_list, add_list):
    dst = list(dst_list or [])
    seen = set(t.lower() for t in dst if isinstance(t, str))
    for t in (add_list or []):
        t = str(t).strip()
        if t and t.lower() not in seen:
            dst.append(t); seen.add(t.lower())
    return dst

def parse_root_domain_from_url(url):
    try:
        u = urlparse(url)
        host = u.netloc or ""
        if "@" in host: host = host.split("@", 1)[1]
        if ":" in host: host = host.split(":", 1)[0]
        return host.lower()
    except: return ""

def enrich_hostname_from_sources(sources, ioc_type):
    abuse = dig(sources, ['abuseipdb'], {}) or {}
    hostname = abuse.get('domain')
    if not hostname:
        hostnames = abuse.get('hostnames') or []
        if isinstance(hostnames, list) and hostnames:
            hostname = hostnames[0]
    if hostname: return hostname
    gn_rdns = dig(sources, ['greynoise', 'rdns']) or dig(sources, ['greynoise', 'metadata', 'rdns'])
    if gn_rdns: return gn_rdns
    otx_host = dig(sources, ['otx', 'hostname']) or dig(sources, ['otx', 'domain'])
    if otx_host: return otx_host
    if ioc_type == 'url':
        return dig(sources, ['urlhaus', 'host'])
    return None

# ---------- AbuseIPDB Category Map ----------
CATEGORY_MAP = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    12: "Blog Spam", 13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted"
}
# ---------- Slimmers ----------

def slim_otx(resp):
    """
    Reduce OTX response to key fields while preserving critical context.
    Works with the /general endpoint structure.
    """
    if not isinstance(resp, dict):
        return resp

    # Top-level indicator/type
    indicator = resp.get("indicator")
    ioc_type = resp.get("type")

    # Pulse info
    pulse_info = resp.get("pulse_info", {})
    pulses = pulse_info.get("pulses", []) or []
    pulse_count = pulse_info.get("count", len(pulses))

    # Tags from all pulses
    tags = []
    for p in pulses:
        tags.extend(p.get("tags", []))

    # Malware families from pulses
    malware_families = []
    for p in pulses:
        for mf in p.get("malware_families", []) or []:
            if isinstance(mf, dict):
                malware_families.append(mf.get("display_name") or mf.get("id"))
            else:
                malware_families.append(mf)

    # Also check related.other.malware_families
    related = pulse_info.get("related", {})
    other_related = related.get("other", {})
    malware_families.extend(other_related.get("malware_families", []))

    # Passive DNS count (if present)
    passive_dns = resp.get("passive_dns", [])
    passive_dns_count = len(passive_dns) if isinstance(passive_dns, list) else 0

    return {
        "indicator": indicator,
        "type": ioc_type,
        "pulse_count": pulse_count,
        "tags": list(set(tags)),
        "passive_dns_count": passive_dns_count,
        "related_count": sum(len(v) for v in related.values() if isinstance(v, list)),
        "malware_families": list(set(malware_families))
    }

def slim_abuseipdb(resp):
    data = resp.get("data", {}) if isinstance(resp, dict) else {}
    return {
        "country": data.get("countryCode"),
        "asn": data.get("asn"),
        "isp": data.get("isp"),
        "abuseConfidenceScore": data.get("abuseConfidenceScore"),
        "totalReports": data.get("totalReports"),
        "categories": data.get("categories") or []
    }

def slim_greynoise(resp):
    if not isinstance(resp, dict): return resp
    return {
        "classification": resp.get("classification"),
        "name": resp.get("name"),
        "last_seen": resp.get("last_seen"),
        "actor": resp.get("actor")
    }

def slim_urlhaus(resp):
    if not isinstance(resp, dict): return resp
    return {
        "url_status": resp.get("url_status"),
        "threat": resp.get("threat"),
        "blacklists": resp.get("blacklists")
    }

# ---------- IOC type detection ----------
def detect_ioc_type(value: str) -> str:
    if not value: return "unknown"
    v = value.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v): return "ip"
    if v.lower().startswith(("http://", "https://")): return "url"
    if "." in v: return "domain"
    return "unknown"

# ---------- IOC Summary Helper ----------
def summarize_ioc(enriched):
    parts = []
    parts.append(f"{enriched.get('type','ioc').upper()} {enriched.get('value')}")
    if enriched.get("risk_level"):
        parts.append(f"is assessed as {enriched['risk_level']} risk "
                     f"(score {enriched.get('risk_score',0)}).")
    isp = enriched.get("isp"); country = enriched.get("country")
    if isp and country:
        parts.append(f"It belongs to {isp} in {country}.")
    elif isp:
        parts.append(f"It belongs to {isp}.")
    elif country:
        parts.append(f"It is located in {country}.")
    if enriched.get("abuseConfidenceScore") is not None:
        parts.append(f"AbuseIPDB confidence score: {enriched['abuseConfidenceScore']} "
                     f"with {enriched.get('totalReports',0)} reports.")
    gn_actor = enriched.get("sources",{}).get("greynoise",{}).get("actor")
    if gn_actor:
        parts.append(f"GreyNoise associates it with actor {gn_actor}.")
    otx_pulses = enriched.get("sources",{}).get("otx",{}).get("pulse_count")
    if otx_pulses:
        parts.append(f"OTX lists it in {otx_pulses} threat pulses.")
    tags = enriched.get("tags", [])
    if tags:
        parts.append(f"Tags: {', '.join(tags)}.")
    return " ".join(parts)
# ---------- Enrichment Engine ----------
class EnrichEngine:
    def __init__(self, session_key, ttl_seconds=86400, force_refresh=False):
        self.session_key = session_key
        self.ttl_seconds = ttl_seconds
        self.force_refresh = force_refresh
        self.now_ts = int(time.time())

        # dependencies
        self.get_api_keys = MODS.get("get_api_keys", lambda sk: {})
        self.KvCache = MODS.get("KvCache", None)
        self.query_abuseipdb = MODS.get("query_abuseipdb", lambda v, k: {"error": "abuseipdb client missing"})
        self.query_greynoise = MODS.get("query_greynoise", lambda v, k: {"error": "greynoise client missing"})
        self.query_urlhaus = MODS.get("query_urlhaus", lambda v, k: {"error": "urlhaus client missing"})
        self.query_otx = MODS.get("query_otx", lambda v, k, t: {"error": "otx client missing"})
        self.score = MODS.get("score", lambda payload: (0, "unknown", []))
        self.build_campaigns = MODS.get("build_campaigns", lambda events, session_key=None: {})
        self.edges_from_enriched = MODS.get("edges_from_enriched", lambda e: [])
        self.node = MODS.get("node", lambda t, k, labels=None, attrs=None: {"type": t, "key": k})
        self.upsert_many = MODS.get("upsert_many", lambda kv, items: None)

        # KV setup
        if self.KvCache:
            self.edges_kv = self.KvCache(session_key, "edges")
            self.nodes_kv = self.KvCache(session_key, "nodes")
            self.ioc_kv = self.KvCache(session_key, "ioc_cache")
        else:
            class _KV:
                def upsert(self, k, v): pass
                def get(self, k): return None
            self.edges_kv = _KV(); self.nodes_kv = _KV(); self.ioc_kv = _KV()

        try:
            self.keys = {k: (v.strip() if v else None) for k, v in (self.get_api_keys(session_key) or {}).items()}
        except:
            self.keys = {}

        self.enriched_events = []

    # ---------- Helpers inside EnrichEngine ----------
    def _is_empty_result(self, record):
        sources = record.get("sources", {})
        if not sources:
            return True
        if all(isinstance(v, dict) and "error" in v for v in sources.values()):
            return True
        return False


    def _lookup_sources(self, ioc_type, ioc_value):
        sources = {}
        with ThreadPoolExecutor() as pool:
            futures = {}

            if ioc_type in ('ip', 'domain', 'url'):
                futures['otx'] = pool.submit(self.query_otx, ioc_value, self.keys.get("otx"), ioc_type)

            if ioc_type == 'ip':
                futures['abuseipdb'] = pool.submit(self.query_abuseipdb, ioc_value, self.keys.get("abuseipdb"))
                futures['greynoise'] = pool.submit(self.query_greynoise, ioc_value, self.keys.get("greynoise"))

            if ioc_type == 'url':
                futures['urlhaus'] = pool.submit(self.query_urlhaus, ioc_value, self.keys.get("urlhaus"))

            for name, fut in futures.items():
                try:
                    raw = fut.result(timeout=15)
                    if name == "otx":
                        
                        sources[name] = slim_otx(raw)
                    elif name == "abuseipdb":
                        sources[name] = slim_abuseipdb(raw)
                    elif name == "greynoise":
                        sources[name] = slim_greynoise(raw)
                    elif name == "urlhaus":
                        sources[name] = slim_urlhaus(raw)
                    else:
                        sources[name] = raw
                except Exception as e:
                    sources[name] = {"error": f"{name} error: {e}"}
        return sources



    def _derive_fields(self, ioc_type, ioc_value, sources, base_tags):
        enriched = {
            'type': ioc_type,
            'value': ioc_value,
            'sources': sources,
            'expiresAt': self.now_ts + self.ttl_seconds,
            'cache_hit': False
        }

        # --- scoring ---
        try:
            risk_score, risk_level, scoring_tags = self.score({'sources': sources})
        except Exception:
            risk_score, risk_level, scoring_tags = 0, "unknown", []

        tags = normalize_tags(base_tags)
        tags = merge_unique_tags(tags, scoring_tags)

        # --- OTX pulse tags ---
        otx_tags = sources.get('otx', {}).get('tags', [])
        tags = merge_unique_tags(tags, otx_tags[:10])

        # --- URLHaus tags ---
        urlhaus_threat = sources.get('urlhaus', {}).get('threat')
        if urlhaus_threat:
            tags = merge_unique_tags(tags, [urlhaus_threat])

        urlhaus_blacklists = sources.get('urlhaus', {}).get('blacklists')
        if isinstance(urlhaus_blacklists, dict):
            for bl, flagged in urlhaus_blacklists.items():
                if flagged:
                    tags = merge_unique_tags(tags, [f"blacklist:{bl}"])

        # --- GreyNoise context ---
        gn_actor = sources.get('greynoise', {}).get('actor')
        if gn_actor:
            tags = merge_unique_tags(tags, [gn_actor])
        gn_name = sources.get('greynoise', {}).get('name')
        if gn_name:
            tags = merge_unique_tags(tags, [gn_name])

        # --- AbuseIPDB categories -> human-readable tags ---
        abuse_cats = sources.get('abuseipdb', {}).get('categories', [])
        if isinstance(abuse_cats, list) and abuse_cats:
            pretty = []
            for cat in abuse_cats:
                try:
                    cid = int(cat)
                except Exception:
                    cid = None
                if cid is not None:
                    pretty.append(CATEGORY_MAP.get(cid, f"category:{cid}"))
                else:
                    pretty.append(str(cat))
            tags = merge_unique_tags(tags, pretty[:10])
        else:
            tags = merge_unique_tags(tags, ["abuseipdb_uncategorized"])

        enriched.update({
            'risk_score': risk_score,
            'risk_level': risk_level,
            'tags': tags
        })

        # --- AbuseIPDB extras ---
        abuse_data = sources.get('abuseipdb', {}) or {}
        if abuse_data:
            enriched['country'] = abuse_data.get('country')
            enriched['asn'] = abuse_data.get('asn')
            enriched['isp'] = abuse_data.get('isp')
            enriched['abuseConfidenceScore'] = abuse_data.get('abuseConfidenceScore')
            enriched['totalReports'] = abuse_data.get('totalReports')

        # --- URL extras ---
        if ioc_type == 'url' and not enriched.get('root_domain'):
            host = parse_root_domain_from_url(ioc_value)
            if host:
                enriched['root_domain'] = host

        # --- hostname derivation ---
        if not enriched.get('hostname'):
            host = enrich_hostname_from_sources(sources, ioc_type)
            if host:
                enriched['hostname'] = host

        enriched['tags'] = normalize_tags(enriched.get('tags'))
        enriched['ioc_summary'] = summarize_ioc(enriched)
        return enriched

    def _persist_graph(self, enriched):
        try:
            edges = self.edges_from_enriched(enriched)
            nodes = [
                self.node(
                    "ioc",
                    enriched["value"],
                    labels=enriched.get("tags", []),
                    attrs={"type": enriched["type"], "risk": enriched.get("risk_level")}
                )
            ]
            if enriched.get("asn"):
                nodes.append(self.node("asn", enriched["asn"]))
            if enriched.get("country"):
                nodes.append(self.node("country", enriched["country"]))
            if enriched.get("hostname"):
                nodes.append(self.node("hostname", enriched["hostname"]))
            if enriched.get("root_domain"):
                nodes.append(self.node("domain", enriched["root_domain"]))
            self.upsert_many(self.edges_kv, edges)
            self.upsert_many(self.nodes_kv, nodes)
        except Exception as e:
            dlog.debug(f"[core] graph persist skipped: {e}")

    def iter_enriched(self, records, type_opt, value_opt):
        for record in records:
            ioc_type = record.get(type_opt) if type_opt in record else type_opt
            ioc_value = record.get(value_opt) if value_opt in record else value_opt
            cache_key = f"{ioc_type}:{ioc_value}"

            # cache read
            try:
                existing = self.ioc_kv.get(cache_key)
            except Exception:
                existing = None

            now_ts = int(time.time())
            if (existing and existing.get('expiresAt', 0) > now_ts
                and not self.force_refresh and not self._is_empty_result(existing)):
                existing['cache_hit'] = True
                self.enriched_events.append(existing)
                yield existing
                continue

            # lookups
            sources = self._lookup_sources(ioc_type, ioc_value)

            # derive
            enriched = self._derive_fields(ioc_type, ioc_value, sources, base_tags=record.get('tags', []))

            # preserve incoming fields
            for field, val in record.items():
                if val in (None, "", []):
                    continue
                if field not in enriched or enriched[field] in (None, "", []):
                    enriched[field] = val

            # timestamps
            try:
                event_time = int(float(record.get("_time"))) if record.get("_time") is not None else now_ts
            except Exception:
                event_time = now_ts
            if existing:
                enriched['first_seen'] = min(existing.get('first_seen', event_time), event_time)
                enriched['last_seen'] = max(existing.get('last_seen', event_time), event_time)
            else:
                enriched['first_seen'] = event_time
                enriched['last_seen'] = event_time

            # persist cache
            try:
                self.ioc_kv.upsert(cache_key, enriched)
            except Exception as e:
                enriched['cache_error'] = str(e)

            # graph
            self._persist_graph(enriched)

            self.enriched_events.append(enriched)
            yield enriched

    def finalize(self):
        try:
            campaigns = self.build_campaigns(self.enriched_events, session_key=self.session_key)
            if campaigns and self.KvCache:
                campaign_kv = self.KvCache(self.session_key, "campaign_cache")
                for cid, data in campaigns.items():
                    try:
                        campaign_kv.upsert(cid, data)
                    except Exception as e:
                        dlog.debug(f"[core] campaign upsert failed: {e}")
        except Exception as e:
            dlog.debug(f"[core] finalize campaigns skipped: {e}")
