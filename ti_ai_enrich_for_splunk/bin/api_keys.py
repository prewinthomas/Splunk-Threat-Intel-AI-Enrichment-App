import splunklib.client as client
import os
import logging

# === Dedicated file logger ===
LOG_PATH = os.path.join(os.environ.get("SPLUNK_HOME", "."), "var", "log", "splunk", "enrichioc.log")
dlog = logging.getLogger("enrichioc_detailed")
dlog.setLevel(logging.DEBUG)
if not dlog.handlers:
    fh = logging.FileHandler(LOG_PATH, mode='a', encoding='utf-8')
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    dlog.addHandler(fh)

dlog.info("=== api_keys.py module loaded ===")

def get_api_keys(session_key=None):
    """
    Load API keys from the KV Store collection 'ti_api_keys'.
    Accepts a session_key argument; falls back to SPLUNK_SESSION_KEY env var.
    Returns a dict with keys for otx, abuseipdb, greynoise, and urlhaus.
    """
    keys = {
        'otx': None,
        'abuseipdb': None,
        'greynoise': None,
        'urlhaus': None
    }

    session_key = session_key or os.environ.get('SPLUNK_SESSION_KEY')
    if not session_key:
        dlog.error("No session key available for get_api_keys()")
        return keys

    try:
        dlog.debug("Connecting to Splunk service to fetch API keys")
        service = client.connect(
            token=session_key,
            owner="nobody",
            app="ti_ai_enrich_for_splunk"
        )
        dlog.debug("Connected to Splunk service, querying KV Store 'ti_api_keys'")
        record = service.kvstore["ti_api_keys"].data.query_by_id("api_keys")

        if not record:
            dlog.error("KV Store record 'api_keys' not found")
            return keys

        # Extract and log each key explicitly
        for field in keys.keys():
            raw_value = record.get(f"{field}_api_key")
            value = (raw_value or "").strip()  # strip whitespace/newlines
            keys[field] = value if value else None
            preview = value[:6] + "..." if value else "None"
            dlog.debug(f"[api_keys.py] Retrieved {field}_api_key: {preview} (len={len(value) if value else 0})")

        dlog.info(f"Retrieved API keys presence: {{k: bool(v) for k,v in keys.items()}}")

    except Exception as e:
        dlog.error(f"Error retrieving API keys: {e}", exc_info=True)

    return keys
