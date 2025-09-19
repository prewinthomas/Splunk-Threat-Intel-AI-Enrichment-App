#!/usr/bin/env python3
import os
import json
import logging
import splunklib.client as client
import splunklib.binding as binding

# === Dedicated file logger ===
LOG_PATH = os.path.join(os.environ.get("SPLUNK_HOME", "."), "var", "log", "splunk", "enrichioc.log")
dlog = logging.getLogger("enrichioc_detailed")
dlog.setLevel(logging.DEBUG)
if not dlog.handlers:
    fh = logging.FileHandler(LOG_PATH, mode='a', encoding='utf-8')
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    dlog.addHandler(fh)

def _json_default(obj):
    """Convert unsupported types for JSON serialization."""
    if isinstance(obj, set):
        return list(obj)
    raise TypeError(f"Type {type(obj)} not serializable")

class KvCache:
    """
    KV Store wrapper that always uses the nobody/ti_ai_enrich_for_splunk namespace.
    """

    def __init__(self, session_key, collection, owner="nobody", app="ti_ai_enrich_for_splunk"):
        self.session_key = session_key
        self.collection = collection
        self.owner = owner
        self.app = app
        try:
            self.service = client.connect(
                token=self.session_key,
                owner=self.owner,
                app=self.app
            )
            dlog.debug(f"[KvCache] Connected to KV Store: owner={self.owner}, app={self.app}, collection={self.collection}")
        except Exception as e:
            dlog.error(f"[KvCache] Failed to connect to KV Store: {e}", exc_info=True)
            raise

    def upsert(self, key, data):
        """
        Insert or update a record in the KV Store.
        """
        try:
            coll = self.service.kvstore[self.collection]
            if "_key" not in data:
                data["_key"] = key

            json_str = json.dumps(data, default=_json_default)

            try:
                # Try update first
                coll.data.update(id=key, data=json_str)
                dlog.debug(f"[KvCache] Updated key={key} in {self.collection}")
            except binding.HTTPError as he:
                if he.status == 404:
                    # Not found, insert instead
                    coll.data.insert(json_str)
                    dlog.debug(f"[KvCache] Inserted key={key} into {self.collection}")
                else:
                    raise
        except Exception as e:
            dlog.error(f"[KvCache] Failed to upsert key={key} into {self.collection}: {e}", exc_info=True)
            raise

    def get(self, key):
        try:
            coll = self.service.kvstore[self.collection]
            rec = coll.data.query_by_id(key)
            dlog.debug(f"[KvCache] Retrieved key={key} from {self.collection}")
            return rec
        except Exception as e:
            dlog.error(f"[KvCache] Failed to retrieve key={key} from {self.collection}: {e}", exc_info=True)
            return None

    def delete(self, key):
        try:
            coll = self.service.kvstore[self.collection]
            coll.data.delete_by_id(key)
            dlog.debug(f"[KvCache] Deleted key={key} from {self.collection}")
        except Exception as e:
            dlog.error(f"[KvCache] Failed to delete key={key} from {self.collection}: {e}", exc_info=True)

    def all(self):
        try:
            coll = self.service.kvstore[self.collection]
            recs = coll.data.query()
            dlog.debug(f"[KvCache] Retrieved all records from {self.collection} (count={len(recs)})")
            return recs
        except Exception as e:
            dlog.error(f"[KvCache] Failed to retrieve all records from {self.collection}: {e}", exc_info=True)
            return []
