def upsert_many(cache, items, key_field="_key"):
    """
    Upsert a list of dicts into a KvCache-like object.
    """
    for it in items:
        try:
            cache.upsert(it[key_field], it)
        except Exception:
            # Optional: merge/update logic could go here
            pass
