#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option
from enrich_ioc_core import EnrichEngine, dlog, detect_ioc_type

@Configuration()
class EnrichIOC(StreamingCommand):
    value = Option(require=True, doc="IOC value to enrich (IP, domain, or URL)")
    refresh = Option(require=False, default="false",
                     doc="Set to 'true' to bypass cache and force API refresh")

    def stream(self, records):
        # get session key
        try:
            session_key = self._metadata.searchinfo.session_key
        except Exception as e:
            yield {"error": f"Failed to get session key: {e}"}
            return

        # materialize input
        try:
            records = list(records)
        except Exception as e:
            yield {"error": f"Failed to read input records: {e}"}
            return
        if not records:
            records = [{"value": self.value}]

        # interpret refresh flag
        force_refresh = str(self.refresh).lower() in ("true", "1", "yes")

        engine = EnrichEngine(session_key=session_key, force_refresh=force_refresh)

        try:
            for record in records:
                val = record.get("value", self.value)
                ioc_type = detect_ioc_type(val)
                for enriched in engine.iter_enriched([{"value": val}], ioc_type, "value"):
                    # If you want to hide raw sources from search output, uncomment:
                    # to_yield = dict(enriched); to_yield.pop("sources", None); yield to_yield
                    yield enriched
        finally:
            try:
                engine.finalize()
            except Exception as e:
                dlog.debug(f"[command] finalize error: {e}")

if __name__ == "__main__":
    dispatch(EnrichIOC, sys.argv, sys.stdin, sys.stdout, __name__)
