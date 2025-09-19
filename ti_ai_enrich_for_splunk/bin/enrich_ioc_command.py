import sys
import json
import splunklib.searchcommands as sc
from enrich_ioc import enrich_indicator

@sc.dispatcher
class EnrichIOCCommand(sc.GeneratingCommand):
    indicator = sc.Option(
        doc='**Required** Indicator of Compromise (IP, domain, or URL) to enrich',
        require=True
    )

    def generate(self):
        # Call the enrichment pipeline
        results = enrich_indicator(self.indicator)

        # Yield one event per provider
        for provider, data in results.items():
            yield {
                "indicator": self.indicator,
                "provider": provider,
                "result": json.dumps(data)
            }

if __name__ == "__main__":
    sys.exit(EnrichIOCCommand.run())
