# Splunk-Threat-Intel-AI-Enrichment-App
This Splunk App enriches Indicators of Compromise (IOCs) (IPs, domains, URLs, file hashes) by querying multiple external threat intelligence sources, then correlates enriched IOCs into campaigns.
A key feature of this app is its use of AI‑driven natural language generation to produce clear, human‑readable IOC summaries and campaign summaries, making threat intelligence more accessible to both analysts and decision‑makers.

✨ Features
🔍 IOC Enrichment from:

AlienVault OTX

AbuseIPDB

GreyNoise

URLHaus

📊 Risk Scoring & Tagging – assigns risk_score and risk_level

🗂️ Caching – KV Store (ioc_cache, edges, nodes, campaign_cache) avoids redundant lookups

📈 IOC Graph Building – persists IOC relationships for visualization

🧩 Campaign Correlation – groups IOCs into campaigns by ASN, country, and root domain

🎭 Actor Attribution – matches campaigns against actor_profiles.csv lookup

📝 AI‑Generated Summaries – natural language IOC summaries and campaign summaries for quick triage and executive reporting

📊 Dashboards – executive overview, IOC graph, search, lookup, and API key management

📝 Detailed Logging – all enrichment activity is logged to:$SPLUNK_HOME/var/log/splunk/enrichioc.log


📋 Prerequisites
Before installing, ensure the following:

Splunk Enterprise 9.2+ or Splunk Cloud

Python 3.7+ runtime

API Keys for OTX, AbuseIPDB, GreyNoise, URLHaus - (Free version/Paid)

KV Store enabled

Admin role for installation and setup

Outbound HTTPS access to enrichment APIs

Index Creation: The app expects an index named ti_enrich for storing enrichment results. You can create it by adding the following stanza to indexes.conf (on the same server or on your indexer):

[ti_enrich]
homePath   = $SPLUNK_DB/ti_enrich/db
coldPath   = $SPLUNK_DB/ti_enrich/colddb
thawedPath = $SPLUNK_DB/ti_enrich/thaweddb
maxTotalDataSizeMB = 5000
frozenTimePeriodInSecs = 7776000   # 90 days retention
Uncomment and copy this stanza to your local folder if creating locally or configure it on your indexer(s) if running in a distributed environment


⚙️ Installation
Install the App
Package as .spl and install via Manage Apps → Install app from file

Restart Splunk if prompted

Configure API Keys

Use the Threat Intel API Key Configuration dashboard
Enter API keys for OTX, AbuseIPDB, GreyNoise, URLHaus
Keys are stored in the ti_api_keys lookup (masked in UI)

KV Store Collections Ensure these collections exist (auto‑created if not):

ioc_cache
edges
nodes
campaign_cache

🔎 Usage
Enrich IOCs
| enrichioc value="8.8.8.8"


📊 Dashboards
1. Executive Threat Intelligence Summary
High‑level overview for SOC managers and executives: IOC volumes, risk distribution, top countries, active campaigns, and recent critical IOCs.

2. IOC Graph & Campaign Summaries
Interactive analyst dashboard: IOC relationship graph with drilldown into campaign summaries and IOC details. Campaign summaries are AI‑generated for readability.

3. IOC Search (IOC Hits on My Network)
Investigator dashboard: enter comma‑delimited IOCs, search across all indexes, return counts and time ranges, with drilldown to raw events.

4. IOC Enrichment Lookup
Quick lookup for a single IOC using | enrichioc. Displays live enrichment results and cached IOC details, including AI‑generated IOC summaries.

5. Threat Intel API Key Configuration
Admin dashboard: manage API keys for OTX, AbuseIPDB, GreyNoise, and URLHaus. Keys are masked and stored in ti_api_keys.

🧪 Testing
Run enrichment on known IOCs or any malicious IOCs

Check logs at:

$SPLUNK_HOME/var/log/splunk/enrichioc.log
Verify KV Store entries in ioc_cache and campaign_cache

Open dashboards to confirm data populates

Troubleshooting

Check logs at:$SPLUNK_HOME/var/log/splunk/enrichioc.log 
Enrich repeated IOCs directly from API instead of cache use below refresh=true
Eg:
| enrichioc value="8.8.8.8" refresh=true
