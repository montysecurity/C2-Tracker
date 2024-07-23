# Work in Progress

The basic idea is to grab the data from C2-Tracker and import it into OpenCTI.

- Wipe data and restart every 7 days
- Group by malware/tool
- Create relationships

## Scripts

- `ingest.py`: pull the current dataset from github via HTTPS, add as "indicators"
- `mitre.py`: relationships between IPs and mitre tools (requires MITRE ATT&CK connector)
- `purge.py `: delete all indicators with label "c2-tracker"