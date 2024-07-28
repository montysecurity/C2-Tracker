# OpenCTI Connector

Ingest data [C2 Tracker Data](https://github.com/montysecurity/C2-Tracker/tree/main/data) into an [OpenCTI](https://github.com/OpenCTI-Platform/opencti) instance.

## Features

- Import C2 Tracker IOCs as Indicators in OpenCTI in STIX format
- Intelligently manage Indicators
    - Delete indicators if they are no longer seen in C2 Tracker
    - Use "c2-tracker" label to avoid deleting unrelated IOCs
    - Link indicators to MITRE tools and malware (requires [MITRE Connector](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/mitre))
- Docker compose file is configured to automatically launch the image on boot
- The script will automatically restart if an error is encountered

## Install (Docker) (Recommended)

1. Create a user with "Connector" & "Default" roles, take note of the Token that is made and put it in an environment variable called `OPENCTI_C2TRACKER_TOKEN`
2. Download the repo: `git clone https://github.com/montysecurity/C2-Tracker.git`
3. Navigate to connector: `cd C2-Tracker/opencti-connector/`
4. Review `docker-compose.yml` and update `OPENCTI_URL` if necessary
5. Run `docker-compose up -d`

## Install (Standalone Python)

Requires Python 3

1. Create a user with "Connector" & "Default" roles, take note of the Token that is made and put it in an environment variable called `OPENCTI_C2TRACKER_TOKEN`
2. Download the repo: `git clone https://github.com/montysecurity/C2-Tracker.git`
3. Navigate to connector: `cd C2-Tracker/opencti-connector/`
4. Review `src/connector.py` variables `api_url` and `api_token`; set environment variable `OPENCTI_URL`
5. Install packages: `pip3 install --upgrade pip && pip3 install requests pycti`
6. Run `src/connector.py`
7. Set Cron Job or Service to run `src/connector.py` when OpenCTI starts up

## Purge Script

There is a script at `opencti-connector/src/purge.py` that is not executed by the docker container. It solely exists to allow the operator to easily delete all of the indicators that were made by this connector. It relies on the label `c2-tracker` to identify those.