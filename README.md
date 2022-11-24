# C2 Tracker

This repo houses the code I made to mine various C2 IPs from Shodan. The searches used were sourced from [Michael Koczwara's Research](https://michaelkoczwara.medium.com/) (see references below).

# Current Metrics

- Suspected C2 Servers: 2,641
    - Cobalt Strike: 1,757
    - Metaploit Framework: 603
    - Covenant: 33
    - Mythic: 55
    - Brute Ratel C4: 9
    - Posh C2: 9

- (Those numbers don't add up so I suspect a few IPs are housing multiple C2s, see future state)

## Current State

This script is automated and will run nightly to update *data/\** so there is no need for you to run it locally.

### Running Locally

However if you want to host a private version, fill out the API key field on line 5 and run the following, then automate it however you wish (e.g. crontab):

```bash
python3 -m pip install -r requirements.txt
python3 tracker.py
```

## Future State

- Write scripts to analyze DNS/WHOIS info
- Build automation into the script
- Write script to identify servers with multiple frameworks running
- Track metrics over time

## References

- [Hunting C2 with Shodan by Michael Koczwara](https://michaelkoczwara.medium.com/hunting-c2-with-shodan-223ca250d06f)
- [Hunting Cobalt Strike C2 with Shodan by Michael Koczwara](https://michaelkoczwara.medium.com/cobalt-strike-c2-hunting-with-shodan-c448d501a6e2)
- [This tweet](https://twitter.com/MichalKoczwara/status/1591750513238118401?cxt=HHwWgsDUiZGqhJcsAAAA)
