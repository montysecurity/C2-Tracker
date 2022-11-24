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

I currently have this script running nightly on a crontab and automatically updating the files in `data`. There is a backup of the data in `backup`, this is not touched by the automation and will occassionally be updated manually.

*Last Backup: 11/24/2022*

### Running Locally

However if you want to host a private version, put your Shodan API key in an environment variable called `SHODAN_API_KEY`

```bash
echo SHODAN_API_KEY=API_KEY >> ~/.bashrc
bash
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
