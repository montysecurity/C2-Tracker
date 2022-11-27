# C2 Tracker

This repo houses the code I made to mine various C2/malware IPs from Shodan. The searches used were sourced from [Michael Koczwara's](https://michaelkoczwara.medium.com/) and [@BushidoToken's (Will's)](https://twitter.com/BushidoToken) research (see references below). Huge thanks to the both of them!

## What do I track?

- C2's
    - [Cobalt Strike](https://www.cobaltstrike.com/)
    - [Metasploit Framework](https://www.metasploit.com/)
    - [Covenant](https://github.com/cobbr/Covenant)
    - [Mythic](https://github.com/its-a-feature/Mythic)
    - [Brute Ratel C4](https://bruteratel.com/)
    - [Posh](https://github.com/nettitude/PoshC2)
    - [Sliver](https://github.com/BishopFox/sliver)
    - [Deimos](https://github.com/DeimosC2/DeimosC2)
    - PANDA
- Malware
    - AcidRain Stealer
    - Misha Stealer (AKA Grand Misha)
    - Patriot Stealer
    - RAXNET Bitcoin Stealer
    - Titan Stealer
    - Collector Stealer
- Tools
    - [Hashcat Cracking Tool](https://hashcat.net/hashcat/)
    - [BurpSuite](https://portswigger.net/burp)
    - [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
    - [XMRig Monero Cryptominer](https://xmrig.com/)

## Current State

I currently have this script running nightly on a crontab and automatically updating the files in `data`. There is a backup of the data in `backup`, this is not touched by the automation and will occassionally be updated manually.

*Last Backup: 11/27/2022*

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
- BushidoToken's [OSINT-SearchOperators](https://github.com/BushidoUK/OSINT-SearchOperators/blob/main/ShodanAdversaryInfa.md)
