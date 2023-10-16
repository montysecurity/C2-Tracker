# C2 Tracker

Free to use IOC feed for various tools/malware. Uses [Shodan](https://www.shodan.io/) searches to collect the IPs. The most recent collection is always stored in `data`; the IPs are broken down by tool and there is an `all.txt`.

The feed should update daily. *Actively working on making the backend more reliable*

## Honorable Mentions

Many of the Shodan queries have been sourced from other CTI researchers:

- [BushidoToken](https://twitter.com/BushidoToken)
- [Michael Koczwara](https://twitter.com/MichalKoczwara)
- [ViriBack](https://twitter.com/ViriBack)

Huge shoutout to them!

Thanks to [BertJanCyber] for creating the [KQL query](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Threat%20Hunting/TI%20Feed%20-%20MontySecurity%20C2%20Tracker%20All%20IPs.md) for ingesting this feed

And finally, thanks to [Y_nexro](https://twitter.com/Y_NeXRo) for creating [C2Live](https://github.com/YoNixNeXRo/C2Live) in order to visualize the data

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
    - [NimPlant C2](https://github.com/chvancooten/NimPlant)
    - [Havoc C2](https://github.com/HavocFramework/Havoc)
    - [Caldera](https://caldera.mitre.org/)
- Malware
    - AcidRain Stealer
    - Misha Stealer (AKA Grand Misha)
    - Patriot Stealer
    - RAXNET Bitcoin Stealer
    - Titan Stealer
    - Collector Stealer
    - [Mystic Stealer](https://twitter.com/_montysecurity/status/1643164749599834112)
    - [Gotham Stealer](https://twitter.com/FalconFeedsio/status/1705765083429863720)
- Tools
    - [Hashcat Cracking Tool](https://hashcat.net/hashcat/)
    - [BurpSuite](https://portswigger.net/burp)
    - [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
    - [XMRig Monero Cryptominer](https://xmrig.com/)
    - [GoPhish](https://getgophish.com/)

### Running Locally

If you want to host a private version, put your Shodan API key in an environment variable called `SHODAN_API_KEY`

```bash
echo SHODAN_API_KEY=API_KEY >> ~/.bashrc
bash
python3 -m pip install -r requirements.txt
python3 tracker.py
```

## References

- [Hunting C2 with Shodan by Michael Koczwara](https://michaelkoczwara.medium.com/hunting-c2-with-shodan-223ca250d06f)
- [Hunting Cobalt Strike C2 with Shodan by Michael Koczwara](https://michaelkoczwara.medium.com/cobalt-strike-c2-hunting-with-shodan-c448d501a6e2)
- [https://twitter.com/MichalKoczwara/status/1591750513238118401?cxt=HHwWgsDUiZGqhJcsAAAA](https://twitter.com/MichalKoczwara/status/1591750513238118401?cxt=HHwWgsDUiZGqhJcsAAAA)
- BushidoToken's [OSINT-SearchOperators](https://github.com/BushidoUK/OSINT-SearchOperators/blob/main/ShodanAdversaryInfa.md)
- [https://twitter.com/MichalKoczwara/status/1641119242618650653](https://twitter.com/MichalKoczwara/status/1641119242618650653)
- [https://twitter.com/MichalKoczwara/status/1641676761283850241](https://twitter.com/MichalKoczwara/status/1641676761283850241)
- [https://twitter.com/_montysecurity/status/1643164749599834112](https://twitter.com/_montysecurity/status/1643164749599834112)
- [https://twitter.com/ViriBack/status/1713714868564394336](https://twitter.com/ViriBack/status/1713714868564394336)