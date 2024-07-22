# C2 Tracker

C2 Tracker is a free-to-use-community-driven IOC feed that uses [Shodan](https://www.shodan.io/) and [Censys](https://search.censys.io/) searches to collect IP addresses of known malware/botnet/C2 infrastructure.

## Honorable Mentions

Many of the queries have been sourced from other CTI researchers:

- [BushidoToken](https://twitter.com/BushidoToken)
- [Michael Koczwara](https://twitter.com/MichalKoczwara)
- [ViriBack](https://twitter.com/ViriBack)
- [Gi7W0rm](https://twitter.com/Gi7w0rm)
- [Glacius_](https://twitter.com/Glacius_)
- [corumir](https://github.com/corumir)

Huge shoutout to them!

Thanks to [BertJanCyber](https://twitter.com/BertJanCyber) for creating the [KQL query](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Threat%20Hunting/TI%20Feed%20-%20MontySecurity%20C2%20Tracker%20All%20IPs.md) for ingesting this feed

And finally, thanks to [Y_nexro](https://twitter.com/Y_NeXRo) for creating [C2Live](https://github.com/YoNixNeXRo/C2Live) in order to visualize the data

## Usage

The most recent collection will be stored in `data/`. The IPs are seperated by the name of the tool and there is an `all.txt` that contains all of the IPs. As it currently stands this feed updates `weekly` on Monday.

### Ingestion/Alerting

- If your SIEM/EDR/TIP has the ability to ingest data from a remote source than you can use the files in their raw text format. See BertJanCyber's KQL query above as an example
- FortinetSIEM 7.2.0 added support for this intel feed - `https://docs.fortinet.com/document/fortisiem/7.2.0/release-notes/553241/whats-new-in-7-2-0`

### Investigations/Historical Analysis

- The repo, by its nature, has version control. This means you can search the history of the repo for when an IP was present in the results. I have used one of my other public tools, [GitHub Repo OSINT Tool](https://github.com/montysecurity/GROT), for this purpose.

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
    - [Empire](https://github.com/EmpireProject/Empire)
    - [Ares](https://github.com/sweetsoftware/Ares)
    - [Hak5 Cloud C2](https://shop.hak5.org/products/c2)
    - [Pantegana](https://github.com/cassanof/pantegana)
    - [Supershell](https://github.com/tdragon6/Supershell/tree/main)
    - Poseidon C2
    - Viper C2
    - [UnamWebPanel](https://github.com/UnamSanctam/UnamWebPanel)
    - [Vshell](https://github.com/veo/vshell)
- Malware
    - AcidRain Stealer
    - Misha Stealer (AKA Grand Misha)
    - Patriot Stealer
    - RAXNET Bitcoin Stealer
    - Titan Stealer
    - Collector Stealer
    - [Mystic Stealer](https://twitter.com/_montysecurity/status/1643164749599834112)
    - [Gotham Stealer](https://twitter.com/FalconFeedsio/status/1705765083429863720)
    - [Meduza Stealer](https://twitter.com/g0njxa/status/1717563999984717991?t=rcVyVA2zwgJtHN5jz4wy7A&s=19)
    - Quasar RAT
    - ShadowPad
    - AsyncRAT
    - DcRat
    - BitRAT
    - DarkComet Trojan
    - XtremeRAT Trojan
    - NanoCore RAT Trojan
    - Gh0st RAT Trojan
    - DarkTrack RAT Trojan
    - njRAT Trojan
    - Remcos Pro RAT Trojan
    - Poison Ivy Trojan
    - Orcus RAT Trojan
    - ZeroAccess Trojan
    - HOOKBOT Trojan
    - [RisePro Stealer](https://github.com/noke6262/RisePro-Stealer)
    - NetBus Trojan
    - Bandit Stealer
    - Mint Stealer
    - Mekotio Trojan
    - Gozi Trojan
    - Atlandida Stealer
- Tools
    - [XMRig Monero Cryptominer](https://xmrig.com/)
    - [GoPhish](https://getgophish.com/)
    - [Browser Exploitation Framework (BeEF)](https://github.com/beefproject/beef)
    - [BurpSuite](https://portswigger.net/burp)
    - [Hashcat](https://hashcat.net/hashcat/)
- Botnets
    - [7777](https://gi7w0rm.medium.com/the-curious-case-of-the-7777-botnet-86e3464c3ffd)
    - [BlackNET](https://github.com/suriya73/BlackNET)
    - Doxerina
    - Scarab

## Running Locally

If you want to host a private version, put your Shodan API key in an environment variable called `SHODAN_API_KEY`, and setup your Censys credentials in `CENSYS_API_ID` & `CENSYS_API_SECRET`

```bash
python3 -m pip install -r requirements.txt
python3 tracker.py
```

## Contributing

I encourage opening an issue/PR if you know of any additional Shodan/Censys searches for identifying adversary infrastructure. I will not set any hard guidelines around what can be submitted, just know, **fidelity is paramount** (high true/false positive ratio is the focus).

## References

- [Hunting C2 with Shodan by Michael Koczwara](https://michaelkoczwara.medium.com/hunting-c2-with-shodan-223ca250d06f)
- [Hunting Cobalt Strike C2 with Shodan by Michael Koczwara](https://michaelkoczwara.medium.com/cobalt-strike-c2-hunting-with-shodan-c448d501a6e2)
- [https://twitter.com/MichalKoczwara/status/1591750513238118401?cxt=HHwWgsDUiZGqhJcsAAAA](https://twitter.com/MichalKoczwara/status/1591750513238118401?cxt=HHwWgsDUiZGqhJcsAAAA)
- BushidoToken's [OSINT-SearchOperators](https://github.com/BushidoUK/OSINT-SearchOperators/blob/main/ShodanAdversaryInfa.md)
- [https://twitter.com/MichalKoczwara/status/1641119242618650653](https://twitter.com/MichalKoczwara/status/1641119242618650653)
- [https://twitter.com/MichalKoczwara/status/1641676761283850241](https://twitter.com/MichalKoczwara/status/1641676761283850241)
- [https://twitter.com/_montysecurity/status/1643164749599834112](https://twitter.com/_montysecurity/status/1643164749599834112)
- [https://twitter.com/ViriBack/status/1713714868564394336](https://twitter.com/ViriBack/status/1713714868564394336)
- [https://gi7w0rm.medium.com/the-curious-case-of-the-7777-botnet-86e3464c3ffd](https://gi7w0rm.medium.com/the-curious-case-of-the-7777-botnet-86e3464c3ffd)
- [https://twitter.com/Glacius_/status/1731699013873799209](https://twitter.com/Glacius_/status/1731699013873799209)