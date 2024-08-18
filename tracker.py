import os
from dotenv import load_dotenv
from shodan import Shodan, exception
from censys.search import CensysHosts

def shodan():
    api_key = os.environ["SHODAN_API_KEY"].strip()
    api = Shodan(api_key)
    # https://michaelkoczwara.medium.com/hunting-c2-with-shodan-223ca250d06f
    # https://michaelkoczwara.medium.com/cobalt-strike-c2-hunting-with-shodan-c448d501a6e2
    # https://twitter.com/MichalKoczwara/status/1591750513238118401?cxt=HHwWgsDUiZGqhJcsAAAA
    # https://github.com/BushidoUK/OSINT-SearchOperators/blob/main/ShodanAdversaryInfa.md
    # https://twitter.com/MichalKoczwara/status/1641119242618650653
    # https://twitter.com/MichalKoczwara/status/1641676761283850241
    queries = {
        "Cobalt Strike C2": [
            "ssl.cert.serial:146473198",
            "hash:-2007783223 port:50050",
            "product:'Cobalt Strike Beacon'",
            "ssl:foren.zik"
        ],
        "Metasploit Framework C2": [
            "ssl:MetasploitSelfSignedCA",
            "http.favicon.hash:-127886975",
            "product:Metasploit"
        ],
        "Covenant C2": [
            "ssl:Covenant http.component:Blazor",
            "http.favicon.hash:-737603591",
            "product:Covenant"
        ],
        "Mythic C2": [
            "ssl:Mythic port:7443",
            "http.favicon.hash:-859291042",
            "product:Mythic"
        ],
        "Brute Ratel C4": [
            "http.html_hash:-1957161625",
            "product:'Brute Ratel C4'"
        ],
        # https://x.com/pedrinazziM/status/1808629285726400879
        "Posh C2": [ 
            "ssl:P18055077",
            "product:PoshC2",
            "http.html_hash:855112502",
            "http.html_hash:-1700067737"
        ],
        "Sliver C2": [
            "ssl:multiplayer ssl.cert.issuer.cn:operators",
            '"HTTP/1.1 404 Not Found" "Cache-Control: no-store, no-cache, must-revalidate" "Content-Length: 0" -"Server:" -"Pragma:"',
            # https://twitter.com/Glacius_/status/1731699013873799209
            "product:'Sliver C2'"
        ],
        "Deimos C2": [
            "http.html_hash:-14029177",
            "product:'Deimos C2'"
        ],
        "PANDA C2":  [
            "http.html:PANDA http.html:layui",
            "product:'Panda C2'"
        ],
        "NimPlant C2" : [
            "http.html_hash:-1258014549"
        ],
        "Havoc C2": [
            "X-Havoc: true",
            "product:Havoc"
        ],
        # https://twitter.com/ViriBack/status/1713714868564394336
        "Caldera C2": [
            "http.favicon.hash:-636718605",
            "http.html_hash:-1702274888",
            'http.title:"Login | CALDERA"'
        ],
        "GoPhish": [
            "http.title:'Gophish - Login'",
        ],
        "AcidRain Stealer": [
            'http.html:"AcidRain Stealer"'
        ],
        "Misha Stealer": [
            "http.title:misha http.component:UIKit"
        ],
        "Patriot Stealer": [
            "http.favicon.hash:274603478",
            "http.html:patriotstealer"
        ],
        "RAXNET Bitcoin Stealer": [
            "http.favicon.hash:-1236243965"
        ],
        "Titan Stealer": [
            "http.html:'Titan Stealer'"
        ],
        "Collector Stealer": [
            'http.html:"Collector Stealer"',
            'http.html:getmineteam'
        ],
        "Mystic Stealer": [
            "http.title:'Mystic Stealer'",
            "http.favicon.hash:-442056565"
        ],
        "Gotham Stealer": [
            "http.title:'Gotham Stealer'",
            "http.favicon.hash:-1651875345"
        ],
        # https://twitter.com/g0njxa/status/1717563999984717991?t=rcVyVA2zwgJtHN5jz4wy7A&s=19
        "Meduza Stealer": [
            "http.html_hash:1368396833",
            "http.title:'Meduza Stealer'"
        ],
        "XMRig Monero Cryptominer": [
            "http.html:XMRig",
            "http.favicon.hash:-782317534",
            "http.favicon.hash:1088998712"
        ],
        # https://gi7w0rm.medium.com/the-curious-case-of-the-7777-botnet-86e3464c3ffd
        "7777 Botnet": [
            "hash:1357418825"
        ],
        # https://www.team-cymru.com/post/botnet-7777-are-you-betting-on-a-compromised-router
        "63256 Botnet" : [
            "hash:1771530908 port:63256"
        ],
        "Quasar RAT": [
            "product:'Quasar RAT'"
        ],
        "ShadowPad" : [
            "product:ShadowPad"
        ],
        "AsyncRAT": [
            "product:AsyncRAT"
        ],
        "DcRAT": [
            "product:DcRat"
        ],
        "BitRAT": [
            "product:BitRAT"
        ],
        "Empire C2": [
            "product:'Empire C2'"
        ],
        "DarkComet Trojan": [
            "product:'DarkComet Trojan'"
        ],
        "XtremeRAT Trojan": [
            "product:'XtremeRAT Trojan'"
        ],
        "NanoCore RAT Trojan": [
            "product:'NanoCore RAT Trojan'"
        ],
        "Gh0st RAT Trojan": [
            "product:'Gh0st RAT Trojan'"
        ],
        "DarkTrack RAT Trojan": [
            "product:'DarkTrack RAT Trojan'"
        ],
        "njRAT Trojan": [
            "product:'njRAT Trojan'"
        ],
        "Remcos Pro RAT Trojan": [
            "product:'Remcos Pro RAT Trojan'"
        ],
        "Poison Ivy Trojan": [
            "product:'Poison Ivy Trojan'"
        ],
        "Orcus RAT Trojan": [
            "product:'Orcus RAT Trojan'"
        ],
        "Ares RAT C2": [
            "product:'Ares RAT C2'"
        ],
        "ZeroAccess Trojan": [
            "product:'ZeroAccess Trojan'"
        ],
        "Hookbot": [
            "http.title:'Hookbot Panel'"
        ],
        # Credit: https://github.com/corumir
        "Hak5 Cloud C2": [
            "product:'Hak5 Cloud C2'",
            "http.favicon.hash:1294130019"
        ],
        # Credit: https://github.com/corumir
        # Tool: https://github.com/suriya73/BlackNET
        "BlackNET Botnet": [
            "http.title:'BlackNet - Login'"
        ],
        "Doxerina Botnet": [
            "http.title:'Doxerina BotNet'"
        ],
        # Credit: https://github.com/corumir
        # Tool: https://github.com/noke6262/RisePro-Stealer
        "RisePro Stealer": [
            "'Server: RisePro'"
        ],
        # Credit: https://github.com/corumir
        # Tool: https://github.com/cassanof/pantegana
        "Pantegana C2": [
            "ssl:Pantegana ssl:localhost",
            "ssl.cert.issuer.cn:'Pantegana Root CA'"
        ],
        # Credit: https://github.com/corumir
        # Tool: https://github.com/tdragon6/Supershell/tree/main
        "Supershell C2": [
            "http.html_hash:84573275",
            "http.favicon.hash:-1010228102",
            "http.title:'Supershell - 登录'"
        ],
        "Viper C2": [
            "http.html_hash:-1250764086"
        ],
        "Poseidon C2": [
            "http.favicon.hash:219045137",
            "http.html_hash:-1139460879",
            "hash:799564296"
        ],
        "Scarab Botnet": [
            "http.title:'Scarab Botnet PANEL'"
        ],
        "Bandit Stealer": [
            "http.title:Login http.html:'Welcome to Bandit' 'Content-Length: 4125' port:8080"
        ],
        "NetBus Trojan": [
            "product:'NetBus Trojan'"
        ],
        "UnamWebPanel": [
            "html:unam_lib.js http.favicon.hash:-1278680098,-1531496738",
            "http.title:'Unam Web Panel &mdash; Login'"
        ],
        "Atlandida Stealer": [
            "http.title:'Atlantida' http.html:'GY7HXsD.jpg'"
        ],
        "Vshell C2": [
            "http.title:'Vshell - 登录'"
        ],
        "BurpSuite": [
            "product:BurpSuite"
        ],
        "Hachcat": [
            "product:'Hachcat Cracking Tool'"
        ],
        "MobSF": [
            "http.title:'Mobile Security Framework - MobSF'"
        ],
        "Villain C2": [
            "hash:856668804"
        ],
        "SpyAgent": [
            "http.title:'SpY-Agent v1.2'"
        ],
        "RedGuard C2": [
            "http.status:307 http:'307 Temporary Redirect Content-Type: text/html; charset=utf-8 Location: https://360.net'"
        ],
        "SpiceRAT": [
            "http.headers_hash:1955818171 http.html_hash:114440660"
        ]
    }

    # https://www.techiedelight.com/delete-all-files-directory-python/
    dir_to_clean = "data"
    for file in os.scandir(dir_to_clean):
        os.remove(file.path)

    ip_set_from_all_products = set()
    for product in queries:
        ip_set_from_product = set()
        product_ips_file = open(f"data/{product} IPs.txt", "a")
        for query in queries[product]:
            print(f"Product: {product}, Query: {query}")
            results = api.search_cursor(query)
            # Catch Shodan Query Errors and pass onto the next C2
            # TODO: make it restart main() while keeping track of what was already documented
            try:
                for result in results:
                    ip = str(result["ip_str"])
                    ip_set_from_product.add(ip)
                    ip_set_from_all_products.add(ip)
            except exception.APIError:
                continue
        for ip in ip_set_from_product:
            product_ips_file.write(f"{ip}\n")

    all_ips_file = open("data/all.txt", "a")
    for ip in ip_set_from_all_products:
        all_ips_file.write(f"{ip}\n")

def censys():
    queries = {
        "RisePro Stealer": [
            "services.http.response.headers: (key: `Server` and value.headers: `RisePro`)",
            "services.software.product:RisePro"
        ],
        "Viper C2": [
            "services.software.product=`VIPER`"
        ],
        "Poseidon C2": [
            "services.http.response.html_title=`POSEIDON`"
        ],
        "Scarab Botnet": [
            "services.software.product=`Scarab`"
        ],
        "Cobalt Strike C2": [
            "services.software.product=`Cobalt Strike`"
        ],
        "AsyncRAT": [
            "services.software.product=`AsyncRAT`"
        ],
        "Supershell C2": [
            "services.software.product=`Supershell`"
        ],
        "Hak5 Cloud C2": [
            "services.software.product=`Cloud C2`"
        ],
        "Gh0st RAT Trojan": [
            "services.service_name:`GHOST`"
        ],
        "DarkComet Trojan": [
            "services.service_name:`DARKCOMET`"
        ],
        "DarkGate Loader": [
            "services.service_name:`DARKGATE`"
        ],
        "Sliver C2": [
            "services.software.product:`SLIVER`"
        ],
        "ShadowPad": [
            "services.software.product:`SHADOWPAD`"
        ],
        "Mint Stealer": [
            "services.software.product=`Mint Stealer`"
        ],
        "Mekotio Trojan": [
            "services.software.product=`Mekotio`"
        ],
        "Gozi Trojan": [
            "services.software.product=`Gozi`"
        ],
        "Browser Exploitation Framework (BeEF)": [
            "services.software.product=`Browser Exploitation Framework (BeEF)`"
        ],
        "Mythic C2": [
            "services.software.product:`Mythic`"
        ],
        "Vshell C2": [
            "services.software.product=`Vshell`",
            "services.http.response.html_title:'Vshell - 登录'"
        ],
        "Hookbot": [
            "services.software.product:`Hookbot`"
        ],
        "Quasar RAT": [
            "services.software.product:`Quasar`"
        ],
        "Havoc C2": [
            "services.software.product:`Havoc`"
        ],
        "Atlandida Stealer": [
            "services: (http.response.html_title:`Atlantida` and http.response.body:`GY7HXsD.jpg`)"
        ],
        "VenomRAT": [
            "services.software.product:VenomRAT"
        ],
        "Orcus RAT": [
            "services.software.product:Orcus"
        ],
        "DcRAT": [
            "services.software.product:DcRat"
        ],
        "Posh C2": [
            "services.software.product:PoshC2"
        ],
        "Deimos C2": [
            "services.software.product:DeimosC2"
        ],
        "Covenant C2": [
            "services.software.product:Covenant"
        ],
        "BitRAT": [
            "services.software.product:BitRAT"
        ],
        "BlackDolphin": [
            "services.software.product:BlackDolphin"
        ],
        "Artemis RAT": [
            "services.software.product:'Artemis Rat'"
        ],
        "Godzilla Loader": [
            "services.software.product:godzilla-loader"
        ],
        "Jinx Loader": [
            "services.software.product:JinxLoader"
        ],
        "Neptune Loader": [
            "services.software.product:neptune-loader"
        ],
        "NimPlant C2": [
            "services.software.product:NimPlant"
        ],
        "Ares RAT C2": [
            "services.software.product:'Ares RAT'"
        ],
        "Villain C2": [
            "services.banner='whoami\\n'"
        ],
        "SpyAgent": [
            "services.http.response.html_title:'SpY-Agent v1.2'",
            "services.software.product=`Spy-Agent`"
        ],
        # https://www.team-cymru.com/post/botnet-7777-are-you-betting-on-a-compromised-router
        "63256 Botnet": [
            "services.port:63256 and services.banner_hashes='sha256:13e9b4b65e60bd9c8e58232591012fa6e2240a7b348ccdd611490e17d00b25f6'"
        ]
    }
    h = CensysHosts()
    all_ips = set()
    for product in queries:
        ips = set()
        product_ips_file = open(f"data/{product} IPs.txt", "a")
        for search_string in queries[product]:
            print(f"Product: {product}, Query: {search_string}")
            query = h.search(search_string)
            results = None
            try:
                results = query()
            except Exception as err:
                print(err)
                continue
            for host in results:
                ip = str(host['ip'])
                all_ips.add(ip)
                ips.add(ip)
        for ip in ips:
            product_ips_file.write(f"{ip}\n")
    all_ips_file = open("data/all.txt", "a")
    for ip in all_ips:
        all_ips_file.write(f"{ip}\n")

def deconflict():
    # Remove any duplicates from the files
    files = os.listdir("data/")
    for file in files:
        filepath = f"data/{file}"
        f = open(filepath, "r")
        lines = f.readlines()
        f.close()
        if len(lines) != len(set(lines)):
            print(f"Deconflicting: {filepath}")
            os.remove(filepath)
            f = open(filepath, "a")
            for line in set(lines):
                f.write(line)
            f.close()

def main():
    load_dotenv()
    shodan()
    censys()
    deconflict()

if __name__ == '__main__':
    main()
