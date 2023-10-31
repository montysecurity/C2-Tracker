import os
from dotenv import load_dotenv
from shodan import Shodan

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
            "ssl.jarm:07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2",
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
        "Posh C2": [ 
            "ssl:P18055077",
             "product:PoshC2"
             ],
        "Sliver C2": [
            "ssl:multiplayer ssl:operators",
            '"HTTP/1.1 404 Not Found" "Cache-Control: no-store, no-cache, must-revalidate" "Content-Length: 0" -"Server:" -"Pragma:"'
            ],
        "Deimos C2": [
            "http.html_hash:-14029177",
            "product:'Deimos C2'",
            "http.title:'Deimos C2'"
            ],
        "PANDA C2":  [ "http.html:PANDA http.html:layui" ],
        "NimPlant C2" : [
            "http.html_hash:-1258014549"
            ],
        "Havoc C2": [ "X-Havoc: true" ],
        # https://twitter.com/ViriBack/status/1713714868564394336
        "Caldera C2": [
            "http.favicon.hash:-636718605",
            "http.html_hash:-1702274888",
            'http.title:"Login | CALDERA"'
        ],
        "GoPhish": [
            "http.title:'Gophish - Login'",
        ],
        "AcidRain Stealer": [ 'http.html:"AcidRain Stealer"' ],
        "Misha Stealer": [ "http.title:misha http.component:UIKit" ],
        "Patriot Stealer": [
            "http.favicon.hash:274603478",
            "http.html:patriotstealer"
        ],
        "RAXNET Bitcoin Stealer": [ "http.favicon.hash:-1236243965" ],
        "Titan Stealer": [ 'http.html:"Titan Stealer"' ],
        "Hachcat Cracking Tool": [ "http.html:hashcat"],
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
            "http.html_hash:1368396833"
        ],
        "BurpSuite": [ "http.html:BurpSuite" ],
        "PowerSploit" : [ "http.html:PowerSploit" ],
        "XMRig Monero Cryptominer": [
            "http.html:XMRig",
            "http.favicon.hash:-782317534",
            "http.favicon.hash:1088998712"
        ],
        # https://gi7w0rm.medium.com/the-curious-case-of-the-7777-botnet-86e3464c3ffd
        "7777 Botnet": [
            "hash:1357418825"
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
        "DcRat": [
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
        ]
    }

    # https://www.techiedelight.com/delete-all-files-directory-python/
    dir_to_clean = "data"
    for file in os.scandir(dir_to_clean):
        os.remove(file.path)

    ip_set_from_all_products = set()
    count_of_all_ips = 0
    count_of_products = 0
    for product in queries:
        count_of_products += 1
        count_of_product_ips = 0
        ip_set_from_product = set()
        product_ips_file = open(f"data/{product} IPs.txt", "a")
        for query in queries[product]:
            print(f"Product: {product}, Query: {query}")
            results = api.search_cursor(query)
            # Catch Shodan Query Errors and restart the script
            if "APIError" in results:
                print("Shodan Error...restarting")
                main()
            for result in results:
                ip = str(result["ip_str"])
                ip_set_from_product.add(ip)
                ip_set_from_all_products.add(ip)
        for ip in ip_set_from_product:
            product_ips_file.write(f"{ip}\n")
            count_of_product_ips += 1
        print(f"- Created data/{product} IPs.txt")
        if count_of_product_ips == 1:
            print(f"- Documented {count_of_product_ips} IP address\n\n")
        elif count_of_product_ips > 1:
            print(f"- Documented {count_of_product_ips} unique IP addresses\n\n")

    all_ips_file = open("data/all.txt", "a")
    for ip in ip_set_from_all_products:
        all_ips_file.write(f"{ip}\n")
        count_of_all_ips += 1
    print("\n- Created data/all.txt")
    print(f"- Searched for {count_of_products} different tools/malware")
    if count_of_all_ips == 1:
        print(f"- Documented {count_of_all_ips} IP address")
    elif count_of_all_ips > 1:
        print(f"- Documented {count_of_all_ips} unique IP addresses")

def main():
    load_dotenv()
    shodan()

if __name__ == '__main__':
    main()