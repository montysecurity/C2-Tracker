import os
from shodan import Shodan

def shodan():
    api_key = os.environ["SHODAN_API_KEY"].strip()
    api = Shodan(api_key)
    # https://michaelkoczwara.medium.com/hunting-c2-with-shodan-223ca250d06f
    # https://michaelkoczwara.medium.com/cobalt-strike-c2-hunting-with-shodan-c448d501a6e2
    # https://twitter.com/MichalKoczwara/status/1591750513238118401?cxt=HHwWgsDUiZGqhJcsAAAA
    # https://github.com/BushidoUK/OSINT-SearchOperators/blob/main/ShodanAdversaryInfa.md
    queries = {
        "Cobalt Strike C2": [
            "ssl.cert.serial:146473198",
            "hash:-2007783223 port:50050",
            "ssl.jarm:07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2",
            "ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1+port:443"
            "product:'Cobalt Strike Beacon'",
            "http.html:'cs4.4'"
            ],
        "Metasploit Framework C2": [
            "ssl:MetasploitSelfSignedCA",
            "http.favicon.hash:-127886975",
            "http.html:msf4"
            ],
        "Covenant C2": [
            "ssl:Covenant http.component:Blazor",
            "http.favicon.hash:-737603591"
            ],
        "Mythic C2": [
            "ssl:Mythic port:7443",
            "http.favicon.hash:-859291042"],
        "Brute Ratel C4": [
            "http.html_hash:-1957161625",
            "product:'Brute Ratel C4'"
            ],
        "Posh": [ "ssl:P18055077" ],
        "Sliver": [
            "ssl:multiplayer ssl:operators",
            "http.html:sliver-client",
            '"HTTP/1.1 404 Not Found" "Cache-Control: no-store, no-cache, must-revalidate" "Content-Length: 0" -"Server:" -"Pragma:"'
            ],
        "Deimos": [ "http.html_hash:-14029177" ],
        "PANDA":  [ 'http.html:"PANDA" http.html:"layui"' ],
        "AcidRain Stealer": [ 'http.html:"AcridRain Stealer"' ],
        "Misha Stealer": [ 'http.title:"misha" http.component:"UIKit"'],
        "Patriot Stealer": [
            "http.favicon.hash:274603478",
            "http.html:'patriotstealer'"
            ],
        "RAXNET Bitcoin Stealer": [ "http.favicon.hash:-1236243965" ],
        "Titan Stealer": [ 'http.html:"Titan Stealer"' ],
        "Hachcat Cracking Tool": [ "http.html:hashcat"],
        "Collector Stealer": [
            'http.html:"Collector Stealer"',
            'http.html:"getmineteam"'
            ],
        "BurpSuite": [ "http.html:BurpSuite" ],
        "PowerSploit" : [ "http.html:PowerSploit" ],
        "XMRig Monero Cryptominer": [
            "http.html:XMRig",
            "http.favicon.hash:-782317534",
            "http.favicon.hash:1088998712"
        ]
    }
    a = open("data/all.txt", "a")
    for product in queries:
        ip_file = f"{product} IPs.txt"
        f = open("data/" + ip_file, "a")
        for query in queries[product]:
            print(f"Search Product: {product}, Query: {query}")
            for i in range(1, 100):
                print(f"- Parsing Page: {i}")
                results = api.search(query, page=i)
                number_of_results = len(results["matches"])
                if number_of_results == 0:
                    print("- Reached last page\n")
                    break
                elif number_of_results > 0:
                    for service in results["matches"]:
                        ip = str(service["ip_str"])
                        f.write(ip + "\n")
                        a.write(ip + "\n")
        seen = set()
        f.close()
        f = open("data/" + ip_file, "r")
        initial_count = 0
        for line in f:
            seen.add(line)
            initial_count += 1
        f.close()
        os.remove("data/" + ip_file)
        new_count = 0
        f = open("data/" + ip_file, "a")
        for ip in seen:
            new_count += 1
            f.write(ip)
        f.close()
        print(f"Total Count for {product}: {initial_count}\nUnique Count for {product}: {new_count}\n\n")
    seen = set()
    a.close()
    initial_count_all = 0
    a = open("data/all.txt", "r")
    for line in a:
        seen.add(line)
        initial_count_all += 1
    a.close()
    os.remove("data/all.txt")
    new_count_all = 0
    a = open("data/all.txt", "a")
    for ip in seen:
        a.write(ip)
        new_count_all += 1
    a.close()
    print(f"Total Count for all: {initial_count_all}\nUnique Count for all: {new_count_all}")

def main():
    shodan()

main()