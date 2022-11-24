import os
from shodan import Shodan

def shodan():
    api_key = os.environ["SHODAN_API_KEY"].strip()
    api = Shodan(api_key)
    # https://michaelkoczwara.medium.com/hunting-c2-with-shodan-223ca250d06f
    # https://michaelkoczwara.medium.com/cobalt-strike-c2-hunting-with-shodan-c448d501a6e2
    # https://twitter.com/MichalKoczwara/status/1591750513238118401?cxt=HHwWgsDUiZGqhJcsAAAA
    queries = {
        "Cobalt Strike": [
            "ssl.cert.serial:146473198",
            "hash:-2007783223 port:50050",
            "ssl.jarm:07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2",
            "product:'Cobalt Strike Beacon'"
            ],
        "Metasploit Framework": [ "ssl:MetasploitSelfSignedCA" ],
        "Covenant": [ "ssl:Covenant http.component:Blazor" ],
        "Mythic": [ "ssl:Mythic port:7443" ],
        "Brute Ratel C4": [ "http.html_hash:-1957161625" ],
        "Posh C2": [ "ssl:P18055077" ],
        "Sliver": [ "ssl:multiplayer ssl:operators" ]
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
    print(f"Initial Count for all: {initial_count_all}\nNew Count for all: {new_count_all}")

def main():
    shodan()

main()
