import requests
import urllib
import re
from time import sleep
from pycti import OpenCTIApiClient
import os
from dateutil.parser import parse
from datetime import date, timedelta, datetime
from stix2 import TLP_WHITE

api_url = "http://192.168.1.78:8080"
api_token = os.getenv("OPENCTI_C2TRACKER_TOKEN")
opencti_api_client = OpenCTIApiClient(api_url, api_token)

def get_current_c2_tracker_ips():
    print("[+] Getting Current IOCs...")
    all_ips = set()
    url = "https://github.com/montysecurity/C2-Tracker/tree/main/data"
    request = requests.get(url)
    tools = list(set(re.findall("\"[\w|\s|\d|\.]+IPs\.txt\"", request.text)))
    i = 0
    for tool in tools:
        tools[i] = str(tool).strip('"')
        i += 1
    for tool in tools:
        print(f"[+] Looking at {tool}")
        url = str("https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/" + str(tool).replace(" ", "%20"))
        request = requests.get(url)
        # Get IPs for C2
        ips = str(request.text).split("\n")
        # Remote empty newline
        ips.pop()
        for ip in ips:
            all_ips.add(ip)
    return all_ips

def add_indicator(c2, ip):
    malwares = opencti_api_client.indicator.list()
    #print(malwares)
    date_now = str(date.today().strftime("%Y-%m-%dT%H:%M:%SZ"))
    # Create the tag (if not exists)
    label = opencti_api_client.label.create(
        value="c2-tracker",
        color="#ffa500",
    )

    # Get TLP Clear ID
    TLP_WHITE_CTI = opencti_api_client.marking_definition.read(id=TLP_WHITE["id"])
    
    # Create indicator
    print(c2 + " --- " + ip)
    indicator = opencti_api_client.indicator.create(
        name=f"{c2} IP - {ip}",
        description=f"This IP is was recently seen hosting {c2}",
        pattern=f"[ipv4-addr:value = '{str(ip)}']",
        pattern_type="stix",
        x_opencti_main_observable_type="IPv4-Addr",
        valid_from=date_now,
        update=True,
        confidence=100,
        markingDefinitions=[TLP_WHITE_CTI["id"]]
    )

    # Add label to indicator
    opencti_api_client.stix_domain_object.add_label(id=indicator["id"], label_id=label["id"])

def update_opencti():
    print("[+] Adding IOCs")
    # Create variable to hold all IPs
    # will be used to compare against current IPs in OpenCTI
    # Will delete any IPs in OpenCTI and not in the all_ips variable
    url = "https://github.com/montysecurity/C2-Tracker/tree/main/data"
    request = requests.get(url)
    # Get all file names ending in " IPs.txt"
    tools = list(set(re.findall("\"[\w|\s|\d|\.]+IPs\.txt\"", request.text)))
    # Strip quotes
    i = 0
    for tool in tools:
        tools[i] = str(tool).strip('"')
        i += 1
    for tool in tools:
        url = str("https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/" + str(tool).replace(" ", "%20"))
        request = requests.get(url)
        # Remove " IPs.txt"
        tool = str(tool)[:-8]
        # Get IPs for C2
        ips = str(request.text).split("\n")
        # Remote empty newline
        ips.pop()
        for ip in ips:
            print(f"[+] Adding {tool} IP: {ip}")
            add_indicator(tool, ip)
            # use break for testing 1 IP of all tools
            break

def delete_aged_out_indicators(current_iocs):
    print("[+] Deleting indicators")
    final_indicators = []
    data = {"pagination": {"hasNextPage": True, "endCursor": None}}
    while data["pagination"]["hasNextPage"]:
        after = data["pagination"]["endCursor"]
        if after:
            print("Listing indicators after " + after)
        data = opencti_api_client.indicator.list(
            first=50,
            after=after,
            withPagination=True,
            orderBy="created_at",
            orderMode="asc",
        )
        final_indicators += data["entities"]

    for indicator in final_indicators:
        for i in range(int(len(indicator["objectLabel"]))):
            if str(indicator["objectLabel"][i]["value"]) == "c2-tracker":
                ioc = str(indicator["name"]).split(" - ")[1]
                if ioc not in current_iocs:
                    print(f"[+] Deleting {ioc}")
                    opencti_api_client.stix_domain_object.delete(id=indicator["id"])

def check_mitre():
    mitre = False

    final_malware = []
    data = {"pagination": {"hasNextPage": True, "endCursor": None}}
    while data["pagination"]["hasNextPage"] and mitre == False:
        after = data["pagination"]["endCursor"]
        if after:
            print("Listing indicators after " + after)
        data = opencti_api_client.malware.list(
            first=50,
            after=after,
            withPagination=True,
            orderBy="created_at",
            orderMode="asc",
        )
        for malware in data["entities"]:
            if str(malware["createdBy"]["name"]) == "The MITRE Corporation":
                mitre = True
                print("MITRE is enabled")
                break
    return mitre

def get_current_indicators():
    final_indicators = []
    data = {"pagination": {"hasNextPage": True, "endCursor": None}}
    while data["pagination"]["hasNextPage"]:
        after = data["pagination"]["endCursor"]
        if after:
            print("Listing indicators after " + after)
        data = opencti_api_client.indicator.list(
            first=50,
            after=after,
            withPagination=True,
            orderBy="created_at",
            orderMode="asc",
        )
        final_indicators += data["entities"]

    for indicator in final_indicators:
        for i in range(int(len(indicator["objectLabel"]))):
            if str(indicator["objectLabel"][i]["value"]) == "c2-tracker":
                print(indicator["name"] + " --- " + indicator["id"])
    return final_indicators

def get_malware():
    final_malware = []
    data = {"pagination": {"hasNextPage": True, "endCursor": None}}
    while data["pagination"]["hasNextPage"]:
        after = data["pagination"]["endCursor"]
        if after:
            print("Listing indicators after " + after)
        data = opencti_api_client.malware.list(
            first=50,
            after=after,
            withPagination=True,
            orderBy="created_at",
            orderMode="asc",
        )
        final_malware += data["entities"]
    
    return final_malware

def get_tools():
    final_tools = []
    data = {"pagination": {"hasNextPage": True, "endCursor": None}}
    while data["pagination"]["hasNextPage"]:
        after = data["pagination"]["endCursor"]
        if after:
            print("Listing indicators after " + after)
        data = opencti_api_client.tool.list(
            first=50,
            after=after,
            withPagination=True,
            orderBy="created_at",
            orderMode="asc",
        )
        final_tools += data["entities"]
    
    return final_tools

def create_relationships(indicators, tools):
    # Create the tag (if not exists)
    label = opencti_api_client.label.create(
        value="c2-tracker",
        color="#ffa500",
    )
    TLP_WHITE_CTI = opencti_api_client.marking_definition.read(id=TLP_WHITE["id"])


    mapping = {
        # MITRE: C2Tracker
        "Mythic": "Mythic C2 IP",
        "Cobalt Strike": "Cobalt Strike C2 IP",
        "NanoCore": "NanoCore RAT Trojan IP",
        "njRAT": "njRAT Trojan IP",
        "ShadowPad": "ShadowPad IP",
        "DarkComet": "DarkComet Trojan IP",
        "AsyncRAT": "AsyncRAT IP",
        "Brute Ratel C4": "Brute Ratel C4 IP",
        "Empire": "Empire C2 IP",
        "Sliver": "Sliver C2 IP",
        "Remcos": "Remcos Pro RAT Trojan IP"
    }
    indicator_tool_malware_names = set()
    for i in indicators:
        indicator_tool_malware_names.add(str(i["name"]).split(" - ")[0])

    tool_names = set()
    for t in tools:
        tool_names.add(str(t["name"]))
    
    for i in indicators:
        n = str(i["name"]).split(" - ")[0]
        for m in mapping:
            if mapping[m] == n:
                for t in tools:
                    if t["name"] == m:
                        print(n, "---", m)
                        print(i)
                        print()
                        print(t)
                        relationship = opencti_api_client.stix_core_relationship.create(
                            fromType=str(i["entity_type"]),
                            fromId=str(i["id"]),
                            toType=str(t["entity_type"]),
                            toId=str(t["id"]),
                            relationship_type="indicates",
                            first_seen=str(date.today().strftime("%Y-%m-%dT%H:%M:%SZ")),
                            last_seen=str(date.today().strftime("%Y-%m-%dT%H:%M:%SZ")),
                            description="This is a server hosting the tool",
                            markingDefinitions=[TLP_WHITE_CTI["id"]]
                        )
                        # Add label to indicator
                        opencti_api_client.stix_core_relationship.add_label(id=relationship["id"], label_id=label["id"])

def main():
    current_iocs = get_current_c2_tracker_ips()
    delete_aged_out_indicators(current_iocs)
    update_opencti()
    mitre = check_mitre()
    if mitre:
        indicators = get_current_indicators()
        malware = get_malware()
        tools = get_tools()
        create_relationships(indicators, tools=malware)
        create_relationships(indicators, tools)

main()