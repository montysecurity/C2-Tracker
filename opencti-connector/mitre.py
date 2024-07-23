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
    mitre = check_mitre()
    if mitre:
        indicators = get_current_indicators()
        malware = get_malware()
        tools = get_tools()
        create_relationships(indicators, tools=malware)
        create_relationships(indicators, tools)

main()