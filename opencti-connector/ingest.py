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


def get_ips():
    url = "https://github.com/montysecurity/C2-Tracker/tree/main/data"
    request = requests.get(url)
    # Get all file names ending in " IPs.txt"
    matches = list(set(re.findall("\"[\w|\s|\d|\.]+IPs\.txt\"", request.text)))
    # Strip quotes
    i = 0
    for match in matches:
        matches[i] = str(match).strip('"')
        i += 1
    for c2 in matches:
        url = str("https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/" + str(c2).replace(" ", "%20"))
        request = requests.get(url)
        # Remove " IPs.txt"
        c2 = str(c2)[:-8]
        # Get IPs for C2
        ips = str(request.text).split("\n")
        # Remote empty newline
        ips.pop()
        for ip in ips:
            add_indicator(c2, ip)
            # use break for testing 1 IP of all tools
            #break

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



def delete_current_indicators():
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
                opencti_api_client.stix_domain_object.delete(id=indicator["id"])
    
    #final_relationships = []
    #data = {"pagination": {"hasNextPage": True, "endCursor": None}}
    #while data["pagination"]["hasNextPage"]:
    #    after = data["pagination"]["endCursor"]
    #    if after:
    #        print("Listing indicators after " + after)
    #    data = opencti_api_client.stix_core_relationship.list(
    #        first=50,
    #        after=after,
    #        withPagination=True,
    #        orderBy="created_at",
    #        orderMode="asc",
    #    )
    #    final_relationships += data["entities"]
#
    #for relationship in final_relationships:
    #    for i in range(int(len(relationship["objectLabel"]))):
    #        if str(relationship["objectLabel"][i]["value"]) == "c2-tracker":
    #            opencti_api_client.stix_core_relationship.delete(id=relationship["id"])
    

def main():
    delete_current_indicators()
    get_ips()

main()