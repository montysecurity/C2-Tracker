from pycti import OpenCTIApiClient
import os

api_url = os.getenv("OPENCTI_URL")
api_token = os.getenv("OPENCTI_C2TRACKER_TOKEN")
opencti_api_client = OpenCTIApiClient(api_url, api_token)

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

def main():
    delete_current_indicators()

main()