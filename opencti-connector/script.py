import requests
import urllib
import re
from time import sleep

url = "https://github.com/montysecurity/C2-Tracker/tree/main/data"

request = requests.get(url)
matches = list(set(re.findall("\"[\w|\s|\d|\.]+IPs\.txt\"", request.text)))

i = 0
for match in matches:
    matches[i] = str(match).strip('"')
    i += 1

print(matches)

for c2 in matches:
    url = str("https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/" + str(c2).replace(" ", "%20"))
    request = requests.get(url)
    print(c2)
    print(request.text)
    print()
    sleep(3)