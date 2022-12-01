#!/bin/bash

python3 tracker.py && echo && echo && git add . && git commit -a -m "Nightly Auto Update" && git push
