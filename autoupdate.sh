#!/bin/bash

git pull && python3 tracker.py && echo && echo && git add . && find -size 0c -delete && git commit -a -m "Nightly Auto Update" && git push