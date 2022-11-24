#!/bin/bash

python3 tracker.py && git commit -a -m "Nightly Auto Update" && git push
