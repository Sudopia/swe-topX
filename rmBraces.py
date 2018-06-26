#! /usr/bin/env python

##
# Author: Preston Ruff
# Filename: rmBraces.py
# Todo: make better variable names
#       match code to google python style guideline
##


"""
Removes empty braces from CVE JSON files.

Necessary to be used after filterJSON.py is run.
"""

import re, fileinput
from os import replace

fName = 'filtered_CVES/edited-nvdcve-1.0-2013.json'
fNametmp = fName + ".tmp"
fp = open(fName, 'r+')
fpTmp = open(fNametmp, 'w')

for line in fp:
    if not re.search(r'^ +\{\},' "\n",line):
        fpTmp.write(line)

fp.close()
fpTmp.close()
replace(fNametmp, fName)

