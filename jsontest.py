#! bin/sh/ python
#!/usr/bin/env python

##
# Author: Preston Ruff
# Organization: IU: CACR
# Filename: jsontest.py
# Date: 06/05/2018
##

import json
with open('CVE-Modified/nvdcve-1.0-modified.json', 'r') as fp:
    try:
        obj = json.load(fp)
    except ValueError:
        print("error loading JSON")
a = 0
b = 0
for item in obj['CVE_Items']:
    cve = item['cve']
    cve_id = cve['CVE_data_meta']['ID']
    #print("--",cve_id,"--")
    probtype = cve['problemtype']
    for field in probtype['problemtype_data']:
        cwe = field['description']
        for item in cwe:
            b += 1
            #print(item['value'])
        if b != 1:
            print(cve_id,"has",b,"description fields")
        b = 0
