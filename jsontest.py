#! bin/sh/ python
#!/usr/bin/env python

##
# Author: Preston Ruff
# Organization: IU: CACR
# Filename: jsontest.py
# Date: 06/05/2018
# Todo: make better variable names
#       match code to google python style guideline
##

import json

#the number of CWE's is determined by the number of desciption fields present
def checkMultiCWE(b):
        if b > 1:
            print(cve_id,"has",b,"CWE's")
    
#the number of CWE's is determined by the number of desciption fields present
def checkNoCWE(b):
        if b == 0:
            print(cve_id,"has",b,"CWE's")

def main():
    with open('../CVE-2017/nvdcve-1.0-2017.json', 'r') as fp:
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

            # uncomment to run desired functions below
            checkMultiCWE(b) 
            #checkNoCWE(b)
            b = 0

if __name__ == "__main__":
    main()
