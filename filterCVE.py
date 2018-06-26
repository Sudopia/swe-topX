#! /usr/bin/env python

##
# Author: Preston Ruff
# Filename: filterJSON.py
##

"""
Removes CVE entries which do not have CWE fields
or have a CVE status of 'reject'.
"""

import json

def checkMultiCWE(b,cveID):
    """This function find CVE's which have multiple CWE fields.
    The number of CWE's is determined by the number of desciption fields present.
    """
    if b > 1:
        print(cveID,"has",b,"CWE's")
    
def checkNoCWE(b,cveID):
    """This function finds CVE's which do not have any CWE fields.
    The number of CWE's is determined by the number of desciption fields present.
    """
    if b == 0:
        print(cveID,"has",b,"CWE's")

def main():
    with open('/home/pruff/Dropbox/swe-topX/CVE-XXXX/nvdcve-1.0-2013.json', 'r') as fp:
        try:
            obj = json.load(fp)
        except ValueError:
            print("error loading JSON")
    a = 0
    b = 0
    cveCount = 0
    jsonOut = dict()
    fileOutPath = "filtered_CVES/edited-nvdcve-1.0-2013.json"
    fileOut = open(fileOutPath, 'w')
    fieldlist = ['cve', 'configurations', 'impact', 'publishedDate', 'lastModifiedDate']
    delCVEs = 0
    for item in obj['CVE_Items']:
        cve = item['cve']
        config = item['configurations']
        impact = item['impact']
        publishedDate = item['publishedDate']
        lastModifiedDate = item['lastModifiedDate']
        cveID = cve['CVE_data_meta']['ID']
        probtype = cve['problemtype']
        for field in probtype['problemtype_data']:
            cwe = field['description']
            for el in cwe:
                b += 1

            # uncomment to run desired functions below
            #checkMultiCWE(b,cveID)
            #checkNoCWE(b,cveID)

            tmp = b
            b = 0
        if tmp == 0:
            for i in fieldlist:
                if i in item:
                    del item[i]
            delCVEs = delCVEs + 1
        elif "** REJECT **" in item:
            for i in fieldlist:
                if i in item:
                    del item[i]
            delCVEs = delCVEs + 1
        else:
            cveCount = cveCount + 1

    json.dump(obj, fileOut, indent=2)
    print(delCVEs, "CVE's removed")
    print(cveCount,"CVE's written to",fileOutPath)
    fileOut.close()
if __name__ == "__main__":
    main()

