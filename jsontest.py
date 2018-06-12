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
#finds CVE's which have multiple CWE fields
def checkMultiCWE(b,cveID):
        if b > 1:
            print(cveID,"has",b,"CWE's")
    
#the number of CWE's is determined by the number of desciption fields present
#finds CVE's which do not have any CWE fields
def checkNoCWE(b,cveID):
        if b == 0:
            print(cveID,"has",b,"CWE's")

def main():
    with open('CVE-2017/nvdcve-1.0-2017.json', 'r') as fp:
        try:
            obj = json.load(fp)
        except ValueError:
            print("error loading JSON")
    a = 0
    b = 0
    cveCount = 0
    jsonOut = dict()
    fileOutPath = "edited-nvdcve-1.0-2017.json"
    fileOut = open(fileOutPath, 'w')
    for item in obj['CVE_Items']:
        cve = item['cve']
        config = item['configurations']
        impact = item['impact']
        publishedDate = item['publishedDate']
        lastModifiedDate = item['lastModifiedDate']
        cveID = cve['CVE_data_meta']['ID']
        #print("--",cve_id,"--")
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
        #maybe attempt to get each of those fields by name using json but use a try except statement to prevent runtime failure if the field doesnt exist in an CVE_Items entry
        if tmp == 0:
            pass
        elif "** REJECT **" in item:
            pass
        else:
            cve.update(config)
            jsonOut.update(cve)
            #might have to use json.dumps('"configurations" : {')
            #json.dumps('}')

            #json.dumps(',') put this after very last field
            #json.dump(cve, fileOut, indent=2)

            cveCount = cveCount + 1
    json.dump(jsonOut, fileOut)
#configurations
#impact
#publishedDate
#lastModifiedDate
    print(cveCount,"CVE's written to",fileOutPath)
    fileOut.close()
if __name__ == "__main__":
    main()


