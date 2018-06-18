#! /usr/bin/env python

##
# Author: Preston Ruff
# Filename: countCWE.py
##

'''
Get list of referenced CWEs and sort them by 
decreasing frequency of occurence
'''

import json, csv
def main():
    fileIn = 'CVE-2017/nvdcve-1.0-2017.json'
    #fileIn = 'edited-nvdcve-1.0-2017.json'
    with open(fileIn, 'r') as fp:
        try:
            obj = json.load(fp)
        except ValueError:
            print("error loading JSON")
    cweList = list()
    for item in obj['CVE_Items']:
        try:
            cve = item['cve']
            probtype = cve['problemtype']
            for field in probtype['problemtype_data']:
                cwe = field['description']
                for el in cwe:
                    cweList.append(el['value'])
        except:
            pass

    with open("CWE.csv", 'w') as csvFile:
        writer = csv.writer(csvFile)
        for x in cweList:
            writer.writerow([x])

    row = str()
    count = 0
    freqList = list() 
    idList = list()

    while cweList:
        for x in cweList:
            tmp = x
            count = count + 1
            cweList.remove(x)
            if tmp not in cweList:
                freqList.append(count)
                idList.append(tmp)
                count = 0
    with open("sortedCWE.csv", 'w') as sortedFile:
        #converts lists to tuples when sorting the lists using a shared index
        freqList, idList = zip(*sorted(zip(freqList, idList), reverse=True))
        for i,val in enumerate(freqList):
            text = str(val) + ',' + idList[i] + '\n'
            sortedFile.write(text)
if __name__ == "__main__":
    main()
