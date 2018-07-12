#! /usr/bin/env python

##
# Author: Preston Ruff
# Filename: countCWE.py
##

"""
Collect, count, and sort CWE references from CVE data feeds.

Analyzes CVE data from NVD JSON data feeds and sorts contained CWE references
by decreasing frequency of occurence.

Bugs: the optional CWE research view input file does not have the names of CWEs 
of the type 'category' so no text will be seen in the name section for those CWEs
in the file outputed by countCWE.py
"""

import argparse
import json
import csv
import sys
import os
from copy import deepcopy

def sumFreq(cweList):
    """Determine frequency of CWE occurences and sort by frequency

    Frequency is determined by the number of lines which contain a respective
    CWE-ID within cweList.

    Args:
        cweList: an unsorted list containing CWE-ID's,
            many of which are repeated

    Returns:
        A tuple which contains the following lists: 
        1. minimized (no repeating elements) list of cweID's 
        2. frequency list of CWE-ID occurences.
        The above lists are sorted together using the frequency values.

    Todo:
        If I decide to get more fields from the CWE CSV dictionary file, I can simply change my titledict values to be the entire row of the input csv file (except for the raw ID number in the first column), then I can call python's csv library and provide a given string to the csv function as long as I make the string iterable by doing something like iter(string) before giving it to the csv parsing function. Then I can index each field such as the CWE description field/column
    """

    cweList.sort()
    idList = list()
    freqList = list()
    freq = 0
    lastFreq = 0
    tmp = ""
    line = ""

    tmp = cweList[0]
    if tmp:
        freq = 1
    for line in cweList[1:]:
        if line == tmp:
            freq = freq + 1
        else:
            idList.append(tmp)
            freqList.append(freq)
            tmp = line
            freq = 1
        lastFreq = freq
    idList.append(line)
    freqList.append(lastFreq)

    freqList, idList = zip(*sorted(zip(freqList, idList), reverse=True))
    return (freqList, idList)

def main():
    #command line interface
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--namefile', help="a NIST CSV file \
            which contains the CWE ID number data in column 1 \
            and the CWE name data in column 2. This is used to map the \
            CWE list to Names/Titles of the respective ID's")
    parser.add_argument("PKoutputFile", help="Output filename for CVEs containing a 7PK CWE and at least one more CWE reference (CSV file).")
    parser.add_argument("dupsOutputFile", help="Output filename for CVEs containing more than one CWE reference but no 7PK CWEs (CSV file).")
    parser.add_argument("inputfile", nargs='+', \
    help="Input filename(s) separated by spaces (JSON file).")
    args = parser.parse_args()
    PKfileOut = args.PKoutputFile
    DupsFileOut = args.dupsOutputFile
    fileInList = args.inputfile

    #save individual/raw CWE-ID references
    cweList = list()
    repeatList = list()
    PKreview = list()
    genDupreview = list()
    tmpRepeatList = list()
    cveRepeatCount = 0
    cveCount = 0
    cveNoneCount = 0
    for fp in fileInList:
        with open(fp, 'r') as fpIn:
            try:
                obj = json.load(fpIn)
            except ValueError:
                print("Error: failure when trying to load inputfile:" "'",fp,"'")
                print("Hint: retry using an input file with a JSON format")
                print("exiting now..")
                sys.exit()
        for item in obj['CVE_Items']:
            cveCount = cveCount + 1
            num = 0
            cve = item['cve']
            present = False
            probtype = cve['problemtype']
            for field in probtype['problemtype_data']:
                cwe = field['description']
                for el in cwe:
                    cweList.append(el['value'])
                    repeatList.append(el['value'])
                    num = num + 1
            if num > 1:
                cve = cve['CVE_data_meta']
                cve = cve['ID']
                repeatList.insert(0,cve)
                #for item in repeatList[1:]:
                for item in repeatList:
                    cweList.pop() #CVEs with CWE quantity > 1 must first be analyzed
                    #print(item,len(item))
                    if item == "CWE-254":
                    #    print(repeatList)
                        present = True
                if present is False:
                    genDupreview.append(repeatList[:])
                else:
                    PKreview.append(repeatList[:])
                present = False
                cveRepeatCount = cveRepeatCount + 1
                num = 0
                 
                del repeatList[:]
            elif num == 0:
                cveNoneCount = cveNoneCount + 1
            del repeatList[:]
    #sorted so that the quantity of CWEs in an entry is increasing
    PKreview.sort(key=len)
    genDupreview.sort(key=len)
    print("print starting PKreview printoff")
    #print(PKreview)
    #print(genDupreview)
    print(cveRepeatCount, "CVEs had multiple CWEs out of %s CVEs processed." % cveCount)
    print(cveNoneCount, "CVEs contained no CWE reference.")

    csvFile = open(PKfileOut, 'w', newline='')
    writer = csv.writer(csvFile)
    writer.writerow(("CVEID", "CWEID"))
    cveID = ""
    row = ""
    for i, val in enumerate(PKreview):
        for j,el in enumerate(val):
            if j == 0:
                cveID = el
            elif j == 1:
                row = cveID + el
                writer.writerow([cveID, el])
            else:
                row = "," + el
                writer.writerow(["", el])
    csvFile.close()

    csvFile = open(DupsFileOut, 'w', newline='')
    writer = csv.writer(csvFile)
    writer.writerow(("CVEID", "CWEID"))
    cveID = ""
    row = ""
    for i, val in enumerate(genDupreview):
        for j,el in enumerate(val):
            if j == 0:
                cveID = el
            elif j == 1:
                row = cveID + el
                writer.writerow([cveID, el])
            else:
                row = "," + el
                writer.writerow(["", el])
    csvFile.close()
if __name__ == "__main__":
    main()
