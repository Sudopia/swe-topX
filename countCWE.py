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
    parser.add_argument("outputfile", help="Output filename for CSV file.")
    parser.add_argument("writemethod", choices=['w', 'a'], \
    help="Output file write method:'w' flag to overwrite existing file or \
    create a new file.'a' flag to append to existing file.")
    parser.add_argument("inputfile", nargs='+', \
    help="Input filename(s) for JSON input files (separate names \
    by a space).")
    args = parser.parse_args()
    nameIn = args.namefile
    fileOut = args.outputfile
    fileInList = args.inputfile
    if args.writemethod == 'a':
        if os.path.isfile(args.outputfile) == False:
            print("Write Method Error: cannot use 'a' option if outputfile \
            does not exist")
            print("Hint: change 'a' flag to 'w' flag to create a new output \
            file (or overwrite an existing file!)")
            sys.exit()

    #save individual/raw CWE-ID references
    cweList = list()
    repeatList = list()
    PKreview = list()
    genDupreview = list()
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
                print("printing tmp (aka repeatList)")
                print(tmp)
                present = False
                cveRepeatCount = cveRepeatCount + 1
                #print(cve, "has %s CWEs" % num)
                num = 0
                 
                #for i in repeatList:
                #    print("\t %s" % i)
                #I was having an issue where I couldnt append repeatList to other lists because when I would later delete repeatList, the appended list would also be deleted from the parent list which it had been appended within 
                print(tmp)
                PKreview.append(tmp)
                del repeatList[:]
                print(PKreview)
                sys.exit()
            elif num == 0:
                cveNoneCount = cveNoneCount + 1
            del repeatList[:]
    #PKreview.sort(key=len)
    #genDupreview.sort(key=len)
    print("print starting PKreview printoff")
    print(PKreview)
    print(cveRepeatCount, "CVEs had multiple CWEs out of %s CVEs processed." % cveCount)
    print(cveNoneCount, "CVEs contained no CWE reference.")
    row = str()
    freqList = list()
    idList = list()

    #a tuple containing two list elements
    freqList = sumFreq(cweList)
    idList = freqList[1]
    freqList = freqList[0]

    #for each title/name found, save it to a corresponding CWE-ID 
    if nameIn is not None:
        titleDict = dict()
        titlef = open(nameIn, 'r', newline='')
        readtitles = csv.reader(titlef)
        next(readtitles, None) #skip CSV header line
        for rowA in idList:
            cweID_A = rowA[4:]
            for rowB in readtitles:
                title = rowB[1]
                cweID_B = rowB[0]
                if cweID_B == cweID_A:
                    titleDict[rowA] = title
            titlef.seek(0,0)
        titlef.close()

    if args.writemethod == 'w':
        csvFile = open(fileOut, 'w', newline='')
    else:
        csvFile = open(fileOut, 'a', newline='')

    writer = csv.writer(csvFile)


    if args.writemethod == 'w':
        if nameIn is None:
            writer.writerow(("CWE ID", "Frequency"))
        else:
            writer.writerow(("CWE ID", "Frequency", "Name"))
    freqCount = 0
    for i, val in enumerate(freqList):
        if nameIn is None or idList[i] not in titleDict:
            row = idList[i], str(val)
        else:
            row = idList[i], str(val), titleDict[idList[i]]
        writer.writerow(row)
        freqCount = freqCount + int(val)
    csvFile.close()
    print(freqCount, "CWE elements processed. Of those, %s were unique." % (i+1))
if __name__ == "__main__":
    main()
