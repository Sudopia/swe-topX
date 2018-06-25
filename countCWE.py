#! /usr/bin/env python

##
# Author: Preston Ruff
# Filename: countCWE.py
##

"""
Collect, count, and sort CWE references from CVE data feeds.

Analyzes CVE data from NVD JSON data feeds and sorts contained CWE references
by decreasing frequency of occurence.
"""

import argparse
import json
import csv
import sys
import os

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
    parser.add_argument("outputfile", help="Output filename for CSV file.")
    parser.add_argument("writemethod", choices=['w', 'a'], \
    help="Output file write method:'w' flag to overwrite existing file or \
    create a new file.'a' flag to append to existing file.")
    parser.add_argument("inputfile", nargs='+', \
    help="Input filename(s) for JSON input files (separate names \
    by a space).")
    args = parser.parse_args()
    if args.writemethod == 'a':
        if os.path.isfile(args.outputfile) == False:
            print("Write Method Error: cannot use 'a' option if outputfile \
            does not exist")
            print("Hint: change 'a' flag to 'w' flag to create a new output \
            file (or overwrite an existing file!)")
            sys.exit()
    fileInList = args.inputfile
    fileOut = args.outputfile

    #save individual/raw CWE-ID references
    cweList = list()
    for fp in fileInList:
        with open(fp, 'r') as fpIn:
            try:
                obj = json.load(fpIn)
            except ValueError:
                print("error loading JSON")
        for item in obj['CVE_Items']:
            cve = item['cve']
            probtype = cve['problemtype']
            for field in probtype['problemtype_data']:
                cwe = field['description']
                for el in cwe:
                    cweList.append(el['value'])
    row = str()
    freqList = list()
    idList = list()

    #a tuple containing two list elements
    freqList = sumFreq(cweList)
    idList = freqList[1]
    freqList = freqList[0]

    if args.writemethod == 'w':
        csvFile = open(fileOut, 'w', newline='')
    else:
        csvFile = open(fileOut, 'a', newline='')

    writer = csv.writer(csvFile)
    if args.writemethod == 'w':
        writer.writerow(("CWE ID", "Frequency"))
    for i, val in enumerate(freqList):
        row = idList[i], str(val)
        writer.writerow(row)
    csvFile.close()

if __name__ == "__main__":
    main()
