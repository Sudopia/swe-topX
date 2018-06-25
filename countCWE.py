#! /usr/bin/env python

##
# Author: Preston Ruff
# Filename: countCWE.py
##

'''
Get list of referenced CWEs and sort them by 
decreasing frequency of occurence
'''

import json, csv, sys, os

def plotFreq(freq, cweId):
    import matplotlib.pyplot as plt
    import numpy as np

    plt.figure(1)
    y_pos = np.arange(len(cweId))
    plt.barh(y_pos, freq, align='center')
    plt.yticks(y_pos, cweId)
    plt.title('CWE frequency in the 2017 CVE data feed')
    plt.ylabel('CWE ID')
    plt.xlabel('Frequency of CWE occurance')

    s = sum(freq)
    rf = freq

    #get relative frequency
    for i, val in enumerate(rf):
        rf[i] = val/s 
    #for i,val in enumerate(rf):
    #    print(round(val, 5), cweId[i])
    
    plt.figure(2)
    y_pos = np.arange(len(cweId))
    plt.barh(y_pos, rf, align='center')
    plt.yticks(y_pos, cweId)
    plt.title('CWE relative frequency in the 2017 CVE data feed')
    plt.ylabel('CWE ID')
    plt.xlabel('Relative Frequency of CWE occurance')

    plt.show()

#def sumFreq(cweList):
def sumFreq(cweList):
    
        #cweList = ["jam","jam","cat","dog","dog"]
        #print("init cweList:",cweList)
        cweList.sort()
        #print("sorted cweList:",cweList)
        
        firstLine = True

        idList = list()
        freqList = list()
        freq = 0
        loopNum = 0
        lastFreq = 0
        tmp = ""
        for line in cweList:
            if firstLine == True:
                tmp = line
                freq = 1
                firstLine = False
            else:
                if line == tmp:
                    freq = freq + 1
                else:
                    idList.append(tmp)
                    freqList.append(freq)
                    tmp = line
                    freq = 1
            lastFreq = freq
            #print("loopNum:",loopNum)
            #print("\ttmp:",tmp)
            #print("\tline:",line)
            #print("\tfirstLine:",firstLine)
            loopNum = loopNum + 1
        idList.append(line)
        freqList.append(lastFreq)
        #print("idList:",idList)
        #print("freqList:",freqList)
        
        freqList, idList = zip(*sorted(zip(freqList, idList), reverse=True))
        return (freqList, idList)

        '''
        cweList = ["cat","jam","cat","dog","dog"]
        cweList.sort()
        print("cweList:",cweList)
        count = 0
        freqList = list() 
        idList = list()
        print("A: printing freqList")
        print(freqList)
        print("A: end printing freqList")
        #minimize CWE-ID reference duplicates and increment their frequency count
        tmp = 0
        while cweList:
            firstLine = True
            for x in cweList:
                if firstLine == True:
                    tmp = x
                    count = count + 1
                    cweList.remove(x)
                elif x == tmp:
                    count = count + 1
                    cweList.remove(x)
                print("cweList after remove(x):")
                print(cweList)
                if (tmp not in cweList) and (tmp != 0):
                    freqList.append(count)
                    idList.append(tmp)
                    count = 0
                firstLine = False
            tmp = 0
        print("B: printing freqList")
        print(freqList)
        print("B: end printing freqList")
        #sorts both lists together using the frequency list
        freqList, idList = zip(*sorted(zip(freqList, idList), reverse=True))
        print("printing idList, freqlist")
        for i,val in enumerate(idList):
            print(val,freqList[i])
        return (freqList, idList)
        '''

def psuedoSort(cweList):
    cweList.sort()
    '''
        1. presort the listA
        2. add unique IDs to listB
        3. add associated frequencies to listC
        4. loop to write all B-C pairs to output file
    '''


    return 0

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("outputfile", help="Output filename for CSV file.")
    parser.add_argument("writemethod", choices=['w','a'], help="Output file write method:'w' flag to overwrite existing file or create a new file.'a' flag to append to existing file.")
    parser.add_argument("inputfile", nargs='+', help="Input filename(s) for JSON input files (separate names by a space).")
    if not len(sys.argv) > 1:
        parser.print_help()
        sys.exit()
    args = parser.parse_args()
    if args.writemethod == 'a':
        if os.path.isfile(args.outputfile) == False:
            print("Write Method Error: cannot use 'a' option if outputfile does not exist")
            print("Hint: change 'a' flag to 'w' flag to create a new output file (or overwrite an existing file!)")
            sys.exit()

    fileInList = args.inputfile
    fileOut = args.outputfile
    #fileInList = ["CVE-2017/nvdcve-1.0-2017.json"]
    #fileIn = 'edited-nvdcve-1.0-2017.json'
    #fileOut = "sortedCWE.csv"

    cweList = list()
    #save individual CWE-ID references
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
    count = 0
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
    #plotFreq(freqList, idList)
    csvFile.close()
if __name__ == "__main__":
    main()
