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

def sumFreq(fPath):
    with open(fPath, 'r+') as fpA:
        readerA = csv.reader(fpA, delimiter=',')
        writerA = csv.writer(fpA)
        with open(fPath, 'r+') as fpB:
            readerB = csv.reader(fpB, delimiter=',')
            #test to see what happens if I edit the file with one filepointer while the other filepointer is reading below its location in the file
            #am I even allowed to open the file in more than one location,
            #I can't remember what happens to fp's when you make edits from multiple locations at the same time
            #I will have to go through the file again and remove the lines which are equal to '\n'
            #the only way to do this will be to omit writing those lines out as I read in the rows of the csv file
            #then I have to go through the file again and sort the file by highest frequency
            #I will just save each non-nl line to a tuple and feed it to a sorting function
            #then I will overwrite the csv lines with the sorted list/tuple
            #since I will need to put the items into a list anyway, I should just maintain a list from the main function, wait to sort until I confirm that I am done adding new ID elements,
            #then call the sumFreq() function to sum the elements and sort them using a pointer to the list
            #research seems to suggest that passing large objects (i.e. a list) as a parameter to a function are not especially inefficient as they are in C unless specifically done by reference (a pointer)
            #then call writeOut() to actually write my completed work to the CSV file
            c = 0
            length = 0
            for row in readerA:
                length = length + 1
            fpA.seek(0,0)
            for row in readerA:
                if c != 0: #in order to "edit" a csv file, it looks like you have to rewrite the whole file but omit or rewrite lines which do not meet your criteria
                    #row[1] = "ayylmao"
                    fpA.write('')
                c = c + 1
            for row in readerB:
                print(row)
            

            '''
            c = 0
            length = 0
            for row in reader:
                length = length + 1
            while c <= length
                for row in reader:
                    if i == 0:
                    curID = row[0]
                    curFreq = row[1]

                    c = c + 1
            c = 0
                    break


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
    if fp == fileInList[0] and args.writemethod == 'w':
        csvFile = open(fileOut, 'w', newline='')
    else:
        csvFile = open(fileOut, 'a', newline='')
'''

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("outputfile", help="Output filename for CSV file.")
    parser.add_argument("writemethod", choices=['w','a'], help="Output file write method:'w' flag to overwrite existing file or create a new file.'a' flag to append to existing file.")
    parser.add_argument("inputfile", nargs='+', help="Input filename for JSON file. To parse multiple JSON files, write the '-i' option before each filename.")
    if not len(sys.argv) > 1:
        parser.print_help()
        sys.exit()
    args = parser.parse_args()
    if args.writemethod == 'a':
        if os.path.isfile(args.outputfile) == False:
            print("Write Method Error: cannot use 'a' option if outputfile does not exist")
            print("Hint: change 'a' flag to 'w' flag to create a new output file (or overwrite an existing file!)")
            sys.exit()
    #print("read the inputfile args:", args.inputfile)
    #print("read the outputfile args:", args.outputfile)

    fileInList = args.inputfile
    fileOut = args.outputfile
    #fileInList = ["CVE-2017/nvdcve-1.0-2017.json"]
    #fileIn = 'edited-nvdcve-1.0-2017.json'
    #fileOut = "sortedCWE.csv"

    #save individual CWE-ID references
    for fp in fileInList:
        with open(fp, 'r') as fpIn:
            try:
                obj = json.load(fpIn)
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

        row = str()
        count = 0
        freqList = list() 
        idList = list()

        #minimize CWE-ID reference duplicates and increment their frequency count
        while cweList:
            for x in cweList:
                tmp = x
                count = count + 1
                cweList.remove(x)
                if tmp not in cweList:
                    freqList.append(count)
                    idList.append(tmp)
                    count = 0

        if fp == fileInList[0] and args.writemethod == 'w':
            csvFile = open(fileOut, 'w', newline='')
        else:
            csvFile = open(fileOut, 'a', newline='')

        #side effect: converts lists to tuples when sorting the lists using a shared index
        freqList, idList = zip(*sorted(zip(freqList, idList), reverse=True))
        freqList = list(freqList)
        #plotFreq(freqList, idList)
        #csv.write("CWE ID" + "," + "Frequency\n")
        writer = csv.writer(csvFile)
        if fp == fileInList[0]:
            writer.writerow(("CWE ID", "Frequency"))
        for i, val in enumerate(freqList):
            #text = str(val) + idList[i]
            #sortedFile.write(text)
            row = idList[i], str(val)
            writer.writerow(row)
            #writer.writerows([[str(val)], [idList[i]]])
    if(len(fileInList) > 1):
        csvFile.close()
        sumFreq(fileOut)
    else:
        csvFile.close()
if __name__ == "__main__":
    main()
