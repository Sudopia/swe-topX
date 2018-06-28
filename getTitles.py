#! /usr/bin/env python



import csv
import argparse

#cweIndex = '/home/pruff/Dropbox/swe-topX/cwedevelopmentconcepts/699.csv'

def main():
    #command line interface
    parser = argparse.ArgumentParser()
    parser.add_argument("freqfile", help="Input filename for CSV file.")
    parser.add_argument("titlefile", help="Input filename for CSV file.")
    args = parser.parse_args()
    freqfile  = args.freqfile
    titlefile = args.titlefile

    cweID = ""
    title = ""
    freqf = open(freqfile, 'r', newline='')
    readfreqs = csv.reader(freqf)
    writefreqs = csv.writer(freqf)
    next(readfreqs, None) #skip CSV header line
    titlef = open(titlefile, 'r+', newline='')
    readtitles = csv.reader(titlef)
    next(readtitles, None) #skip CSV header line

    for rowA in readfreqs:
        cweID_A = rowA[0][4:]
        for rowB in readtitles:
            title = rowB[1]
            cweID_B = rowB[0]
            if cweID_B == cweID_A:
                changedline = str(rowA[0]),str(rowA[1]),str(title)
                writefreqs.writerow(changedline) 
        titlef.seek(0,0)
    freqf.close()
    titlef.close()
if __name__ == "__main__":
    main()
