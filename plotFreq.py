#! /usr/bin/env python

##
# Author: Preston Ruff
# Filename: plotFreq.py
##

"""
Plots the frequency of CWE references.

The CSV file used as input must have the following requirements:
A CSV header using the format 'CWE-ID, Frequency'. The  data must match the
header format in that there must be two columns. Furthermore they must contain
the following data types in respective column order, 'string, integer'.
"""

import csv
import argparse
import matplotlib.pyplot as plt
import numpy as np

def plotFreq(freq, cweID):
    """Plots the frequency of CWE references in two different bar graphs.
    Bar graph A displays the frequency directly.
    Bar graph B displays the relative frequency using a ratio of
    the frequency sum.

    Args:
        freq: a list of numbers indicating frequency of respective
            cweID occurences. This is sorted by descending order.
        cweID: a list of CWE-ID's sorted against the freq list.
    """
    plt.figure(1)
    y_pos = np.arange(len(cweID))
    s = sum(freq)
    rf = freq
    #get relative frequency
    for i, val in enumerate(rf):
        rf[i] = val/s

    #configure bar graph A
    plt.barh(y_pos, freq, align='center')
    plt.yticks(y_pos, cweID)
    plt.title('CWE frequency in CVE data feed')
    plt.ylabel('CWE ID')
    plt.xlabel('Frequency of CWE occurance')
    plt.figure(2)

    #configure bar graph B
    y_pos = np.arange(len(cweID))
    plt.barh(y_pos, rf, align='center')
    plt.yticks(y_pos, cweID)
    plt.title('CWE relative frequency in CVE data feed')
    plt.ylabel('CWE ID')
    plt.xlabel('Relative Frequency of CWE occurance')

    #display all graphs
    plt.show()

def main():
    #command line interface
    parser = argparse.ArgumentParser()
    parser.add_argument("inputfile", help="Input filename for CSV file.")
    args = parser.parse_args()
    fileIn = args.inputfile

    freq = list()
    cweID = list()

    with open(fileIn, newline='') as f:
        reader = csv.reader(f)
        next(reader, None) #skip CSV header line
        for row in reader:
            cweID.append(row[0])
            freq.append(int(row[1]))
    plotFreq(freq, cweID)

if __name__ == "__main__":
    main()
