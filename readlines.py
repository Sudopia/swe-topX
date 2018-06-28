#! /usr/bin/evn python


import argparse
import csv

"""
Can read from a csv file by reading in the entire csv file into 
a variable in memory. Is still able to use the CSV library to parse the 
various CSV data columns.
"""
def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("titlefile", help="Input filename for CSV file.")
    args = parser.parse_args()
    titlefile = args.titlefile

    f = open(titlefile, 'r')
    allLines = f.readlines()

    reader = csv.reader(iter(allLines))
    print("starting program ..")
    for row in reader:
        print(row[1], row[0])

    #for line in allLines:
    #    print(line[1])

if __name__ == "__main__":
    main()

