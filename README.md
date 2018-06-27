# Readme
Note: this is a *markdown* file (.md) whose style formatting is best seen by using a markdown viewer or by viewing this file directly on the github.com repository from a web browser.

#### About
This purpose of the project is to determine the most frequent computer security weaknesses encountered in the wild. This is done by taking JSON file(s) containing CVEs and counting the CWEs referenced within. An optional bar chart plotting script `plotFreq.py` is included for visualization of your data. Otherwise the CSV file output from `countCWE.py`contains the raw frequency data and must be run to create the file which `plotFreq.py` uses to display its charts.

#### File Index
* Readme.md - the file you are reading now
* report.md - a more comprehensive description of this project
* countCWE.py - counts the frequency of CWE occurrences in a given 	JSON dataset of CVEs
* plotFreq.py - uses the output CSV file from *countCWE.py* to plot standard frequency and relative (ratio) frequency bar graphs of CWEs
* LICENSE - the terms of use of this project

#### Requirements
* Python 3.XX
* *plotFreq.py* requires you to install matplotlib
If you have pip installed you may install matplotlib by running `pip install matplotlib`

#### Usage
Run `python countCWE.py -h` or `python plotFreq.py -h` for respective usage. 


#### Additional Documentation
Use one of the following commands: `pydocs countCWE` or `pydocs plotFreq` to get an outline of function documentation of functions implemented in *countCWE.py* and *plotFreq.py* respectively. The comments displayed from using pydoc are also available in the actual python code but if you do not wish to view the entire source code then it is nice to know that the pydoc command exists.
