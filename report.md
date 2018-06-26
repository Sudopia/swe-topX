Project Goal:
To determine the most frequent computer security weaknesses encountered in the wild. This will allow me to publish a report of issues for software development teams to mitigate. I will determine the size of my list of weaknesses once I have looked at the data and minimized some security weakness classification categories.

Project Description: 
When a novel security vulnerability is discovered, a Common Vulnerability and Exposure (CVE) record is published to the Mitre corpororation who then adds it to their CVE database which is provided for public use. Other organizations such as National Institute of Standard and Technology (NIST) provide copies of the Mitre CVE database and even add additional info such as risk evaluations and alternative file types of database downloads. So in order to determine the frequency of security weaknesses I downloaded from NIST, JSON formatted data feeds containing CVE records for the last 5 years. So data from the years 2013-2017 were used. The field of data I gathered from each of the CVE records is the ID number of the CWEs that the CVE was classified under. A CWE, or common weakness enumeration, serves to describe what category of security weakness allowed the vulnerability described in a CVE to occur.

I then counted the frequency of each CWE encountered in my dataset. CWE classifications can be too specific in some cases where they are used to describe a given common problem as applied to a specific software vendor's product. Since the problem is the same regardless of the vendor, including vendor specific CWEs sometimes contributes to the sprawl of classification categories. Further, some CWEs problems which are very similar to other CWEs. Sometimes these problems can be merged into a slightly more general problem name. The idea is that if I can minimize or condense CWE listings then I can provide software development teams with a more actionable list for them to consider.

I wrote two python scripts: one to count the CWEs and write the CWE IDs and associated frequencies into a comma separated file (CSV), the other to display a couple simple bar graphs of the frequencies. For the latter, I included a bar graph of the actual frequency of each CWE as well as a relative frequency bar graph showing the percentage of the total number of CWEs that each ID instance comprises.

Description:
Common Vulnerabilities and Exposures (CVEs)  have many duplicate entries due to posting of subentries which belong to the same parent exposure or vulnerability group. Further, multiple software vendors claim CVEs as unique within their respective software applications. By considering each of these instances to be considered duplicate, CVE listings can be simplified. Additionally, CVEs which are not in an appropriate or active status can be removed from the database to enable further simplification. The statuses to be removed include:

special statuses
A vulnerability is discovered in 2015 and a request is made for a CVE ID in 2015. The vulnerability is assigned "CVE-2015-NNNN" but not made public. (The CVE ID would appear as "Reserved" in the CVE List.) The discloser does not publish the CVE ID publicly until 2017, though. In this case, the CVE ID is still "CVE-2015-NNNN", despite the fact that the vulnerability isn't made public until 2017. 

CVE IDs have the format CVE-YYYY-NNNNN. The YYYY portion is the year that the CVE ID was assigned OR the year the vulnerability was made public (if before the CVE ID was assigned). Where N is of arbitrary length greater or equal to 4.
The year portion is not used to indicate when the vulnerability was discovered, but only when it was made public or assigned.

Site showing difference between CVE,CWE, and CVSS.
So once I make my list of top N weakness types, I could sort those containing CVSS values to determine the priority of the issues assuming I dont go to broad in my categorization.so maybe not but the compare/contrast info at this website is still useful for my report background information.
source: https://www.acunetix.com/blog/articles/better-scan-results-cvss-cve-cwe/

Data to be analyzed:
I retrieved yearly CVE reports from the National Vulnerability Database (NVD) as provided by National Institute of Standard and Technology (NIST). I downloaded the JSON data feed versions of CVE reports given from years 2013 through 2017.
The files were obtained from the following link: https://nvd.nist.gov/vuln/data-feeds


