"""
Author: Eric Tang
Date: 1/12/2022
SCAP Project

This program crawls each individual vulnerability page on nipc.org.cn.
The data is then scraped and structured in preparation for Google Spreadsheets.
"""

import write
import requests
from bs4 import BeautifulSoup
import time
url_headers = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36 QIHU 360SE'
}

n = 0 # index
headers = ["name"] # 1 x n of header names


moreVuln = True
check = 0 # if a DNE page occurs 5 times in a row, process ends complete
exist = write.get_values("nipc_type")
if exist:
  n = int(write.get_values("nipc_type")[-1][1])
  headers = write.get_headers(["nipc_type", "nipc_data"])
  #n = 276990

while(moreVuln):
  max = 0
  k = n + 20
  vulns = [] # m x n of NIPC vulns

  while n < k and moreVuln:
    print(n)
    n += 1
    f = ""
    try: 
      f = requests.get("http://www.nipc.org.cn/vulnerability/" + str(n), headers = url_headers)
    except: # Connection attempt failed, retrying
      print("Retrying")
      time.sleep(5)
      f = requests.get("http://www.nipc.org.cn/vulnerability/" + str(n), headers = url_headers)


    soup = BeautifulSoup(f.content, 'lxml')

    #################

    name_tag = soup.findAll("h2", class_="card-title")
    vuln_tags = soup.findAll("div", class_="col-4")
    info_tags = soup.findAll("div", class_="card-text")

    # checks if there's more vulnerabilities, terminates if 20 pages in a row 'DNE'
    if not (name_tag):
      print("DNE: " + str(n))
      check = check + 1
      if n > 1000000:
        moreVuln = False
        print("PROCESS COMPLETE")
      continue
    check = 0

    """
    obtains basic header tags
    from the first vulnerability
    """
    if n == 1:
      for vuln_tag in vuln_tags:
        headers.append((str(vuln_tag).split()[2]).replace("：", ""))
      headers.pop(2)



    v = []

    """
    obtains name header tag 
    """
    v.append(str(name_tag[0])[23:-5])


    """
    obtains basic vulnerability info
    """
    for vuln_tag in vuln_tags:
      if(vuln_tag.a):
        temp = str(vuln_tag.a)[9:-9]
      elif (vuln_tag.span):
        temp = str(vuln_tag.span)[6:-7]
      # ensures there is something to be appended
      if temp != "-":
        v.append(temp)
      else:
          v.append("")

    #########################

    """
    obtains unique attribute tags
    """
    for info_tag in info_tags[2:]:
      header = str(info_tag.h6)[4:-5] # removes <h6> tags
      if header not in headers:
        headers.append(header)
        for i in range(0, len(vulns)):
          vulns[i].append("")
    """
    checks if vulnerability exists within the NVD database
    skips append if true
    """
    if (v.pop(2)) or ("CVE-" in v[0]) or ("nvd.nist.gov" in v[3]):
      continue


    """
    obtains unique info between <p class=\"\"> and </p>
    """
    for info_tag in info_tags[2:]:
      for head in headers[10:]:
        if head in str(info_tag):
          temp = str(info_tag).split("<p class=\"\">",1)[1] # data cleaning
          temp = temp.split("</p>")[0]
          temp = temp.replace("\n", "").strip()
          if temp in v:
            continue
          index = headers.index(head)
          while index >= len(v):
            v.append("") 
          v[index] = temp

    vulns.append(v)
    print("ADDED: " + str(n))
  # ensures all vulnerabilites are equal length
    if len(v) > max:
      max = len(v)
  for vuln in vulns:
    while len(vuln) < max:
      vuln.append("")

  if not exist:
    write.feed_nipc(headers, vulns)
    exist = True
  elif len(vulns) > 0:
    write.update_nipc(headers, vulns)
