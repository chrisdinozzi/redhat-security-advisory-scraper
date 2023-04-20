#RedHat Security Advisory Scraper
#Version 0.1

import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.edge.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import xlsxwriter


opts = Options()
opts.use_chromium = True
opts.add_argument("headless")
opts.add_argument("disable-gpu")
opts.add_argument('log-level=3')
opts.add_argument('enable-javascript')
opts.add_experimental_option('excludeSwitches', ['enable-logging'])
driver = webdriver.Edge(options=opts)

workbook = xlsxwriter.Workbook('output.xlsx')
worksheet = workbook.add_worksheet()
wrap_format = workbook.add_format({'text_wrap': True})
worksheet.write('A1','Advisory',wrap_format)
worksheet.write('B1','Packages',wrap_format)
worksheet.write('C1','Checksums (SHA256)',wrap_format)
worksheet.write('D1','CVEs',wrap_format)
worksheet.write('E1','CVSS Scores',wrap_format)



base_URL="https://access.redhat.com/errata/"
advisories=["RHSA-2023:0045","RHSA-2023:0046","RHSA-2023:0291"]
#advisories=["RHSA-2023:0045"]

def getPackages(soup):
    package_table=(soup.find("h2", string="Red Hat Enterprise Linux Server 7")).find_next("table")
    td_name = package_table.findAll("td",class_="name")
    td_checksum = package_table.findAll("td",class_="checksum")
    packages=""
    checksums=""
    for name,checksum in zip(td_name,td_checksum):
       name = name.text.strip()
       packages = packages+name+'\r\n'
       
       checksum=checksum.text.strip().replace("SHA-256: ","")
       checksums = checksums+checksum+'\r\n'
       
       print("[*]Packages: "+name + ":" +checksum)

    worksheet.write('B'+str(c),packages,wrap_format)
    worksheet.write('C'+str(c),checksums,wrap_format)
    return 0

def getCVEs(soup):
    cve_list=(soup.find("h2", string="CVEs")).find_next("ul")
    a_list=cve_list.findAll("a")
    CVEs=""
    CVSS_scores=""
    for a in a_list:
        cve_URL = a['href']
        cve_no = a.text
        CVEs = CVEs + cve_no + '\r\n'
        print("[*] Getting CVSS for: "+cve_no)
        CVSS_score = getCVSS(cve_URL)
        CVSS_scores = CVSS_scores+CVSS_score + '\r\n'
    
    worksheet.write('D'+str(c),CVEs,wrap_format)
    worksheet.write('E'+str(c),CVSS_scores,wrap_format)
    return 0

def getCVSS(cve_URL): 
    driver.get(cve_URL)
    try:
        element = WebDriverWait(driver, 30).until(
            EC.presence_of_element_located((By.CLASS_NAME, "stat-card-left")))
        cvss_soup = BeautifulSoup(driver.page_source,"html.parser")
        cvss_stat_card = cvss_soup.find("a",class_="stat-card-left")
        cvss_score=(cvss_stat_card.find_next("span",class_="stat-number")).text
        print("[*] CVSS Score: "+cvss_score)
        return cvss_score  
    except TimeoutException as e:
        print("[-] Wait Timed out. Problem with the page?: "+cve_URL)
        #print(e) 
        return 0

def scrapeSite(a):
    URL = base_URL + a
    try:
        page = requests.get(URL)
        soup = BeautifulSoup(page.content,"html.parser")
        print("[*] Getting packages for: "+a)
        getPackages(soup)
        print("[*] Getting CVEs for: "+a)
        getCVEs(soup)
    except requests.exceptions.Timeout:
        print('[-] Error, request time out: '+URL)
    except requests.exceptions.TooManyRedirects:
        print('[-] Error, too many redirects: '+URL)
    except requests.exceptions.HTTPError as err:
        raise SystemExit("[-] Error, HTTP Error: "+err)
    except requests.exceptions.RequestException as e:
        print('[-] Error, something went really, really, really wrong...: '+URL)
        raise SystemExit(e)

    return 0

def main():
    global c
    c=2 #count the current row on the output csv
    for advisory in advisories:
        worksheet.write('A'+str(c),advisory,wrap_format)
        scrapeSite(advisory)
        print("\n----------------")
        c=c+1 #c++ lol
    driver.quit()
    workbook.close()
    return 0

if __name__ == '__main__':

    main()
    print("[+] Finished executing")
