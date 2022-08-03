#
# InBECstigation
# Created by: Eduardo Chavarro - eduardo.ovalle@kaspersky.com @echavarro
#
# PST analysis tools, extracts information from PST collections:
#   Mail to
#   Mail from
#   Mail CC
#   x_originating_ip
#   Suspicious headers based on SPF/DKIM
#   Extracts domains from mailboxes and analyze them
#   Verifies suspicious appearance domains, checks the creation date
#   Verifies suspicious mailboxes based on suspicious domains
#   Extract suspicious messages and creates a Timeline including suspicious domain creation time
#
#   usage: python InBECstigation.py -f pstfile -l domains
#       -f pstfile: PST container filename, ex: Exchange.pst. Can be multiple pst files separated by comma
#       -ld legitdmn: legitimate domains to investigate possible appearance. Coma separated domains, ex: a.com,b.com 
#       -m messagespath: a folder with single msg files that can be included in the analysis process.
#


import argparse
import pypff
from email.parser import HeaderParser
import pandas as pd
import numpy as np
import whois
from difflib import SequenceMatcher
from termcolor import colored
from datetime import datetime
import extract_msg
import glob
import time
import requests
import base64, re

apikey = ''  #### ENTER API KEY HERE ####

requests.urllib3.disable_warnings()
client = requests.session()
client.verify = False
domainErrors = []
delay = {}

appearance_threshold=0.7
susp_strings=["spf=softfail","dmarc=fail","compauth=fail"]

def decodeSubject(subject):
    encoded_word_regex = r'=\?{1}(.+)\?{1}([B|Q])\?{1}(.+)\?{1}='
    charset, encoding, encoded_text = re.match(encoded_word_regex, subject).groups()
    if encoding == 'B':
        return base64.b64decode(subject)
    else:
        return subject

def DomainScanner(domain): #'From Matthew Clairmont VT_Domain_Scanner
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': apikey, 'url': domain}

    try:
        r = client.post(url, params=params)
    except requests.ConnectTimeout as timeout:
        logger('-','Connection timed out. Error is as follows-'+str(timeout),"red",Flase)

    logger('',domain,"green",True)

    if r.status_code == 200:
        try:
            jsonResponse = r.json()
            if jsonResponse['response_code'] != 1:
                logger('\t','There was an error submitting the domain for scanning.',"red",False)
            elif jsonResponse['response_code'] == -2:
                logger('\t',str(domain)+' is queued for scanning.','yellow',False)
                delay[domain] = 'queued'
            else:
                logger('\t',str(domain)+' was scanned successfully.','yellow',False)

        except ValueError:
            logger('\t','There was an error when scanning '+str(domain),"red",False)

        time.sleep(1)  ############### IF YOU HAVE A PRIVATE ACCESS YOU CAN CHANGE THIS TO 1 ###################
        return delay

    elif r.status_code == 204:
        logger('','Received HTTP 204 response. You may have exceeded your API request quota or rate limit.',"Yellow",False)

def DomainReportReader(domain, delay): #'From Matthew Clairmont VT_Domain_Scanner
    if delay:
        if domain in delay:
            time.sleep(10)

    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': apikey, 'resource': domain}

    try:
        r = client.post(url, params=params)
    except requests.ConnectTimeout as timeout:
        logger('\t','Connection timed out. Error '+str(timeout),"red",False)
        exit(1)

    if r.status_code == 200:
        try:
            jsonResponse = r.json()
            if jsonResponse['response_code'] == 0:
                logger('\t','There was an error submitting the domain for scanning.',"red",False)
                pass

            scandate = jsonResponse['scan_date']
            positives = jsonResponse['positives']
            total = jsonResponse['total']

            data = [scandate, domain, positives, total]
            return data

        except ValueError:
            logger('\t','There was an error when scanning '+str(domain),"red",False)

        except KeyError:
            logger('\t','There was an error when scanning '+str(domain),"red",False)

    elif r.status_code == 204:
        logger('','Received HTTP 204 response. You may have exceeded your API request quota or rate limit.',"Yellow",False)
        time.sleep(10)
        DomainReportReader(domain, delay)

def logger(msg_preamble, msg, color, log=True):
    print(msg_preamble+colored(msg,color))
    if log:
        with open(logfile, 'a') as file:
            file.write(str(msg)+"\r\n")

def similarities(a, b):
    return SequenceMatcher(None, a, b).ratio()

def dmn_whois(dmn):
    w = whois.whois(dmn)
    return w

def dmn_appearance(dmnfull,real):
    dmn=[i for i in dmnfull if i not in real]
    dmnappearance=[]
    for b in dmn:
        for a in real:
            if similarities(a, b) > appearance_threshold:
                dmnappearance.append(b)
    return dmnappearance

def headers_to_df(headers):
    return dict([(title.lower(), value) for title, value in headers.items()])

def parse_folder(base):
    messages = []
    for folder in base.sub_folders:
        try:
            if folder.number_of_sub_folders:
                messages += parse_folder(folder)
        except:
            a=1 
        for message in folder.sub_messages:
            parser = HeaderParser()
            headers = parser.parsestr(message.transport_headers)
            messages.append(headers_to_df(headers))
    return messages

def unique(list1):
    x = np.array(list1)
    return np.unique(x)

def mails(dfmails,m_type):
    if m_type != "from":
        tmp=[]
        for line in dfmails:
            for m in line.split(','):
                tmp.append(m)
    else:
        tmp=dfmails
    tmp2=[]    
    for l in unique(tmp):
        try:
            tmp2.append((l.split("<")[1]).split(">")[0])
        except:
            tmp2.append(l)
    return unique(tmp2)

def mail_domains(mails_list):
    tmp=[]
    for l in mails_list:
        tmp.append(l.split("@")[1])
    return unique(tmp)

def x_org_ip():
    logger("","* Extracting x_originating_ip","green",True)
    x_originating_ip=[ip.replace("[","").replace("]","") for ip in df[df["x-originating-ip"].notna()]["x-originating-ip"].unique()]
    logger("\t",x_originating_ip,"yellow",True) 
    return x_originating_ip

def mboxes(mbtype,title):
    logger("","- "+title,"green",True)
    mailboxes=mails(df[df[mbtype].notna()][mbtype].unique(),mbtype)
    logger("\t",mailboxes,"yellow",True)
    return mailboxes

def check_messages(msg_field,title,value):
    logger("","Verifying messages "+title, 'yellow',True)
    tmp=df[df[msg_field].str.lower().str.contains(value).fillna(False)]
    logger("Subjects: ",unique(tmp["subject"]),'red',True)
    return tmp

logger("","InBECstigation - Quickly Analyze PST containers on BEC incidents","green",False)
print()
parser = argparse.ArgumentParser(description='PST analysis tools, extracts information from PST collections.')
parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-f', '--pstfile', default="Exchange.pst", help="PST container filename, ex: Exchange.pst. Coma separated files can be used")
parser.add_argument('-ld','--legitdmn', help="legitimate domains to investigate possible appearance. Coma separated domains, ex: a.com,b.com")
parser.add_argument('-vt','--VirusTotal', default=0,help="Verify extracted IP addresses against VirusTotal. Select -vt 1 if you want to check them.")
parser.add_argument('-o', '--outfile', default="InBECstigation.log", help="Save output to this file")
parser.add_argument('-m', '--messagesPath', default="msg", help="Add messages included in this folder for the analysis, *.msg files are required.")

args = parser.parse_args()

legit_domains=args.legitdmn.split(',') 
vt_check=args.VirusTotal 
logfile=args.outfile
tlfile='TL_'+logfile
with open(logfile, 'w') as file:
    file.write("")



logger("","********************************************************\r\nGetting messages headers","green",False)

pstfile=args.pstfile.split(',')
i=0
messages=[]
logger("","Appending Exchange files","green",True)
for file in pstfile:
    try:
        pst = pypff.open(file)
    except:
        logger(""," -- Error, file "+file+" do not exists.","red",True)
    root = pst.get_root_folder()
    logger("\t","Including container for analysis: "+file,"green",True)
    messages=messages+parse_folder(root)
    pst.close()



f = glob.glob(args.messagesPath+'/*.msg')

for filename in f:
    logger("\t","Including msg file for analysis: "+filename,"green",True)
    msg = extract_msg.Message(filename)
    messages.append(headers_to_df(msg.headerDict))

df=pd.DataFrame(messages)
now = datetime.now()
current_time = now.strftime("%H:%M:%S")
logger("\t","Number of messages to analyze: "+str(len(df.index)),"green",True)
logger("\t","Legitimate domains to be evaluated: ","green",True)
logger("\t",legit_domains,"yellow",True)
logger("\t","Analysis time: "+current_time,"green",True)
logger("","********************************************************","green",True)

x_originating_ip=x_org_ip()

logger("\r\n","* Extracting mailboxes","green",True)
mail_from=mboxes("from","From Mail")
mail_to=mboxes("to","Mail in TO")
mail_cc=mboxes("cc","Mail in CC")
return_path=mboxes("return-path", "Mailboxes in return-path")



mbfull=unique(np.concatenate([mail_from,mail_to,mail_cc,return_path]))

logger("\r\n","* Extracting domains from pst collection","green",True)
domains=mail_domains(mbfull)
logger("\t",domains,"yellow",True)

logger("\r\n","* Verifying possible appearance domains","green",True)  
dmn_app=dmn_appearance(domains,legit_domains)
logger("",dmn_app,"yellow",True)

logger("\r\n","* Verifying appearance domains metadata","green",True)

susp_rows=[]

for dmn in dmn_app:
    w=dmn_whois(dmn)
    logger("\t[suspicious domain] ",dmn,"red",True)
    logger("\t","Creation date: "+str(w.creation_date),"yellow",True)
    susp_rows.append([str(w.creation_date)+'+00:00',dmn,'Suspicious domain creation time','','','','',''])

susp_mb=[]
logger("\r\n","* Suspicious mailboxes:","green",True)
for m in mbfull:
    for d in dmn_app:
        try:
            if m.index(d): 
                susp_mb.append(m)
        except:
            a=1
logger("",susp_mb, 'red',True)

logger("\r\n","* Verifying messages including appearance domains","green",True)

susp_msg=pd.DataFrame()
for dmn in dmn_app:
    tmp=check_messages("from","from domain "+dmn,dmn)
    if tmp.size > 0: 
        susp_msg=susp_msg.append(tmp) 
    tmp=check_messages("to","to domain "+dmn,dmn)
    if tmp.size > 0: 
        susp_msg=susp_msg.append(tmp) 
    tmp=check_messages("cc","in CC to domain "+dmn,dmn)
    if tmp.size > 0: 
        susp_msg=susp_msg.append(tmp) 

logger("\r\n","* Verifying messages where authentication-results parameter is suspicious","green",True)

for val in susp_strings:
    tmp=check_messages("authentication-results","with value "+val,val)
    if tmp.size > 0: 
        susp_msg=susp_msg.append(tmp) 

if susp_msg.size > 0: 
    susp_msg["date"]=pd.to_datetime(susp_msg["date"],format='%a, %d %b %Y %X %z')
    logger("\r\n","* Suspicious messages: "+str(len(susp_msg.index)),"red",True)

    for index, item in susp_msg.iterrows():
        susp_rows.append([str(item["date"]),item["from"],item["return-path"],item["subject"],item["to"],item["cc"],item["thread-index"],item["received-spf"]])

    if len(susp_rows)>1:
        logger("\r\n","* Creating timeline for suspicious events to file: "+tlfile,"green",True)
        sorted_list=sorted(susp_rows, key=lambda x: x[0])
        sorted_list.insert(0,["date","from","return-path","subject","to","cc","thread-index","received-spf"])
        with open(tlfile, 'w') as file:
            for l in sorted_list:
                out=str(l)[1:-1]
                file.write(out+'\r\n')


print(unique(susp_rows["subject"]))
pattern='.*SubjectXXX'                  #Subject for analysis here
mask=df['subject'].str.contains(pattern,case=False,na=False)
print('Messages related to pattern '+pattern+': '+str(len(df[mask])))
print('Exporting to file '+pattern+'.csv')
tmp=df.loc[mask, ['date','received','from','to','cc','subject']]
tmp["date"]=pd.to_datetime(tmp["date"],format='%a, %d %b %Y %X %z')
tmp.to_csv(pattern+'.csv',index=False)



if vt_check >0:
    logger('','* Verifying IP addresses against VirusTotal',"green",True)
    for ip in x_originating_ip:
        try:
            delay = DomainScanner(ip)
            data = DomainReportReader(ip, delay)
            if data:
                logger('\t',data,"yellow",True)
                time.sleep(1)  
        except Exception as err:  
            logger('','- Encountered an error but scanning will continue.'+str(err),"red",False)

logger("","********************************************************\r\nProcess Finished","green",True)
logger("","********************************************************","green",False)
