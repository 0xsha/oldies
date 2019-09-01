#-------------------------------------------------------------------------------
# Name:        PHPSerFind.py 
# Purpose:     Very Basic Script - PHP Serialization Scanner  (demo version)
#
# Author:      0xSha
#
# Created:     20/11/2012
# Copyright:   (c) 0xsha.io 2012
# Licence:     GPLV3
#-------------------------------------------------------------------------------
#!/usr/bin/env python

import os,re,sys



#global stuff

ScanPath = "//path-to-cms//"

# with basic modification from PyCrawler
class CodeCrawler(object):

    def isphp(self,f):
        if os.path.splitext(f)[1] == ".php":
             return True
        return False

    def pathmaker(self,dirc):
            dirs= os.listdir(dirc)
            newdirs= []
            for i in dirs:
                newdirs.append(os.path.join(dirc,i))
            return newdirs

    def pyCrawler(self,dirc, pred, res):
        for i in self.pathmaker(dirc):
            if os.path.isfile(i) and pred(i):
                #print "Found!", i
                res.append(i)
            elif os.path.isdir(i):
                #print "Crawling to", i
                self.pyCrawler(i, pred, res)
        return res


class ParsePHPCode(object):
    def __init__(self, phpfile):
        self.phpfile = phpfile
        f = open(phpfile, 'r')
        self.filelines = f.readlines()
        f.close()


    def ReturnLines(self,strs):
        lst = []
        for i in xrange(0, len(self.filelines)):
                if strs in self.filelines[i]:
                    lst.append(i+1)
        return lst

    def FunctionContent(self,line):
        buff = ''.join(self.filelines[line:-1])
        startoffunction = buff.find('{')
        c = 1
        for i in range(startoffunction+1, len(buff)):
            if buff[i] == '{':
                c+=1
            if buff[i] == '}':
                c-=1
            if c == 0:
                return buff[startoffunction:i+1]

    def Report__destruct(self):
        for line in parsePHP.ReturnLines('__destruct'):
          body = self.FunctionContent(line)


          if body == None:
            continue


          if body.find("$this->") == -1 and body.find("global") == -1:
            continue

          # really important stuff
          print "[+] __Destruct in Line %s :"%(line)
          print self.phpfile
          print self.filelines[line-1]+body
          print "###########################################################################################"

    def ReportUnserialize(self):
        for line in parsePHP.ReturnLines('unserialize'):
            found = False
            for i in range(0, line-1):
                if "function" in self.filelines[i]:
                    body = self.FunctionContent(i+1)
                    if (body != None and 'unserialize' in body):
                            print "[+] Unserialize in function,  Line %s"%(line)
                            print self.phpfile
                            print self.filelines[i]+body
                            print "###########################################################################################"
                            found = True
                            break

            if found:
                continue
            try:
                buff = ''.join(self.filelines[line-5:line+5])
                print "[+] Unserialize In Line %s"%(line)
                print self.phpfile
                print buff
                print "###########################################################################################"

            except:

                print "[+] Unserialize In Line %s"%(line)
                print "[-] Unserlize in buttom or top of file review it"
                print self.phpfile





# Check For Exploitabilty Condotions and find some 0day xD
class CodeAudit(CodeCrawler):

    def CheckForOOP(self,strcode):
        match = re.findall("class",strcode)
        if len(match) >= 1:
            return True
        else:
            return False

    def CheckForUnserialize(self,strcode):
        match = re.findall("unserialize",strcode)
        if len(match) >= 1:
            return True
        else:
            return False

    def CheckForDestruct(self,strcode):
        match = re.findall("__destruct",strcode)
        if len(match) >= 1:
            return True
        else:
            return False



    def CheckForExploitability(self):

        Oflag = False
        Sflag = False
        Dflag = False

        result = self.pyCrawler(ScanPath,self.isphp,[])

        print "###########################################################"
        print "\t\t\t[+] Exploitabilty Report : \n"
        for flist in result:

            #debug
            #print "[+] Auditing the %s " %(os.path.basename(flist))
            fp = open(flist,"r")
            fh = fp.read()
            if not Oflag:
                Oflag = self.CheckForOOP(fh.strip())
                if Oflag:
                    print "[+] Code is OOP "
            if not Sflag:
                Sflag = self.CheckForUnserialize(fh.strip())
                if Sflag:
                    print "[+] Found Unserialize"
            if not Dflag:
                Dflag = self.CheckForDestruct(fh.strip())
                if Dflag:
                    print "[+] Found __destruct() "

            if Oflag  and Sflag and Dflag:
                print "[+] All exploitaiton conditions have met"
                print "###########################################################"
                fp.close()
                return True


        fp.close()
        return False



    def AuditCode(self):
       if not self.CheckForExploitability():
            print "[-] One or more conditions not found exiting :("
            sys.exit(0)




# Todo Make it more OOP like (not in demo)
if __name__ == '__main__':


    CCAduit = CodeAudit()
    CCAduit.AuditCode()

    CCrawler = CodeCrawler()
    result = CCrawler.pyCrawler(ScanPath,CCrawler.isphp,[])

    for flist in result:
        parsePHP =  ParsePHPCode(flist)
        parsePHP.Report__destruct()
        parsePHP.ReportUnserialize()