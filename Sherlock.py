#!/usr/bin/env python

from bs4 import BeautifulSoup
from Queue import Queue, Empty as QueueEmpty
from traceback import format_exc
from cgi import escape
import optparse
import urlparse
import requests
import urllib2
import socket
import sys
import re
"""
Sherlock V1.1 by 0xSha.io Copyright 2011
"""

"""
What is Sherlock ? and why Sherlock? 
Sherlock is a tool for searching and subdomains also can perform 
reverse IP and even WebServer scan on target correctly, precisely like Sherlock.
"""

"""
@0xsha
"""

"""
Note : "Crawler code is borrowed/stolen from James Mills"
"""


try:
    import nmap
except:
    print "[-] if you need scanning install nmap and nmap-python"
    pass


################
#  Global Part #
################

user_agent = {
    'User-agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_0) AppleWebKit/537.36 (KHTML, like Gecko)"}
lib_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_0)"


USAGE = "%prog [options] <url>"

url_base = ".dnsdb.org"


def Banner():
    print r"""
 _______________
< Sherlock V1.1 >
 ---------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
        """


################
# Utility Part #
################


def GetHTML(url):
    '''
    @ params 
    @ url : website to dump 
    @ return : actual html 
    '''
    if "www." in url:
        url.replace("wwww.", "")

    if not (url.startswith("http://")):
        url = "http://" + url

    r = requests.get(url+url_base)
    return r.text


def MakeSoup(html):
    '''
    @ params
    @ html : HTML Source
    @ return : soup object 
    '''
    soup = BeautifulSoup(html)
    return soup


def GetLinks(soup):
    '''
    @ params
    @ soup : Get Soup Object 
    @ return : Links 
    '''
    links = []
    for link in soup.find_all('a'):
        links.append(link.get_text())
    return links


def CallAll(url):
    '''
    @ params
    @ url : url to do all
    @ return : sites
    '''
    html = GetHTML(url)
    soup = MakeSoup(html)
    links = GetLinks(soup)
    return links

# stackoverflow snipped


def extractIPs(fileContent):
    '''
    @ params
    @ fileContent : Get String To parser
    @ Return : list of IPs
    '''
    pattern = r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([ (\[]?(\.|dot)[ )\]]?(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})"
    ips = [each[0] for each in re.findall(pattern, fileContent)]
    for item in ips:
        location = ips.index(item)
        ip = re.sub("[ ()\[\]]", "", item)
        ip = re.sub("dot", ".", ip)
        ips.remove(item)
        ips.insert(location, ip)
    return ips


################
# Crawler Part #
################


class Crawler(object):
    '''
    Main Crawler class
    '''

    def __init__(self, root, depth, locked=True):
        self.root = root
        self.depth = depth
        self.locked = locked
        self.host = urlparse.urlparse(root)[1]
        self.urls = []
        self.links = 0
        self.followed = 0

    def crawl(self):
        page = Fetcher(self.root)
        page.fetch()
        q = Queue()
        for url in page.urls:
            q.put(url)
        followed = [self.root]

        n = 0

        while True:
            try:
                url = q.get()
            except QueueEmpty:
                break

            n += 1

            if url not in followed:
                try:
                    host = urlparse.urlparse(url)[1]
                    if self.locked and re.match(".*%s" % self.host, host):
                        followed.append(url)
                        self.followed += 1
                        page = Fetcher(url)
                        page.fetch()
                        for i, url in enumerate(page):
                            if url not in self.urls:
                                self.links += 1
                                q.put(url)
                                self.urls.append(url)
                        if n > self.depth and self.depth > 0:
                            break
                except Exception, e:
                    print "ERROR: Can't process url '%s' (%s)" % (url, e)
                    print format_exc()


class Fetcher(object):
    '''
    Fetcher class For Crawler
    '''

    def __init__(self, url):
        self.url = url
        self.urls = []

    def __getitem__(self, x):
        return self.urls[x]

    def _addHeaders(self, request):
        request.add_header("User-Agent", lib_agent)

    def open(self):
        url = self.url
        try:
            request = urllib2.Request(url)
            handle = urllib2.build_opener()
        except IOError:
            return None
        return (request, handle)

    def fetch(self):
        request, handle = self.open()
        self._addHeaders(request)
        if handle:
            try:
                content = unicode(handle.open(request).read(), "utf-8",
                                  errors="replace")
                soup = BeautifulSoup(content)
                tags = soup('a')
            except urllib2.HTTPError, error:
                if error.code == 404:
                    print >> sys.stderr, "ERROR: %s -> %s" % (error, error.url)
                else:
                    print >> sys.stderr, "ERROR: %s" % error
                tags = []
            except urllib2.URLError, error:
                print >> sys.stderr, "ERROR: %s" % error
                tags = []
            for tag in tags:
                href = tag.get("href")
                if href is not None:
                    url = urlparse.urljoin(self.url, escape(href))
                    if url not in self:
                        self.urls.append(url)

################
# Scanner Part #
################


def GetIpByHost(url):
    '''
    @ params
    @ url : get host name 
    @ return : ip address 
    '''
    ip = socket.gethostbyaddr(url)
    return ''.join(ip[2])


def CheckForPors(ip):
    '''
    @ params 
    @ ip : ip address to perform port scan 
    @ return : true of on web port is open 
    '''
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, '80,443,8080')
        if (nm[ip].has_tcp(80) or nm[ip].has_tcp(443) or nm[ip].has_tcp(8080)):
            print "[+] WebServer is up on %s and host is %s " % (ip, socket.gethostbyaddr(ip)[0])
            return True
        else:
            print "[-] ip %s has no WebServer up " % ip
            return False
    except:
        pass

###################
# Reverse-IP-Part #
###################


# stupid method instead of stupid gethostbyaddr
def GetIpSelfSeo(host):
    '''
    @ params
    @ host : get host to resolve ip 
    @ return : ip address of site 
    '''
    payload = {'url': host, 'submit': 'Get+IP'}
    r = requests.post(
        "http://www.selfseo.com/find_ip_address_of_a_website.php", data=payload)
    ip = extractIPs(r.text)
    return str(ip[0])


def GetTotallSite(ip):
    '''
    @ params
    @ ip : ip address to retrive totall reverse sites 
    @ return : number of sites in shared hosting 
    '''
    try:
        r = requests.get("http://www.sitedossier.com/ip/" +
                         ip, headers=user_agent)
        soup = MakeSoup(r.text)
        i = soup.find('i').get_text()
        # stupid regex
        match = re.findall("\d{2,5}", i)
        return match[1]
    except:
        return "[-] Can't work with dossier"


def SplipNum(num):
    '''
    @ params
    @ num  : totall number 
    @ return : list of pages of possible
    '''
    if int(num) < 101:
        return int(num)

    lst = []
    x = int(num)
    for i in range(0, int(num), 100):
        lst.append(i)
        # lst.append(i+(x-i))
        lst.pop(0)
        return lst


def RecivceSites(lstnum, ip):
    '''
    @ params lstnum,ip
    @ lstnum : list of numbers to grab lins 
    @ ip : ip address to reverse 
    @ return : final sites 
    '''
    sites = []
    if lstnum > 101:
        for i in lstnum:
            res = requests.get("http://www.sitedossier.com/ip/" +
                               ip+"/"+str(i), headers=user_agent)
            soup = BeautifulSoup(res.text)
            for link in soup.find_all('a'):
                sites.append(link.get('href').replace(
                    "/site/", "").replace("www.", ""))
    else:
        res = requests.get(
            "http://www.sitedossier.com/ip/"+ip, headers=user_agent)
        soup = BeautifulSoup(res.text)
        for link in soup.find_all('a'):
            sites.append(link.get('href').replace(
                "/site/", "").replace("www.", ""))

    return sites


def parse_options():
    '''
    @ params : null 
    @ return : opps , args  
    '''
    parser = optparse.OptionParser(usage=USAGE)

    parser.add_option("-s", "--scan", default=False, dest="scan",
                      help="Scan for Web Servers")

    parser.add_option("-d", "--depth",
                      action="store", type="int", default=30, dest="depth",
                      help="Maximum depth to traverse default is 30")

    parser.add_option("-r", "--reverse",
                      action="store", type="int", default=0, dest="reverse",
                      help="Perform Reverse IP on Target")

    opts, args = parser.parse_args()

    if len(args) < 1:
        Banner()
        parser.print_help()
        raise SystemExit, 1

    return opts, args


def main():
    '''
    Main Funciton 
    @ params : null
    @ return : null
    '''
    opts, args = parse_options()

    url = args[0]

    if not (url.startswith("http://")):
        url = "http://" + url

    Banner()
    targets = []

    print "[+] Grabbing Stared ..."
    output = open("__dns_output__.txt", "w")

    u = CallAll(url)
    for i in u:
        if "." in i:
            print i

            # write in file
            output.write(i+"\n")

        # keep for scan
        targets.append(i)

    # check for fixing infinitle loop of crawler
    if len(targets) > 3:
        depth = opts.depth
        print "[+] searching more deep with depth %d" % depth

        crawler = Crawler(url+url_base, depth)
        crawler.crawl()
        lst = crawler.urls
        for i in lst:
            print i.replace("http://", "").replace(".dnsdb.org/", "")
            # write in file
            output.write(
                i.replace("http://", "").replace(".dnsdb.org/", "") + "\n")
            # keep for scan
            targets.append(i)
    else:
        print "[-] can't go deeper !"

    print "[+] wrote output in __dns_output__.txt"
    output.close()

    if opts.reverse:
        routput = open("__reverse_output__.txt", "w")

        print "[+] Staring Reverse Ip On Target"
        try:
            host = url.replace("http://", "")
            ip = GetIpSelfSeo(host)
            num = GetTotallSite(ip)
            lstnum = SplipNum(num)
            sites = RecivceSites(lstnum, ip)

            for site in sites:
                routput.write(site+"\n")
                print site

            print "[+] wrote output in __reverse_output__.txt"

        except:
            print "[-] No Other Site or Error During Reverse-IP (captcha) "
            pass

        routput.close()

    if opts.scan:
        print "[!] Warining it may take VERY LONG TIME"
        for target in targets:
            ip = GetIpByHost(target)
            CheckForPors(ip)
            for site in sites:
                print site


if __name__ == "__main__":
    # calling main
    main()


r = requests.Response.ok.getter
