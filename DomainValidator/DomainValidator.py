#!/usr/bin/python

# Created by Matt Cwieka

import sys, re, os, urllib2, time, string, socket
from optparse import OptionParser

def main():

    base_url = "http://www.mcafee.com/threat-intelligence/domain/default.aspx?domain="
    domain = sys.argv[1]
    request = base_url + domain
    req = urllib2.Request(request)
    
    try:
        f = urllib2.urlopen(req)
        print 'Downloading ' + request
        
    except urllib2.HTTPError, e:
        print "HTTP Error:", e.code, request

    except urllib2.URLError, e:
        print "URL Error:", e.reason, request

    s = f.readlines()
  
    riskRe = "\<img\sid\=\"ctl00\_mainContent\_imgRisk\"\stitle\=\"(.*?)\""

    for i in s:
        for match in re.finditer(riskRe, i):
            risk =  str(match.group(1))
    cef = 'CEF:0|DomainValidator|DomainValidatorMcAfee|1.0|100|Domain Check'+'|1|shost='+domain+' msg='+risk
    print cef

    syslog(cef)


def syslog(message, level=5, facility=8, host='22.22.22.22', port=514):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = '<%d>%s' % (level + facility*8, message)
    sock.sendto(data, (host, port))
    sock.close()

if __name__ == "__main__":
    main()
    
