#coding:utf-8
'''
#这是一个用来检测网站是否存在域传送漏洞的脚本，请在python2.7版本下运行
#可以根据需要，选择单个检测和批量检测
'''
import sys
import socket
import optparse
try:
    from dns import resolver, query, exception
except ImportError:
    print "This script requires dnspython"
    print "http://www.dnspython.org/"
    sys.exit(1)



class Transferrer(object):
    def __init__(self, domain):
        self.domain = domain
        ## build list of nameservers
        nss = resolver.query(domain, 'NS')
        self.nameservers = [ str(ns) for ns in nss ]


    def transfer(self):
        for ns in self.nameservers:
            print >> sys.stderr, "Querying %s" % (ns,)
            print >> sys.stderr, "-" * 50
            z = self.query(ns)
            print z
            print >> sys.stderr, "%s\n" % ("-" * 50,)


    def query(self, ns):
        nsaddr = self.resolve_a(ns)
        try:
            z = self.pull_zone(nsaddr)
        except (exception.FormError, socket.error, EOFError):
            print >> sys.stderr, "AXFR failed\n"
            return None
        else:
            return z


    def resolve_a(self, name):
        """Pulls down an A record for a name"""
        nsres = resolver.query(name, 'A')
        return str(nsres[0])


    def pull_zone(self, nameserver):
        """Sends the domain transfer request"""
        q = query.xfr(nameserver, self.domain, relativize=False, timeout=2)
        zone = ""   ## janky, but this library returns
        for m in q: ## an empty generator on timeout
            zone += str(m)
        if not zone:
            raise EOFError
        return zone
def get_domain():
    s = []
    try:
        n = int(raw_input('[*]Single sweep: 1 \r\n[*]List sweep: 2\n'))
        print 'Your choice is: '+str(n)
        if n == 1:
            path = raw_input('input the address>>>>> ')
            s.append(path)
        else:
            path = raw_input('input the path>>>>> ')
            f = open(path,'r')
            for line in f:
                s.append(line)
        return s
    except:
        print '[*]Error!!!!!!!!!!  check your choice !'




if __name__ == "__main__":
    url = get_domain()
    try:
        for i in range(len(url)):
            s =  url[i].strip('\n')
            print s
            t = Transferrer(s)
            t.transfer()
        print '[*]Task has been finished!'
    except:
        pass


