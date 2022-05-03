#!/usr/bin/env python
"""
LICENSE http://www.apache.org/licenses/LICENSE-2.0
"""

import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct
import random

try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


victim_domain = DomainName('findall.app.')
local_ip = '127.0.0.1'
IP = '147.182.132.99'
TTL = 30

soa_record = SOA(
    mname=victim_domain.ns1,  # primary name server
    rname=victim_domain.hostmaster,  # email of the domain administrator
    times=(
        201307231,  # serial number
        60 * 60 * 1,  # refresh
        60 * 60 * 3,  # retry
        60 * 60 * 24,  # expire
        60 * 60 * 1,  # minimum
    )
)
ns_records = [NS(victim_domain.ns1), NS(victim_domain.ns2)]
records = {
    victim_domain: [A(local_ip), MX(victim_domain.mail), soa_record] + ns_records,
    victim_domain.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
    victim_domain.ns2: [A(IP)],
    victim_domain.mail: [A(IP)],
}


def dns_response(data, client_ip):
    request = DNSRecord.parse(data)

    print(request)

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname).lower()
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    if qn.startswith('fake'):
        # reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A(IP2)))
        reply.header.rcode = 3
    elif qn == victim_domain or qn.endswith('.' + victim_domain):
        for name, rrs in records.items():
            if name == qn:
                for rdata in rrs:
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))

        for rdata in ns_records:
            reply.add_ar(RR(rname=victim_domain, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

        reply.add_auth(RR(rname=victim_domain, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    print("---- Reply:\n", reply)

    # install BIND 9.11 or earlier/ Unbound/s

    try:
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        ip = client_ip
        # details of the flags below
        line = now + ' ' + ip + ' ' + qn.replace('.' + dom + '.', '') + ' ' + qt + ' ' + \
               str(reply.header.rcode) + ' ' + str(request.header.tc) + ' ' + str(request.header.rd) + \
               ' ' + str(request.header.cd)
        os.system(
            'echo "' + line + '" >> ' + 'log')
    except Exception as e:
        print(e)

    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
                                              self.client_address[1]))
        try:
            data = self.get_data()
            print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data, self.client_address[0]))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
    parser.add_argument('--port', default=5053, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')

    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    print("Starting nameserver...")

    servers = []
    if args.udp:
        servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp:
        servers.append(socketserver.ThreadingTCPServer(('', args.port), TCPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()


if __name__ == '__main__':
    main()
