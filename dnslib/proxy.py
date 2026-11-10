# -*- coding: utf-8 -*-

from __future__ import print_function

import binascii,socket,struct

from dnslib import DNSRecord,DNSHeader,DNSError,RCODE,QTYPE
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger

def validate_reply(request,reply):
    """
        Validate that an upstream response belongs to the supplied request.

        Checks (per RFC1035/RFC5452):
          - transaction id matches
          - response is a response (QR=1) with the same opcode as the request
          - question section matches exactly (name compared case-insensitively
            per DNS label rules, plus qtype/qclass), including multi-question
            packets and empty question sections

        Raises DNSError if the response cannot be correlated with the request.
        Answer/authority/additional sections are not inspected so legitimate
        unknown RR types and additional records (eg EDNS OPT) are preserved.
    """
    if request.header.id != reply.header.id:
        raise DNSError("Upstream response transaction id does not match "
                       "request (request=%d response=%d)" % (
                                    request.header.id,reply.header.id))
    if reply.header.qr != 1:
        raise DNSError("Upstream response QR flag is not set")
    if request.header.opcode != reply.header.opcode:
        raise DNSError("Upstream response opcode does not match request "
                       "(request=%s response=%s)" % (
                                    request.header.opcode,reply.header.opcode))
    if len(request.questions) != len(reply.questions):
        raise DNSError("Upstream response question count does not match "
                       "request (request=%d response=%d)" % (
                                    len(request.questions),
                                    len(reply.questions)))
    for index,(q1,q2) in enumerate(zip(request.questions,reply.questions)):
        # DNSLabel.__eq__ implements the DNS case-insensitive name rules
        if q1.qname != q2.qname or q1.qtype != q2.qtype or \
           q1.qclass != q2.qclass:
            raise DNSError("Upstream response question %d does not match "
                           "request (request=%r response=%r)" % (
                                    index,q1,q2))
    return reply

def servfail(request):
    """
        Build a SERVFAIL skeleton reply for an upstream failure
        (timeout/truncated/mismatched/invalid response). This is deliberately
        distinct from an upstream NXDOMAIN, which means the name genuinely
        does not exist and must be forwarded unchanged.
    """
    if request.questions:
        reply = request.reply()
    else:
        # request.reply() would synthesise an empty question section
        reply = DNSRecord(DNSHeader(id=request.header.id,
                                    bitmap=request.header.bitmap,
                                    qr=1))
    reply.header.rcode = RCODE.SERVFAIL
    return reply

class ProxyResolver(BaseResolver):
    """
        Proxy resolver - passes all requests to upstream DNS server and
        returns response

        Note that the request/response will be each be decoded/re-encoded
        twice:

        a) Request packet received by DNSHandler and parsed into DNSRecord
        b) DNSRecord passed to ProxyResolver, serialised back into packet
           and sent to upstream DNS server
        c) Upstream DNS server returns response packet which is parsed into
           DNSRecord
        d) ProxyResolver returns DNSRecord to DNSHandler which re-serialises
           this into packet and returns to client

        In practice this is actually fairly useful for testing but for a
        'real' transparent proxy option the DNSHandler logic needs to be
        modified (see PassthroughDNSHandler)

        Upstream responses are validated against the request (transaction id,
        QR/opcode and question section) before being returned. Upstream
        timeouts, truncated reads or mismatched/invalid responses result in
        SERVFAIL rather than being confused with an upstream NXDOMAIN.

    """

    def __init__(self,address,port,timeout=0,strip_aaaa=False):
        self.address = address
        self.port = port
        self.timeout = timeout or None
        self.strip_aaaa = strip_aaaa

    def resolve(self,request,handler):
        try:
            if self.strip_aaaa and request.q.qtype == QTYPE.AAAA:
                reply = request.reply()
                reply.header.rcode = RCODE.NXDOMAIN
            else:
                if handler.protocol == 'udp':
                    proxy_r = request.send(self.address,self.port,
                                    timeout=self.timeout)
                else:
                    proxy_r = request.send(self.address,self.port,
                                    tcp=True,timeout=self.timeout)
                reply = validate_reply(request,DNSRecord.parse(proxy_r))
        except socket.timeout:
            reply = servfail(request)
        except (socket.error,DNSError):
            # Truncated/closed connection, unparseable or mismatched response
            reply = servfail(request)

        return reply

class PassthroughDNSHandler(DNSHandler):
    """
        Modify DNSHandler logic (get_reply method) to send directly to
        upstream DNS server rather then decoding/encoding packet and
        passing to Resolver (The request/response packets are still
        parsed and logged but this is not inline)

        The raw upstream response is only forwarded when it validates against
        the request (transaction id, QR/opcode and question section). On an
        upstream timeout, truncated read or mismatched/invalid response the
        client receives a SERVFAIL reply instead of an unrelated or forged
        packet. Valid responses (including NXDOMAIN and unknown RR types) are
        forwarded byte-for-byte with their additional records intact.
    """
    def get_reply(self,data):
        host,port = self.server.resolver.address,self.server.resolver.port
        timeout = self.server.resolver.timeout

        request = DNSRecord.parse(data)
        self.server.logger.log_request(self,request)

        try:
            if self.protocol == 'tcp':
                tcp_data = struct.pack("!H",len(data)) + data
                response = send_tcp(tcp_data,host,port,timeout=timeout)[2:]
            else:
                response = send_udp(data,host,port,timeout=timeout)

            reply = validate_reply(request,DNSRecord.parse(response))
            self.server.logger.log_reply(self,reply)
        except (socket.timeout,socket.error,DNSError) as e:
            self.server.logger.log_error(self,e)
            response = servfail(request).pack()

        return response

def send_tcp(data,host,port,timeout=None):
    """
        Helper function to send/receive DNS TCP request
        (in/out packets will have prepended TCP length header)
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        if timeout is not None:
            sock.settimeout(timeout)
        sock.connect((host,port))
        sock.sendall(data)
        response = sock.recv(8192)
        if not response:
            raise DNSError("Upstream TCP connection closed before response")
        length = struct.unpack("!H",bytes(response[:2]))[0]
        while len(response) - 2 < length:
            chunk = sock.recv(8192)
            if not chunk:
                raise DNSError("Upstream TCP response truncated "
                               "(expected %d bytes, got %d)" % (
                                    length,len(response) - 2))
            response += chunk
        return response
    finally:
        if (sock is not None):
            sock.close()

def send_udp(data,host,port,timeout=None):
    """
        Helper function to send/receive DNS UDP request
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        if timeout is not None:
            sock.settimeout(timeout)
        sock.sendto(data,(host,port))
        response,server = sock.recvfrom(8192)
        if not response:
            raise DNSError("Empty UDP response from upstream")
        return response
    finally:
        if (sock is not None):
            sock.close()

if __name__ == '__main__':

    import argparse,sys,time

    p = argparse.ArgumentParser(description="DNS Proxy")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Local proxy port (default:53)")
    p.add_argument("--address","-a",default="",
                    metavar="<address>",
                    help="Local proxy listen address (default:all)")
    p.add_argument("--upstream","-u",default="8.8.8.8:53",
            metavar="<dns server:port>",
                    help="Upstream DNS server:port (default:8.8.8.8:53)")
    p.add_argument("--tcp",action='store_true',default=False,
                    help="TCP proxy (default: UDP only)")
    p.add_argument("--timeout","-o",type=float,default=5,
                    metavar="<timeout>",
                    help="Upstream timeout (default: 5s)")
    p.add_argument("--strip-aaaa",action='store_true',default=False,
                    help="Retuen NXDOMAIN for AAAA queries (default: off)")
    p.add_argument("--passthrough",action='store_true',default=False,
                    help="Dont decode/re-encode request/response (default: off)")
    p.add_argument("--log",default="request,reply,truncated,error",
                    help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix",action='store_true',default=False,
                    help="Log prefix (timestamp/handler/resolver) (default: False)")
    args = p.parse_args()

    args.dns,_,args.dns_port = args.upstream.partition(':')
    args.dns_port = int(args.dns_port or 53)

    print("Starting Proxy Resolver (%s:%d -> %s:%d) [%s]" % (
                        args.address or "*",args.port,
                        args.dns,args.dns_port,
                        "UDP/TCP" if args.tcp else "UDP"))

    resolver = ProxyResolver(args.dns,args.dns_port,args.timeout,args.strip_aaaa)
    handler = PassthroughDNSHandler if args.passthrough else DNSHandler
    logger = DNSLogger(args.log,prefix=args.log_prefix)
    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger,
                           handler=handler)
    udp_server.start_thread()

    if args.tcp:
        tcp_server = DNSServer(resolver,
                               port=args.port,
                               address=args.address,
                               tcp=True,
                               logger=logger,
                               handler=handler)
        tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)

