# -*- coding: utf-8 -*-

"""
    Tests for the response validation added to the proxy resolver and the
    passthrough handler (dnslib.proxy).

    No real sockets are used: a controlled socket stand-in lets each test
    script exactly what the upstream returns (matching reply, mismatched
    reply, timeout, truncated read, garbage) and inspect the raw bytes the
    proxy forwards back to the client.
"""

from __future__ import print_function

import socket as _socket
import struct
import unittest

from dnslib import (DNSRecord,DNSHeader,DNSQuestion,DNSError,QTYPE,CLASS,
                    RCODE,RR,RD,TXT,EDNS0)
from dnslib import proxy


class FakeSocket(object):
    """
        Socket double recording outbound data and replaying a scripted
        upstream behaviour.
    """

    instances = []

    def __init__(self,fake_module,family,stype,behavior):
        self.fake_module = fake_module
        self.family = family
        self.stype = stype
        self.behavior = behavior
        self.connected = None
        self.sent = []
        self.timeout = None
        self.closed = False
        FakeSocket.instances.append(self)

    def settimeout(self,timeout):
        self.timeout = timeout

    def connect(self,addr):
        self.connected = addr

    def sendall(self,data):
        self.sent.append(data)

    def sendto(self,data,addr):
        self.sent.append(data)
        self.connected = addr
        return len(data)

    def recv(self,size):
        return self._next()

    def recvfrom(self,size):
        return self._next(),self.connected or ('upstream',53)

    def _next(self):
        item = self.behavior.pop(0)
        if isinstance(item,Exception):
            raise item
        return item

    def close(self):
        self.closed = True


class FakeSocketModule(object):
    """
        Minimal replacement for the stdlib socket module exposing only the
        attributes the proxy code paths touch.
    """

    AF_INET = _socket.AF_INET
    AF_INET6 = _socket.AF_INET6
    SOCK_STREAM = _socket.SOCK_STREAM
    SOCK_DGRAM = _socket.SOCK_DGRAM
    timeout = _socket.timeout
    error = _socket.error

    def __init__(self,behavior):
        self.behavior = list(behavior)

    def socket(self,family,stype):
        return FakeSocket(self,family,stype,list(self.behavior))


class SocketPatch(object):
    """
        Replace socket.socket inside both dnslib.proxy and dnslib.dns with a
        stand-in backed by the supplied behaviour list. Both modules reference
        the same stdlib socket module so the original is saved once.
    """

    def __init__(self,behavior):
        self.fake = FakeSocketModule(behavior)
        self._target = proxy.socket
        self._original = None

    def __enter__(self):
        self._original = self._target.socket
        self._target.socket = self.fake.socket
        FakeSocket.instances = []
        return self

    def __exit__(self,*exc):
        self._target.socket = self._original
        return False

    @property
    def sockets(self):
        return list(FakeSocket.instances)

    @property
    def sent(self):
        return b"".join(b"".join(s.sent) for s in FakeSocket.instances)


class FakeLogger(object):
    def log_request(self,*a):
        pass

    def log_reply(self,*a):
        pass

    def log_error(self,*a):
        pass

    def log_recv(self,*a):
        pass

    def log_send(self,*a):
        pass


class FakeServer(object):
    def __init__(self,resolver):
        self.resolver = resolver
        self.logger = FakeLogger()


class FakeHandler(object):
    def __init__(self,resolver,protocol='udp'):
        self.protocol = protocol
        self.server = FakeServer(resolver)


def question_record(qname="example.com",qtype=QTYPE.A,qclass=CLASS.IN,
                    qid=0x1234,questions=None):
    header = DNSHeader(id=qid)
    record = DNSRecord(header)
    if questions is None:
        questions = [DNSQuestion(qname,qtype,qclass)]
    for question in questions:
        record.add_question(question)
    return record


def response_record(request,rcode=RCODE.NOERROR,questions=None,
                    qr=1,opcode=None,ident=None,answers=None,ar=None):
    header = DNSHeader(id=request.header.id if ident is None else ident,
                       bitmap=request.header.bitmap,qr=qr)
    if opcode is not None:
        header.opcode = opcode
    if questions is None:
        questions = list(request.questions)
    reply = DNSRecord(header,questions=list(questions))
    for answer in answers or []:
        reply.add_answer(answer)
    for additional in ar or []:
        reply.add_ar(additional)
    reply.header.rcode = rcode
    return reply


def udp_behavior(record):
    return [record.pack()]


def tcp_behavior(record,chunks=None):
    payload = record.pack()
    framed = struct.pack("!H",len(payload)) + payload
    if chunks is None:
        return [framed]
    return list(chunks)


class ValidateReplyTests(unittest.TestCase):

    def setUp(self):
        self.request = question_record()

    def test_matching_reply_passes(self):
        reply = response_record(self.request)
        self.assertIs(proxy.validate_reply(self.request,reply),reply)

    def test_name_comparison_is_case_insensitive(self):
        reply = response_record(self.request,
                                questions=[DNSQuestion("ExAmPlE.CoM",
                                                       QTYPE.A,CLASS.IN)])
        self.assertIs(proxy.validate_reply(self.request,reply),reply)

    def test_transaction_id_mismatch_rejected(self):
        reply = response_record(self.request,ident=0x9999)
        with self.assertRaises(DNSError):
            proxy.validate_reply(self.request,reply)

    def test_non_response_rejected(self):
        reply = response_record(self.request,qr=0)
        with self.assertRaises(DNSError):
            proxy.validate_reply(self.request,reply)

    def test_opcode_mismatch_rejected(self):
        reply = response_record(self.request,opcode=2)
        with self.assertRaises(DNSError):
            proxy.validate_reply(self.request,reply)

    def test_same_id_different_question_name_rejected(self):
        reply = response_record(self.request,
                                questions=[DNSQuestion("other.com",
                                                       QTYPE.A,CLASS.IN)])
        with self.assertRaises(DNSError):
            proxy.validate_reply(self.request,reply)

    def test_same_question_different_type_rejected(self):
        reply = response_record(self.request,
                                questions=[DNSQuestion("example.com",
                                                       QTYPE.AAAA,CLASS.IN)])
        with self.assertRaises(DNSError):
            proxy.validate_reply(self.request,reply)

    def test_same_question_different_class_rejected(self):
        reply = response_record(self.request,
                                questions=[DNSQuestion("example.com",
                                                       QTYPE.A,CLASS.CH)])
        with self.assertRaises(DNSError):
            proxy.validate_reply(self.request,reply)

    def test_multi_question_match(self):
        request = question_record(questions=[
            DNSQuestion("a.example",QTYPE.A,CLASS.IN),
            DNSQuestion("b.example",QTYPE.MX,CLASS.IN)])
        reply = response_record(request)
        self.assertIs(proxy.validate_reply(request,reply),reply)

    def test_multi_question_partial_mismatch_rejected(self):
        request = question_record(questions=[
            DNSQuestion("a.example",QTYPE.A,CLASS.IN),
            DNSQuestion("b.example",QTYPE.MX,CLASS.IN)])
        reply = response_record(request,questions=[
            DNSQuestion("a.example",QTYPE.A,CLASS.IN),
            DNSQuestion("b.example",QTYPE.TXT,CLASS.IN)])
        with self.assertRaises(DNSError):
            proxy.validate_reply(request,reply)

    def test_question_count_mismatch_rejected(self):
        reply = response_record(self.request,questions=[])
        with self.assertRaises(DNSError):
            proxy.validate_reply(self.request,reply)

    def test_empty_question_sections_match(self):
        request = question_record(questions=[])
        reply = response_record(request)
        self.assertEqual(len(reply.questions),0)
        self.assertIs(proxy.validate_reply(request,reply),reply)

    def test_empty_question_reply_to_populated_request_rejected(self):
        request = question_record(questions=[])
        reply = response_record(request,
                                questions=[DNSQuestion("example.com")])
        with self.assertRaises(DNSError):
            proxy.validate_reply(request,reply)


class ProxyResolverTests(unittest.TestCase):

    def resolve(self,request,protocol='udp',behavior=None,timeout=5,
                strip_aaaa=False):
        resolver = proxy.ProxyResolver('10.0.0.1',53,timeout=timeout,
                                       strip_aaaa=strip_aaaa)
        handler = FakeHandler(resolver,protocol)
        with SocketPatch(behavior or []) as patch:
            reply = resolver.resolve(request,handler)
        return reply,patch

    def test_udp_matching_reply_forwarded(self):
        request = question_record()
        upstream = response_record(request,answers=RR.fromZone(
                                        "example.com 60 A 1.2.3.4"))
        reply,patch = self.resolve(request,'udp',udp_behavior(upstream))
        self.assertEqual(reply.header.id,request.header.id)
        self.assertEqual(reply.header.rcode,RCODE.NOERROR)
        self.assertEqual(str(reply.a.rdata),"1.2.3.4")
        # The outbound datagram must be exactly the request wire bytes
        self.assertEqual(patch.sent,request.pack())

    def test_tcp_matching_reply_forwarded_with_length_prefix(self):
        request = question_record()
        upstream = response_record(request,answers=RR.fromZone(
                                        "example.com 60 A 5.6.7.8"))
        reply,patch = self.resolve(request,'tcp',tcp_behavior(upstream))
        self.assertEqual(reply.header.rcode,RCODE.NOERROR)
        self.assertEqual(str(reply.a.rdata),"5.6.7.8")
        expected = struct.pack("!H",len(request.pack())) + request.pack()
        self.assertEqual(patch.sent,expected)

    def test_upstream_nxdomain_preserved(self):
        request = question_record()
        upstream = response_record(request,rcode=RCODE.NXDOMAIN)
        reply,_ = self.resolve(request,'udp',udp_behavior(upstream))
        self.assertEqual(reply.header.rcode,RCODE.NXDOMAIN)

    def test_udp_timeout_is_servfail_not_nxdomain(self):
        request = question_record()
        reply,patch = self.resolve(request,'udp',
                                   [_socket.timeout("timed out")])
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)
        self.assertEqual(reply.header.id,request.header.id)
        self.assertEqual(reply.questions,request.questions)

    def test_tcp_timeout_is_servfail_not_nxdomain(self):
        request = question_record()
        reply,_ = self.resolve(request,'tcp',
                               [_socket.timeout("timed out")])
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_wrong_transaction_id_is_servfail(self):
        request = question_record()
        upstream = response_record(request,ident=0x4242)
        reply,_ = self.resolve(request,'udp',udp_behavior(upstream))
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_wrong_question_name_is_servfail(self):
        request = question_record()
        upstream = response_record(request,
                                   questions=[DNSQuestion("evil.test")])
        reply,_ = self.resolve(request,'udp',udp_behavior(upstream))
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_wrong_question_type_is_servfail(self):
        request = question_record()
        upstream = response_record(request,
                                   questions=[DNSQuestion("example.com",
                                                          QTYPE.AAAA)])
        reply,_ = self.resolve(request,'udp',udp_behavior(upstream))
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_multi_question_mismatch_is_servfail(self):
        request = question_record(questions=[
            DNSQuestion("a.example",QTYPE.A),
            DNSQuestion("b.example",QTYPE.MX)])
        upstream = response_record(request,questions=[
            DNSQuestion("a.example",QTYPE.A),
            DNSQuestion("c.example",QTYPE.MX)])
        reply,_ = self.resolve(request,'udp',udp_behavior(upstream))
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_empty_question_request_validate_and_servfail(self):
        request = question_record(questions=[])
        good = response_record(request)
        reply,_ = self.resolve(request,'udp',udp_behavior(good))
        self.assertEqual(reply.header.rcode,RCODE.NOERROR)

        bad = response_record(request,
                              questions=[DNSQuestion("example.com")])
        reply,_ = self.resolve(request,'udp',udp_behavior(bad))
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)
        self.assertEqual(len(reply.questions),0)

    def test_garbage_response_is_servfail(self):
        request = question_record()
        reply,_ = self.resolve(request,'udp',[b"\x12\x34"])
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_tcp_truncated_response_is_servfail(self):
        request = question_record()
        payload = response_record(request).pack()
        # Claim more bytes than the connection delivers then close
        framed = struct.pack("!H",len(payload) + 50) + payload
        reply,_ = self.resolve(request,'tcp',[framed,b""])
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_tcp_closed_before_response_is_servfail(self):
        request = question_record()
        reply,_ = self.resolve(request,'tcp',[b""])
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_case_variant_name_accepted(self):
        request = question_record("example.com")
        upstream = response_record(request,
                                   questions=[DNSQuestion("EXAMPLE.com")])
        reply,_ = self.resolve(request,'udp',udp_behavior(upstream))
        self.assertEqual(reply.header.rcode,RCODE.NOERROR)

    def test_unknown_rr_and_additional_preserved(self):
        request = question_record()
        unknown = RR("example.com",rtype=65534,rclass=CLASS.IN,ttl=30,
                     rdata=RD(b"\x01\x02\x03\x04"))
        additional = RR("meta.example.com",rtype=QTYPE.TXT,ttl=10,
                        rdata=TXT("hello"))
        upstream = response_record(request,answers=[unknown],ar=[additional])
        reply,_ = self.resolve(request,'udp',udp_behavior(upstream))
        self.assertEqual(reply.header.rcode,RCODE.NOERROR)
        self.assertEqual(reply.rr[0].rtype,65534)
        self.assertEqual(reply.rr[0].rdata.data,b"\x01\x02\x03\x04")
        self.assertEqual(len(reply.ar),1)
        self.assertEqual(reply.ar[0].rtype,QTYPE.TXT)

    def test_timeout_zero_means_blocking_socket(self):
        request = question_record()
        upstream = response_record(request)
        _,patch = self.resolve(request,'udp',udp_behavior(upstream),timeout=0)
        self.assertIsNone(patch.sockets[0].timeout)

    def test_strip_aaaa_still_returns_nxdomain_locally(self):
        request = question_record(qtype=QTYPE.AAAA)
        resolver = proxy.ProxyResolver('10.0.0.1',53,strip_aaaa=True)
        handler = FakeHandler(resolver)
        with SocketPatch([]) as patch:
            reply = resolver.resolve(request,handler)
        self.assertEqual(reply.header.rcode,RCODE.NXDOMAIN)
        # No upstream traffic for a stripped query
        self.assertEqual(patch.sockets,[])


class PassthroughHandlerTests(unittest.TestCase):

    def get_reply(self,request,protocol='udp',behavior=None,timeout=5):
        resolver = proxy.ProxyResolver('10.0.0.1',53,timeout=timeout)
        handler = proxy.PassthroughDNSHandler.__new__(
                                            proxy.PassthroughDNSHandler)
        handler.protocol = protocol
        handler.server = FakeServer(resolver)
        with SocketPatch(behavior or []) as patch:
            raw = handler.get_reply(request.pack())
        return DNSRecord.parse(raw),raw,patch

    def test_udp_matching_bytes_forwarded_unchanged(self):
        request = question_record()
        upstream = response_record(request,answers=RR.fromZone(
                                        "example.com 60 A 9.9.9.9"))
        reply,raw,patch = self.get_reply(request,'udp',
                                         udp_behavior(upstream))
        self.assertEqual(raw,upstream.pack())
        self.assertEqual(reply.header.rcode,RCODE.NOERROR)
        self.assertEqual(patch.sent,request.pack())

    def test_tcp_matching_bytes_forwarded_without_length_prefix(self):
        request = question_record()
        upstream = response_record(request,answers=RR.fromZone(
                                        "example.com 60 A 9.9.9.9"))
        reply,raw,patch = self.get_reply(request,'tcp',
                                         tcp_behavior(upstream))
        self.assertEqual(raw,upstream.pack())
        expected = struct.pack("!H",len(request.pack())) + request.pack()
        self.assertEqual(patch.sent,expected)

    def test_tcp_segmented_read_reassembled(self):
        request = question_record()
        upstream = response_record(request)
        framed = struct.pack("!H",len(upstream.pack())) + upstream.pack()
        half = len(framed) // 2
        reply,raw,_ = self.get_reply(request,'tcp',
                                     [framed[:half],framed[half:]])
        self.assertEqual(raw,upstream.pack())
        self.assertEqual(reply.header.id,request.header.id)

    def test_nxdomain_forwarded_as_is(self):
        request = question_record()
        upstream = response_record(request,rcode=RCODE.NXDOMAIN)
        reply,raw,_ = self.get_reply(request,'udp',udp_behavior(upstream))
        self.assertEqual(raw,upstream.pack())
        self.assertEqual(reply.header.rcode,RCODE.NXDOMAIN)

    def test_udp_timeout_returns_generated_servfail(self):
        request = question_record()
        reply,raw,patch = self.get_reply(request,'udp',
                                         [_socket.timeout("timed out")])
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)
        self.assertEqual(reply.header.id,request.header.id)
        self.assertEqual(reply.questions,request.questions)

    def test_tcp_timeout_returns_generated_servfail(self):
        request = question_record()
        reply,_,_ = self.get_reply(request,'tcp',
                                   [_socket.timeout("timed out")])
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_mismatched_id_not_forwarded(self):
        request = question_record()
        upstream = response_record(request,ident=0xdead)
        reply,raw,_ = self.get_reply(request,'udp',udp_behavior(upstream))
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)
        self.assertNotEqual(raw,upstream.pack())
        self.assertEqual(DNSRecord.parse(raw).header.id,request.header.id)

    def test_mismatched_question_not_forwarded(self):
        request = question_record()
        upstream = response_record(request,
                                   questions=[DNSQuestion("other.test")])
        reply,_,_ = self.get_reply(request,'udp',udp_behavior(upstream))
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_wrong_qtype_not_forwarded(self):
        request = question_record()
        upstream = response_record(request,
                                   questions=[DNSQuestion("example.com",
                                                          QTYPE.MX)])
        reply,_,_ = self.get_reply(request,'udp',udp_behavior(upstream))
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_qr_zero_not_forwarded(self):
        request = question_record()
        upstream = response_record(request,qr=0)
        reply,_,_ = self.get_reply(request,'udp',udp_behavior(upstream))
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_opcode_mismatch_not_forwarded(self):
        request = question_record()
        upstream = response_record(request,opcode=2)
        reply,_,_ = self.get_reply(request,'udp',udp_behavior(upstream))
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_multi_question_mismatch_not_forwarded(self):
        request = question_record(questions=[
            DNSQuestion("a.example",QTYPE.A),
            DNSQuestion("b.example",QTYPE.MX)])
        upstream = response_record(request,questions=[
            DNSQuestion("a.example",QTYPE.A),
            DNSQuestion("b.example",QTYPE.TXT)])
        reply,_,_ = self.get_reply(request,'udp',udp_behavior(upstream))
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_empty_question_section_policy(self):
        request = question_record(questions=[])
        good = response_record(request)
        reply,raw,_ = self.get_reply(request,'udp',udp_behavior(good))
        self.assertEqual(raw,good.pack())

        bad = response_record(request,
                              questions=[DNSQuestion("example.com")])
        reply,raw,_ = self.get_reply(request,'udp',udp_behavior(bad))
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)
        self.assertEqual(len(reply.questions),0)

    def test_garbage_is_servfail(self):
        request = question_record()
        reply,_,_ = self.get_reply(request,'udp',[b"not-a-dns-packet"])
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_tcp_truncated_is_servfail(self):
        request = question_record()
        payload = response_record(request).pack()
        framed = struct.pack("!H",len(payload) + 20) + payload
        reply,_,_ = self.get_reply(request,'tcp',[framed,b""])
        self.assertEqual(reply.header.rcode,RCODE.SERVFAIL)

    def test_case_variant_accepted(self):
        request = question_record("Example.COM")
        upstream = response_record(request,
                                   questions=[DNSQuestion("eXaMPLe.com")])
        reply,raw,_ = self.get_reply(request,'udp',udp_behavior(upstream))
        self.assertEqual(raw,upstream.pack())
        self.assertEqual(reply.header.rcode,RCODE.NOERROR)

    def test_unknown_rr_roundtrips_transparently(self):
        request = question_record()
        unknown = RR("example.com",rtype=65534,rclass=CLASS.IN,ttl=30,
                     rdata=RD(b"\xde\xad\xbe\xef"))
        opt = EDNS0(udp_len=4096)
        upstream = response_record(request,answers=[unknown],ar=[opt])
        reply,raw,_ = self.get_reply(request,'udp',udp_behavior(upstream))
        # Transparent mode must hand back the exact upstream bytes
        self.assertEqual(raw,upstream.pack())
        self.assertEqual(reply.rr[0].rtype,65534)
        self.assertEqual(reply.rr[0].rdata.data,b"\xde\xad\xbe\xef")
        self.assertEqual(len(reply.ar),1)
        self.assertEqual(reply.ar[0].rtype,QTYPE.OPT)

    def test_timeout_applied_to_socket(self):
        request = question_record()
        upstream = response_record(request)
        _,_,patch = self.get_reply(request,'udp',udp_behavior(upstream),
                                   timeout=3.5)
        self.assertEqual(patch.sockets[0].timeout,3.5)


if __name__ == '__main__':
    unittest.main(verbosity=2)
