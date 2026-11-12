#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    Tests enforcing that RR parsing honours the declared RDLENGTH.

    A malformed RR must never consume bytes belonging to following records:
    sequential reads inside RDATA are bounded by the RDLENGTH window while
    compression pointers may still reference names elsewhere in the packet
    (the local consumption boundary and the pointer reference scope are
    independent).
"""

from __future__ import print_function

import struct
import unittest

from dnslib import DNSRecord, DNSError, QTYPE


def header(an=2):
    # id, flags, qd=1, an, ns=0, ar=0
    return struct.pack('!HHHHHH', 0x1234, 0x8180, 1, an, 0, 0)


def encode_name(name=b'example.com'):
    return b''.join(bytes([len(label)]) + label
                    for label in name.split(b'.')) + b'\x00'


def question():
    return encode_name() + struct.pack('!HH', QTYPE.A, 1)


def raw_rr(name_wire, rtype, rclass, ttl, rdata, rdlength=None):
    if rdlength is None:
        rdlength = len(rdata)
    return name_wire + struct.pack('!HHIH', rtype, rclass, ttl,
                                   rdlength) + rdata


# Second RR carries an unmistakable marker so any byte borrowed by the first
# RR is easy to spot in the parsed output / error offsets.
MARKER_NAME = b'\x06marker\x07example\x03com\x00'
MARKER_RR = raw_rr(MARKER_NAME, QTYPE.A, 1, 300, b'\x09\x09\x09\x09')
NAME_POINTER = b'\xc0\x0c'  # points at example.com in the question section


class RDLengthTests(unittest.TestCase):

    def assertRejected(self, packet, rtype):
        with self.assertRaises(DNSError) as ctx:
            DNSRecord.parse(packet)
        message = str(ctx.exception)
        self.assertIn(rtype, message,
                      "error should name the offending record type: %s" % message)
        return message

    def test_txt_internal_length_cannot_borrow_next_rr(self):
        # RDLENGTH claims 10 bytes; the second character-string length byte
        # (0x06) actually belongs to the marker RR's name
        rdata = b'\x03abc' + b'\x06marker'
        bad = raw_rr(NAME_POINTER, QTYPE.TXT, 1, 60, rdata, rdlength=10)
        packet = header() + question() + bad + MARKER_RR
        message = self.assertRejected(packet, 'TXT')
        self.assertIn('character-string', message)

    def test_txt_truncated_internal_field(self):
        # length byte says 5 but only 2 content bytes remain in RDATA
        bad = raw_rr(NAME_POINTER, QTYPE.TXT, 1, 60, b'\x05ab')
        packet = header() + question() + bad + MARKER_RR
        self.assertRejected(packet, 'TXT')

    def test_mx_missing_exchange_name(self):
        # preference present but the exchange name is entirely missing
        bad = raw_rr(NAME_POINTER, QTYPE.MX, 1, 60,
                     struct.pack('!H', 10), rdlength=2)
        packet = header() + question() + bad + MARKER_RR
        self.assertRejected(packet, 'MX')

    def test_soa_truncated_times(self):
        # both names valid (compressed) but only 8 of the 20 time bytes exist
        rdata = NAME_POINTER + NAME_POINTER + struct.pack('!II', 1, 2)
        bad = raw_rr(NAME_POINTER, QTYPE.SOA, 1, 60, rdata)
        packet = header() + question() + bad + MARKER_RR
        self.assertRejected(packet, 'SOA')

    def test_a_declared_too_short(self):
        # A RDLENGTH of 2 but four address bytes were put on the wire
        bad = raw_rr(NAME_POINTER, QTYPE.A, 1, 60,
                     b'\x01\x02\x03\x04', rdlength=2)
        packet = header() + question() + bad + MARKER_RR
        self.assertRejected(packet, 'A')

    def test_unknown_type_rdlength_too_long(self):
        # opaque TYPE99 blob with RDLENGTH past the end of the packet
        bad = raw_rr(NAME_POINTER, 99, 1, 60, b'\xaa\xbb', rdlength=30)
        packet = header(an=1) + question() + bad
        message = self.assertRejected(packet, 'RR')
        self.assertIn('RDLENGTH 30', message)

    def test_unknown_type_declared_too_short(self):
        # TYPE99 declares 2 bytes while 4 are present: the extra two must be
        # treated as the start of the next (here deliberately broken) RR,
        # never silently swallowed into the opaque blob
        bad = raw_rr(NAME_POINTER, 99, 1, 60, b'\xde\xad\xbe\xef', rdlength=2)
        packet = header() + question() + bad + MARKER_RR
        with self.assertRaises(DNSError):
            DNSRecord.parse(packet)

    def test_well_formed_pair_keeps_marker_intact(self):
        # control case: both RRs parse and the marker RR is untouched
        good = raw_rr(NAME_POINTER, QTYPE.A, 1, 60, b'\x05\x06\x07\x08')
        packet = header() + question() + good + MARKER_RR
        record = DNSRecord.parse(packet)
        self.assertEqual(len(record.rr), 2)
        self.assertEqual(str(record.rr[0].rdata), '5.6.7.8')
        self.assertEqual(str(record.rr[1].rname), 'marker.example.com.')
        self.assertEqual(str(record.rr[1].rdata), '9.9.9.9')

    def test_compression_pointer_in_rdata_still_resolved(self):
        # The MX exchange name is a compression pointer to the question name;
        # bounding RDATA must not turn it into an isolated byte string
        mx_rdata = struct.pack('!H', 10) + NAME_POINTER
        good = raw_rr(NAME_POINTER, QTYPE.MX, 1, 60, mx_rdata)
        packet = header() + question() + good + MARKER_RR
        record = DNSRecord.parse(packet)
        self.assertEqual(str(record.rr[0].rdata.label), 'example.com.')
        self.assertEqual(record.rr[0].rdata.preference, 10)
        self.assertEqual(str(record.rr[1].rname), 'marker.example.com.')

    def test_rdata_pointer_scope_is_packet_not_rdata_window(self):
        # Backward pointers can legitimately land on a name that is not part
        # of the RDATA window (here a second question name); lifting the read
        # limit while following the pointer must still resolve correctly
        second_name = b'\x04mail\x07example\x03com\x00'
        two_questions = (struct.pack('!HHHHHH', 0x1234, 0x8180, 2, 1, 0, 0)
                         + question()
                         + second_name + struct.pack('!HH', QTYPE.A, 1))
        mail_offset = len(header()) + len(question())
        pointer = struct.pack('!H', 0xC000 | mail_offset)
        mx_rdata = struct.pack('!H', 20) + pointer
        mx_rr = raw_rr(NAME_POINTER, QTYPE.MX, 1, 60, mx_rdata)
        packet = two_questions + mx_rr
        record = DNSRecord.parse(packet)
        self.assertEqual(str(record.rr[0].rdata.label),
                         'mail.example.com.')

    def test_roundtrip_reparses_identically(self):
        good = raw_rr(NAME_POINTER, QTYPE.A, 1, 60, b'\x05\x06\x07\x08')
        packet = header() + question() + good + MARKER_RR
        record = DNSRecord.parse(packet)
        repacked = DNSRecord.parse(record.pack())
        self.assertEqual(repacked, record)
        self.assertEqual(str(repacked.rr[1].rname), 'marker.example.com.')


if __name__ == '__main__':
    unittest.main()
