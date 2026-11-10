# -*- coding: utf-8 -*-

"""
    Tests for the ZoneResolver wildcard (authoritative zone) mode.

    These tests build real DNSRecord requests with DNSRecord.question and
    assert against the parsed DNSRecord reply (owner name, rcode and RR
    set). They never issue system/network DNS lookups and do not cover
    DNSSEC.

    Small zone under example.test containing a wildcard ("*.example.test"),
    deeper explicit nodes and an empty non-terminal:

        example.test.          SOA ns.example.test. admin.example.test. ...
        *.example.test.        A       203.0.113.10
        host.example.test.     A       198.51.100.7
        deep.host.example.test. A      198.51.100.8
        deep.host.example.test. TXT    "deep-txt"
        leaf.ent.example.test. TXT     "ent-leaf"
        mail.example.test.     MX      10 mail1.example.test.
        mail1.example.test.    A       198.51.100.9
        alias.example.test.    CNAME   host.example.test.
        wcalias.example.test.  CNAME   wc-target.example.test.

    "ent.example.test." is an empty non-terminal: it has no RRs of its own
    but exists because its child "leaf.ent.example.test." holds records.
    Expected query/answer table:

        QNAME                     QTYPE  RCODE      ANSWER (owner/type/rdata)
        ------------------------- ------ ---------- ----------------------------------------
        example.test.             SOA    NOERROR    example.test/SOA
        example.test.             A      NOERROR    (empty; NODATA at apex)
        host.example.test.        A      NOERROR    host.example.test/A 198.51.100.7
        HOST.Example.Test.        A      NOERROR    HOST.Example.Test/A 198.51.100.7 (case kept)
        host.example.test.        AAAA   NOERROR    (empty; NODATA)
        deep.host.example.test.   A      NOERROR    deep.host.example.test/A 198.51.100.8
        deep.host.example.test.   MX     NOERROR    (empty; NODATA)
        ent.example.test.         TXT    NOERROR    (empty; ENT exists -> NODATA)
        node.ent.example.test.    A      NXDOMAIN   (ENT blocks the wildcard)
        b.deep.host.example.test. A     NXDOMAIN   (explicit node blocks the wildcard)
        foo.example.test.         A      NOERROR    foo.example.test/A 203.0.113.10 (synthesised)
        FOO.Example.TEST.         A      NOERROR    FOO.Example.TEST/A 203.0.113.10
        foo.example.test.         MX     NOERROR    (empty; wildcard NODATA)
        foo.example.test.         AAAA   NOERROR    (empty; wildcard NODATA)
        a.b.example.test.         A      NXDOMAIN   (wildcard matches one label only)
        mail.example.test.        MX     NOERROR    mail.example.test/MX + glue A in ADDITIONAL
        alias.example.test.       A      NOERROR    alias/CNAME host + host/A
        wcalias.example.test.     A      NOERROR    wcalias/CNAME wc-target + synthesised A
        other.test.               A      REFUSED    (outside the zone)
        example.test.other.       A      REFUSED    (outside the zone)
"""

from __future__ import print_function

import unittest

from dnslib import DNSRecord,QTYPE,RCODE
from dnslib.zoneresolver import ZoneResolver

ZONE = """
$ORIGIN example.test.
example.test. 3600 IN SOA ns.example.test. admin.example.test. 1 3600 3600 3600 3600
*.example.test. 300 IN A 203.0.113.10
host.example.test. 300 IN A 198.51.100.7
deep.host.example.test. 300 IN A 198.51.100.8
deep.host.example.test. 300 IN TXT "deep-txt"
leaf.ent.example.test. 300 IN TXT "ent-leaf"
mail.example.test. 300 IN MX 10 mail1.example.test.
mail1.example.test. 300 IN A 198.51.100.9
alias.example.test. 300 IN CNAME host.example.test.
wcalias.example.test. 300 IN CNAME wc-target.example.test.
"""

class WildcardZoneTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.resolver = ZoneResolver(ZONE,wildcard=True)

    def ask(self,qname,qtype):
        request = DNSRecord.question(qname,qtype=qtype)
        reply = self.resolver.resolve(request,None)
        # Round-trip through the wire format so assertions exercise the
        # same packet a real client would decode.
        return DNSRecord.parse(reply.pack())

    def answer_tuples(self,reply):
        return [(str(rr.rname),QTYPE[rr.rtype],str(rr.rdata))
                for rr in reply.rr]

    def additional_tuples(self,reply):
        return [(str(rr.rname),QTYPE[rr.rtype],str(rr.rdata))
                for rr in reply.ar]

    def test_origin_and_tree(self):
        self.assertEqual(self.resolver.origin,(b'example',b'test'))
        # The empty non-terminal is present but holds no RRs.
        self.assertEqual(self.resolver.tree[(b'ent',b'example',b'test')],{})
        # Its child does hold records.
        self.assertIn('TXT',
                      self.resolver.tree[(b'leaf',b'ent',b'example',b'test')])
        # Wildcard is stored under its literal owner name.
        self.assertIn((b'*',b'example',b'test'),self.resolver.tree)

    def test_apex(self):
        reply = self.ask("example.test","SOA")
        self.assertEqual(RCODE.get(reply.header.rcode),'NOERROR')
        self.assertEqual(self.answer_tuples(reply)[0][1],'SOA')
        # Existing apex name without the requested type is NODATA.
        nodata = self.ask("example.test","A")
        self.assertEqual(RCODE.get(nodata.header.rcode),'NOERROR')
        self.assertEqual(nodata.rr,[])

    def test_explicit_node_and_case(self):
        reply = self.ask("host.example.test","A")
        self.assertEqual(RCODE.get(reply.header.rcode),'NOERROR')
        self.assertEqual(self.answer_tuples(reply),
                         [('host.example.test.','A','198.51.100.7')])
        # Comparisons are case-insensitive; an explicit owner keeps its
        # zone (lowercased) spelling.
        upper = self.ask("HOST.Example.Test","A")
        self.assertEqual(RCODE.get(upper.header.rcode),'NOERROR')
        self.assertEqual(self.answer_tuples(upper),
                         [('host.example.test.','A','198.51.100.7')])
        # Existing name, missing type -> NODATA not NXDOMAIN.
        nodata = self.ask("host.example.test","AAAA")
        self.assertEqual(RCODE.get(nodata.header.rcode),'NOERROR')
        self.assertEqual(nodata.rr,[])

    def test_deep_explicit_node(self):
        reply = self.ask("deep.host.example.test","A")
        self.assertEqual(RCODE.get(reply.header.rcode),'NOERROR')
        self.assertEqual(self.answer_tuples(reply),
                         [('deep.host.example.test.','A','198.51.100.8')])
        nodata = self.ask("deep.host.example.test","MX")
        self.assertEqual(RCODE.get(nodata.header.rcode),'NOERROR')
        self.assertEqual(nodata.rr,[])

    def test_empty_nonterminal_blocks_wildcard(self):
        # ent.example.test exists as an empty non-terminal, so it answers
        # NODATA for its own qtype and a child one level down cannot be
        # synthesised from the apex wildcard.
        nodata = self.ask("ent.example.test","TXT")
        self.assertEqual(RCODE.get(nodata.header.rcode),'NOERROR')
        self.assertEqual(nodata.rr,[])

        reply = self.ask("node.ent.example.test","A")
        self.assertEqual(RCODE.get(reply.header.rcode),'NXDOMAIN')
        self.assertEqual(reply.rr,[])

    def test_explicit_node_blocks_wildcard_below(self):
        reply = self.ask("b.deep.host.example.test","A")
        self.assertEqual(RCODE.get(reply.header.rcode),'NXDOMAIN')
        self.assertEqual(reply.rr,[])

    def test_wildcard_synthesis(self):
        reply = self.ask("foo.example.test","A")
        self.assertEqual(RCODE.get(reply.header.rcode),'NOERROR')
        # Synthesised owner is the QNAME, not the wildcard owner.
        self.assertEqual(self.answer_tuples(reply),
                         [('foo.example.test.','A','203.0.113.10')])

    def test_wildcard_preserves_qname_case(self):
        reply = self.ask("FOO.Example.TEST","A")
        self.assertEqual(RCODE.get(reply.header.rcode),'NOERROR')
        self.assertEqual(self.answer_tuples(reply),
                         [('FOO.Example.TEST.','A','203.0.113.10')])

    def test_wildcard_nodata(self):
        for qtype in ("MX","AAAA","TXT"):
            reply = self.ask("foo.example.test",qtype)
            self.assertEqual(RCODE.get(reply.header.rcode),'NOERROR')
            self.assertEqual(reply.rr,[])

    def test_wildcard_matches_single_label_only(self):
        reply = self.ask("a.b.example.test","A")
        self.assertEqual(RCODE.get(reply.header.rcode),'NXDOMAIN')
        self.assertEqual(reply.rr,[])

    def test_explicit_wildcard_owner_query(self):
        # Querying the literal '*' name hits the explicit wildcard node.
        reply = self.ask("*.example.test","A")
        self.assertEqual(RCODE.get(reply.header.rcode),'NOERROR')
        self.assertEqual(self.answer_tuples(reply),
                         [('*.example.test.','A','203.0.113.10')])

    def test_mx_with_glue(self):
        reply = self.ask("mail.example.test","MX")
        self.assertEqual(RCODE.get(reply.header.rcode),'NOERROR')
        self.assertEqual(self.answer_tuples(reply),
                         [('mail.example.test.','MX','10 mail1.example.test.')])
        self.assertIn(('mail1.example.test.','A','198.51.100.9'),
                      self.additional_tuples(reply))

    def test_cname_chain_to_explicit_target(self):
        reply = self.ask("alias.example.test","A")
        self.assertEqual(RCODE.get(reply.header.rcode),'NOERROR')
        self.assertEqual(self.answer_tuples(reply),
                         [('alias.example.test.','CNAME','host.example.test.'),
                          ('host.example.test.','A','198.51.100.7')])
        self.assertIn(('host.example.test.','A','198.51.100.7'),
                      self.additional_tuples(reply))

    def test_cname_chain_through_wildcard(self):
        reply = self.ask("wcalias.example.test","A")
        self.assertEqual(RCODE.get(reply.header.rcode),'NOERROR')
        self.assertEqual(self.answer_tuples(reply),
                         [('wcalias.example.test.','CNAME',
                           'wc-target.example.test.'),
                          ('wc-target.example.test.','A','203.0.113.10')])

    def test_out_of_zone_refused(self):
        for qname in ("other.test","example.test.other","sub.other.test"):
            reply = self.ask(qname,"A")
            self.assertEqual(RCODE.get(reply.header.rcode),'REFUSED',qname)
            self.assertEqual(reply.rr,[])

    def test_authoritative_answer_flag(self):
        reply = self.ask("foo.example.test","A")
        self.assertEqual(reply.header.aa,1)


class WildcardValidationTest(unittest.TestCase):

    def test_glob_and_wildcard_exclusive(self):
        with self.assertRaises(ValueError):
            ZoneResolver("example.test. A 1.2.3.4",glob=True,wildcard=True)

    def test_cname_cannot_coexist(self):
        with self.assertRaises(ValueError):
            ZoneResolver(
                "x.example.test. CNAME h.example.test.\n"
                "x.example.test. A 1.2.3.4",wildcard=True)

    def test_delegation_rejected(self):
        zone = ("example.test. SOA ns.example.test. a 1 1 1 1 1\n"
                "sub.example.test. NS nsx.example.test.")
        with self.assertRaises(ValueError):
            ZoneResolver(zone,wildcard=True)

    def test_apex_ns_allowed(self):
        resolver = ZoneResolver(
            "example.test. NS ns.example.test.\n"
            "ns.example.test. A 1.2.3.4",wildcard=True)
        self.assertEqual(resolver.origin,(b'example',b'test'))

    def test_explicit_origin(self):
        resolver = ZoneResolver("host.example.test. A 1.2.3.4",
                                wildcard=True,origin="example.test.")
        self.assertEqual(resolver.origin,(b'example',b'test'))
        self.assertIn((b'example',b'test'),resolver.tree)

    def test_empty_zone_requires_origin(self):
        with self.assertRaises(ValueError):
            ZoneResolver("",wildcard=True)


class LegacyModeTest(unittest.TestCase):
    """The original exact and glob behaviour is unchanged."""

    def test_exact_mode_nxdomain_for_missing_type(self):
        resolver = ZoneResolver("host.example.test. A 1.2.3.4")
        reply = resolver.resolve(
            DNSRecord.question("host.example.test",qtype="TXT"),None)
        self.assertEqual(RCODE.get(reply.header.rcode),'NXDOMAIN')

    def test_glob_mode(self):
        resolver = ZoneResolver("*.example.test. A 1.2.3.4",glob=True)
        reply = resolver.resolve(
            DNSRecord.question("a.b.example.test",qtype="A"),None)
        self.assertEqual(RCODE.get(reply.header.rcode),'NOERROR')
        self.assertEqual([(str(rr.rname),str(rr.rdata)) for rr in reply.rr],
                         [('a.b.example.test.','1.2.3.4')])


if __name__ == '__main__':
    unittest.main(verbosity=2)
