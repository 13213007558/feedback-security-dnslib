# -*- coding: utf-8 -*-

from __future__ import print_function

import copy

from dnslib import RR,QTYPE,RCODE
from dnslib.label import DNSLabel
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger

class ZoneResolver(BaseResolver):
    """
        Simple fixed zone file resolver.

        The resolver supports two mutually exclusive name matching modes:

        glob=False (default)
            Exact label matching against the zone RRs (with optional glob
            style matching when glob=True - see below). This is the original
            behaviour and is retained unchanged. A name that has no matching
            RR is always answered with NXDOMAIN, so it does not model an
            authoritative zone (it cannot distinguish "name exists but no
            data for the qtype" from "name does not exist") and its glob
            matching is shell glob syntax rather than DNS wildcard semantics.

        wildcard=True (RFC 1034 section 4.3.3 / RFC 4592 wildcard semantics)
            The zone RRs are loaded into a name tree keyed by lowercase label
            tuples. Resolution walks the tree to find the closest enclosing
            node (the deepest existing ancestor of the QNAME). Both explicit
            RRs and empty non-terminals count as existing nodes:

              * an exact node for the QNAME answers from its own RRs;
              * otherwise a wildcard immediately below the closest
                enclosing node ("*" plus the enclosing suffix) may
                synthesise an answer, replacing the owner name with the
                QNAME;
              * an existing name with no RR of the requested type returns
                NOERROR with an empty answer section (NODATA), never
                NXDOMAIN;
              * a name with no enclosing node and no applicable wildcard
                returns NXDOMAIN;
              * a QNAME outside the zone origin is refused (REFUSED);
              * owner names are compared case-insensitively while
                synthesised owner names preserve the QNAME casing;
              * CNAME RRs are followed, including through a wildcard, and a
                CNAME node may not hold any other record type;
              * non-apex NS records (zone cuts/delegations) and DNAME
                records are rejected at construction time because this
                resolver is a single-zone authoritative server and does not
                implement referrals.

        The glob and wildcard modes cannot be combined.
    """

    def __init__(self,zone,glob=False,wildcard=False,origin=None):
        """
            Initialise resolver from zone file.
            Stores RRs as a list of (label,type,rr) tuples.

            If 'glob' is True use glob match against the zone file.
            If 'wildcard' is True build a name tree and apply RFC 1034/4592
            wildcard zone semantics.
            'origin' sets the zone apex for wildcard mode; when omitted the
            apex is derived as the common suffix of the zone owner names.
        """
        if glob and wildcard:
            raise ValueError("glob and wildcard modes are mutually exclusive")
        self.zone = [(rr.rname,QTYPE[rr.rtype],rr) for rr in RR.fromZone(zone)]
        self.glob = glob
        self.wildcard = wildcard
        self.eq = 'matchGlob' if glob else '__eq__'
        if wildcard:
            self._build_tree(origin)

    # ------------------------------------------------------------------
    # Wildcard (authoritative) mode
    # ------------------------------------------------------------------

    @staticmethod
    def _key(label):
        """Case-insensitive tree key for a label (tuple of bytes labels)."""
        return tuple(component.lower() for component in DNSLabel(label).label)

    def _in_zone(self,key):
        """True if key is the zone apex or a name beneath it."""
        if not self.origin:
            # An empty apex (root) contains every name.
            return True
        return key == self.origin or key[-len(self.origin):] == self.origin

    def _build_tree(self,origin):
        """
            Build the name tree from the zone RRs.

            self.tree maps a lowercase label tuple to a dict of
            rtype-name -> list of RR objects. Every ancestor suffix of an
            owner name (down to the zone apex) is registered as an empty
            node so empty non-terminals are represented. Wildcards are
            stored under their literal '*' owner name.
        """
        owner_keys = []
        for name,rtype,rr in self.zone:
            if rtype == 'DNAME':
                raise ValueError(
                    "DNAME records are not supported by wildcard mode: %s" %
                    rr.toZone())
            owner_keys.append(self._key(name))

        if origin is None:
            if not owner_keys:
                raise ValueError(
                    "cannot derive zone origin from an empty zone; "
                    "pass origin explicitly")
            # Common suffix of the RR owner names (including wildcards).
            suffix = list(reversed(owner_keys[0]))
            for key in owner_keys[1:]:
                shared = 0
                for a,b in zip(suffix,reversed(key)):
                    if a != b:
                        break
                    shared += 1
                suffix = suffix[:shared]
            origin = tuple(reversed(suffix))
        self.origin = self._key(origin)

        self.tree = {self.origin: {}}
        for name,rtype,rr in self.zone:
            key = self._key(name)
            if rtype == 'NS' and key != self.origin:
                raise ValueError(
                    "non-apex NS record (delegation/zone cut) is not "
                    "supported by wildcard mode: %s" % rr.toZone())
            # Register the node and every ancestor suffix (empty
            # non-terminals) down to the zone apex. Label tuples run
            # most-specific first, so an ancestor of (a,b,c) is (b,c),
            # then (c).
            for depth in range(0,len(key)-len(self.origin)+1):
                self.tree.setdefault(key[depth:],{})
            self.tree.setdefault(key,{}).setdefault(rtype,[]).append(rr)

        for key,node in self.tree.items():
            if 'CNAME' in node and len(node) > 1:
                raise ValueError(
                    "CNAME node cannot contain other record types: %s" %
                    DNSLabel(key))

    def _records(self,key,qtype):
        """
            Return the RRs answering qtype at an exact existing key.
            ANY returns every RR at the node. Returns an empty list when
            the node exists but holds no matching type (NODATA).
        """
        node = self.tree.get(key)
        if node is None:
            return None
        if qtype == 'ANY':
            records = []
            for rrs in node.values():
                records.extend(rrs)
            return records
        return list(node.get(qtype,()))

    def _answer_from_node(self,key,qtype,owner,reply):
        """
            Attach the RRs for qtype at key to the reply, synthesising
            owner names for wildcard nodes. Returns the CNAME target label
            when the node is a CNAME node, otherwise None.
        """
        node = self.tree[key]
        is_wildcard = key[:1] == (b'*',)
        if 'CNAME' in node:
            for rr in node['CNAME']:
                answer = copy.copy(rr)
                if is_wildcard:
                    answer.rname = owner
                reply.add_answer(answer)
            return node['CNAME'][0].rdata.label
        for rr in self._records(key,qtype):
            answer = copy.copy(rr) if is_wildcard else rr
            if is_wildcard:
                answer.rname = owner
            reply.add_answer(answer)
        return None

    def _add_additional(self,reply):
        """
            Add in-zone A/AAAA glue for names referenced by the answer
            section (CNAME/PTR targets, MX exchange, NS name).
        """
        for answer in reply.rr:
            rtype = QTYPE[answer.rtype]
            if rtype not in ('CNAME','PTR','MX','NS'):
                continue
            target = answer.rdata.label
            key = self._key(target)
            for addr_type in ('A','AAAA'):
                for rr in self.tree.get(key,{}).get(addr_type,()):
                    if rr not in reply.ar:
                        reply.add_ar(rr)

    def _resolve_wildcard(self,request):
        """
            Resolve a request against the name tree following RFC 1034
            section 4.3.3 / RFC 4592 wildcard semantics.
        """
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        qkey = self._key(qname)

        # Out of zone queries are refused rather than answered authoritatively.
        if not self._in_zone(qkey):
            reply.header.rcode = RCODE.REFUSED
            return reply

        owner = qname
        seen = set()
        while True:
            key = self._key(owner)
            if key in seen:
                reply.header.rcode = RCODE.SERVFAIL
                return reply
            seen.add(key)

            if key in self.tree:
                # Exact node (including an explicit '*' owner query and
                # empty non-terminals).
                target = self._answer_from_node(key,qtype,owner,reply)
            else:
                # Find the closest enclosing existing node (strict
                # ancestor suffix, i.e. drop labels from the left).
                depth = 1
                while depth < len(key) and key[depth:] not in self.tree:
                    depth += 1
                closest = key[depth:]
                # RFC 4592: a wildcard matches exactly one label, so it
                # can only apply when the QNAME sits one level below the
                # closest encloser.
                if depth != 1:
                    if reply.rr:
                        # Partial CNAME chain already present.
                        return reply
                    reply.header.rcode = RCODE.NXDOMAIN
                    return reply
                # The wildcard owner is '*' followed by the enclosing
                # suffix, expressed most-specific label first.
                wildcard_key = (b'*',) + closest
                wildcard = self.tree.get(wildcard_key)
                if wildcard is None:
                    # A partial CNAME chain may already be present; keep
                    # NOERROR in that case and return the chain so far.
                    if reply.rr:
                        return reply
                    reply.header.rcode = RCODE.NXDOMAIN
                    return reply
                target = self._answer_from_node(
                                    wildcard_key,qtype,owner,reply)

            # Add in-zone A/AAAA glue for CNAME/PTR/MX/NS targets.
            self._add_additional(reply)

            if target is None:
                # Existing name: no answer means NODATA, never NXDOMAIN.
                return reply

            # Follow the CNAME chain while the target stays in zone.
            tkey = self._key(target)
            if not self._in_zone(tkey):
                return reply
            owner = DNSLabel(target)

    # ------------------------------------------------------------------
    # Resolver entry point
    # ------------------------------------------------------------------

    def resolve(self,request,handler):
        """
            Respond to DNS request - parameters are request packet & handler.
            Method is expected to return DNS response
        """
        if self.wildcard:
            return self._resolve_wildcard(request)

        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        for name,rtype,rr in self.zone:
            # Check if label & type match
            if getattr(qname,self.eq)(name) and (qtype == rtype or
                                                 qtype == 'ANY' or
                                                 rtype == 'CNAME'):
                # If we have a glob match fix reply label
                if self.glob:
                    a = copy.copy(rr)
                    a.rname = qname
                    reply.add_answer(a)
                else:
                    reply.add_answer(rr)
                # Check for A/AAAA records associated with reply and
                # add in additional section
                if rtype in ['CNAME','NS','MX','PTR']:
                    for a_name,a_rtype,a_rr in self.zone:
                        if a_name == rr.rdata.label and a_rtype in ['A','AAAA']:
                            reply.add_ar(a_rr)
        if not reply.rr:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply

if __name__ == '__main__':

    import argparse,sys,time

    p = argparse.ArgumentParser(description="Zone DNS Resolver")
    p.add_argument("--zone","-z",required=True,
                        metavar="<zone-file>",
                        help="Zone file ('-' for stdin)")
    p.add_argument("--port","-p",type=int,default=53,
                        metavar="<port>",
                        help="Server port (default:53)")
    p.add_argument("--address","-a",default="",
                        metavar="<address>",
                        help="Listen address (default:all)")
    p.add_argument("--glob",action='store_true',default=False,
                        help="Glob match against zone file (default: false)")
    p.add_argument("--wildcard",action='store_true',default=False,
                        help="RFC 1034/4592 wildcard zone semantics "
                             "(default: false; mutually exclusive with --glob)")
    p.add_argument("--origin",default=None,
                        metavar="<origin>",
                        help="Zone apex for wildcard mode (default: derived "
                             "from the zone owner names)")
    p.add_argument("--udplen","-u",type=int,default=0,
                    metavar="<udplen>",
                    help="Max UDP packet length (default:0)")
    p.add_argument("--tcp",action='store_true',default=False,
                        help="TCP server (default: UDP only)")
    p.add_argument("--log",default="request,reply,truncated,error",
                    help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix",action='store_true',default=False,
                    help="Log prefix (default: False)")
    args = p.parse_args()

    if args.zone == '-':
        args.zone = sys.stdin
    else:
        args.zone = open(args.zone)

    resolver = ZoneResolver(args.zone,
                            glob=args.glob,
                            wildcard=args.wildcard,
                            origin=args.origin)
    logger = DNSLogger(args.log,prefix=args.log_prefix)

    print("Starting Zone Resolver (%s:%d) [%s]" % (
                        args.address or "*",
                        args.port,
                        "UDP/TCP" if args.tcp else "UDP"))
    if args.wildcard:
        print("    Wildcard zone origin: %s" % DNSLabel(resolver.origin))

    for rr in resolver.zone:
        print("    | ",rr[2].toZone(),sep="")
    print()

    if args.udplen:
        DNSHandler.udplen = args.udplen

    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger)
    udp_server.start_thread()

    if args.tcp:
        tcp_server = DNSServer(resolver,
                               port=args.port,
                               address=args.address,
                               tcp=True,
                               logger=logger)
        tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)
