#!/usr/bin/env python
# coding=UTF-8
#

import copy
import enum
import dataclasses as dc

import vdns.rr
import vdns.src.src0
import vdns.common

from typing import Any, Optional, Sequence

# We use this a lot in this file. Must be Sequence and not list/tuple
RRTypeList = Sequence[Sequence[vdns.rr.RR]]


@dc.dataclass
class ZoneData:

    @dc.dataclass
    class Meta:
        domain: str = ''
        subsoas: list[vdns.rr.SOA] = dc.field(default_factory=list)
        network: Optional[vdns.common.IPNetwork] = None

        @property
        def reverse(self) -> bool:
            return self.network is not None

    @dc.dataclass
    class SubdomainData:
        ns: list[vdns.rr.NS] = dc.field(default_factory=list)
        ds: list[vdns.rr.DS] = dc.field(default_factory=list)
        glue: list[vdns.rr.Host] = dc.field(default_factory=list)

    # The raw database data - Maybe delete this
    dbdata: dict[str, Any] = dc.field(default_factory=dict)

    sources: list[vdns.src.src0.Source] = dc.field(default_factory=list)  # The source objects
    meta: Meta = dc.field(default_factory=Meta)  # Metadata of the zone
    soa: vdns.rr.SOA = dc.field(default_factory=vdns.rr.SOA)    # Zone's SOA. Formerly known as "zone"
    data: vdns.src.src0.DomainData = dc.field(default_factory=vdns.src.src0.DomainData)  # The actual records
    subs: dict[str, SubdomainData] = dc.field(default_factory=dict)  # Subdomain data

    @property
    def main(self) -> Optional[vdns.src.src0.Source]:
        """Returns the main source object or None."""
        if not self.sources:
            return None
        return self.sources[0]

    @property
    def reverse(self) -> bool:
        return self.meta.reverse


@dc.dataclass
class Zone0:
    """
    Base class for producing zone files
    """
    dt: ZoneData

    def __init__(self, dt: ZoneData) -> None:
        self.dt = dt

    def make(self) -> str:
        raise NotImplementedError

#     def make_ptr_name(self, rec):
#         """
#         Format the name of a PTR record (i.e. reverse IPv4 or IPv6)
#         """
#         if rec['family'] == 4:
#             rev = rec['ip_str'].split('.')
#             rev.reverse()
#             rev = '.'.join(rev)
#             ret = rev + '.in-addr.arpa'
#         elif rec['family'] == 6:
#             ip2 = rec['ip_str'] + '/128'
#             ret = vdns.common.reverse_name(ip2)
#         #            logging.error('Unhandled address family: %s', rec['family'])
#         #            ret=''
#         else:
#             logging.error('Unknown address family: %s', rec['family'])
#             ret = ''
#
#         # Get rid of the suffix if we can
#         domain = self.dt['_domain']
#         if ret[-len(domain):] == domain:
#             ret = ret[:-len(domain) - 1]
#
#         return ret

    def make_soa(self) -> str:
        return self.dt.data.soa.record()

    '''
    def mkrecord(self, rrname: str, rec: dict) -> str:
        types = {
            'mx': vdns.rr.MX,
            'ns': vdns.rr.NS,
            'host': vdns.rr.Host,
            'a': vdns.rr.Host,
            'aaaa': vdns.rr.Host,
            'ptr': vdns.rr.PTR,
            'cname': vdns.rr.CNAME,
            'cnames': vdns.rr.CNAME,
            'txt': vdns.rr.TXT,
            'dnskey': vdns.rr.DNSKEY,
            'dnssec': vdns.rr.DNSKEY,
            'ds': vdns.rr.DS,
            'sshfp': vdns.rr.SSHFP,
            'dkim': vdns.rr.DKIM,
            'srv': vdns.rr.SRV,
        }

        rr: vdns.rr.RR = vdns.rr.make_rr(types[rrname], rec)
        return rr.record()
    '''

    def make_toplevel(self) -> str:
        """
        Create the top-level entries.
        These are the entries with empty hostname or hostname=='.'
        """
        ret = ''
        data = self.dt.data

        reclist: RRTypeList
        dnskey: list[vdns.rr.DNSKEY] = [vdns.rr.DNSKEY.from_dnssec(x) for x in data.dnssec]

        # for recs in [data.ns, data.mx, dnskey, data.txt]:
        reclist = [data.ns, data.mx, dnskey, data.txt]
        for recs in reclist:
            for rec in recs:
                if rec.hostname is not None and rec.hostname not in ('', '.'):
                    continue
                ret += rec.record()

        for rec in data.hosts:
            if rec.hostname != '':
                continue
            ret += rec.record()

        # Add DKIM and SRV here (last) since they have a host part
        reclist = [data.dkim, data.srv]
        for recs in reclist:
            for rec in recs:
                if rec.hostname != '':
                    continue
                ret += rec.record()

        return ret

    def make_subzones(self) -> str:
        """
        Create entries that are considered subdomains
        For now these are entries that have NS
        """

        ret = ''
        glue = ''

        for subsoa in sorted(self.dt.meta.subsoas):
            ret += '\n'
            subdata: ZoneData.SubdomainData = self.dt.subs[subsoa.name]
            subsoa_rrs: list[Sequence[vdns.rr.RR]] = [subdata.ns, subdata.ds]
            for recs in subsoa_rrs:
                for rec in recs:
                    ret += rec.record()

            for rec in subdata.glue:
                glue += rec.record()

        if glue != '':
            ret += '\n; Glue records\n'
            ret += glue

        return ret

    def make_hosts(self) -> str:
        """
        Make the host entries

        Host entries are accompanied by relevant records like CNAMEs,
        TXTs, etc...
        """
        done = []  # List of entries already handled
        ret = ''

        rec: vdns.rr.RR
        recs: Sequence[vdns.rr.RR]
        reclist: RRTypeList

        # Determine entries to be excluded
        # - since we added them previously
        for rec in self.dt.data.ns:
            if rec.hostname not in done:
                done.append(rec.hostname)

        # Examine all hosts
        #        hosts2=dict([(h['ip'], h) for h in self.dt['hosts']])
        #        ips=hosts2.keys()
        #        ips.sort()
        for rec in self.dt.data.hosts:
            hostname = rec.hostname
            if hostname == '':
                continue

            ret += rec.record()

            if hostname in done:
                continue

            done.append(hostname)

            rec2: vdns.rr.RR
            recs2: Sequence[vdns.rr.RR]
            reclist2: RRTypeList

            # Add additional info here
            reclist2 = [self.dt.data.txt, self.dt.data.sshfp]
            for recs2 in reclist2:
                for rec2 in recs2:
                    if rec2.hostname != hostname:
                        continue
                    rec3 = copy.deepcopy(rec2)
                    rec3.hostname = ''
                    ret += rec3.record()

            # CNAMEs are special. We look for cnames that are
            # pointing to this host
            for cname in self.dt.data.cnames:
                if cname.hostname0 != hostname:
                    continue
                ret += cname.record()
                done.append(cname.hostname)

            # Add DKIM here (last) as it has a hostname part
            for dkim in self.dt.data.dkim:
                if dkim.hostname != hostname:
                    continue
                ret += dkim.record()

        # Now do the rest cnames
        reclist = [self.dt.data.cnames, self.dt.data.txt]
        for recs in reclist:
            ret += '\n'
            for rec in recs:
                if rec.hostname == '':
                    continue
                if rec.hostname not in done:
                    ret += rec.record()

        return ret

    def make_reverse(self) -> str:
        """
        Make the reverse entries
        """
        ret = ''

        # Create a dict and sort the keys. We list IPv4 before IPv6.
        # Keys are: X-Y where X is 4 or 6 depending on the family and
        # Y is the numerical representation of the address as returned by
        # inet_pton. All of this to be able to sort based on numerical
        # value instead of string representation
        # hosts = {}
        host: vdns.rr.Host
        hosts: list[vdns.rr.Host] = []
        for host in self.dt.data.hosts:
            # Skip entries that are not designated as reverse
            if not host.reverse:
                continue

            # x['net_domain'] = self.dt['_domain']      # TODO: Is the replacement correct? Is _domain == meta.domain?
            ptr = vdns.rr.PTR.from_host(host, self.dt.meta.domain)
            # # k = b'%d-%s' % (host.ip.version, host.ip.packed)
            # k = b'%d-%b' % (host.ip.version, host.ip.packed)
            # hosts[k] = ptr
            hosts.append(ptr)

        for rec in sorted(hosts):
            ret += rec.record()

        return ret

    @dc.dataclass
    class MakeKeysItem:
        class KeyType(enum.Enum):
            key = 1
            public = 1
            private = 2

        keytype: KeyType
        fn: str
        st_key: str

    def make_keys(self) -> list[MakeKeysItem]:
        """
        Make the key files

        Returns a list of entries. Each entry is a tuple of:
        (type, fn, contents)
        Where type is 'key' or 'private'
        """

        ret: list[Zone0.MakeKeysItem] = []

        x: vdns.rr.DNSSEC
        for x in self.dt.data.dnssec:
            # fn0 = 'K%s.+%03d+%d' % (x.domain, x.algorithm, x.keyid)
            fn0 = f'K{x.domain}.+{x.algorithm:03}+{x.keyid}'

            item = self.MakeKeysItem(
                keytype=self.MakeKeysItem.KeyType.public,
                fn=f'{fn0}.key',
                st_key=x.st_key_pub,
            )
            ret.append(item)

            item = self.MakeKeysItem(
                keytype=self.MakeKeysItem.KeyType.private,
                fn=f'{fn0}.private',
                st_key=x.st_key_priv,
            )
            ret.append(item)

            # fn = fn0 + '.key'
            # rec = ('key', fn, x['st_key_pub'])
            # ret.append(rec)

            # fn = fn0 + '.private'
            # rec = ('private', fn, x['st_key_priv'])
            # ret.append(rec)

        return ret


if __name__ == '__main__':
    pass

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
