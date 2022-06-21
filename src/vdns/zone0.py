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
    class SubdomainData:
        soa: vdns.rr.SOA = dc.field(default_factory=vdns.rr.SOA)
        ns: list[vdns.rr.NS] = dc.field(default_factory=list)
        ds: list[vdns.rr.DS] = dc.field(default_factory=list)
        glue: list[vdns.rr.Host] = dc.field(default_factory=list)

    domain: str = ''

    # The raw database data - Maybe delete this
    dbdata: dict[str, Any] = dc.field(default_factory=dict)

    sources: list[vdns.src.src0.Source] = dc.field(default_factory=list)  # The source objects
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
        return self.data.reverse


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

    def make_soa(self) -> str:
        return self.dt.data.soa.record()

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

        if not self.dt.reverse:
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

        for _, subdata in sorted(self.dt.subs.items()):
            ret += '\n'
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

        # All records that may have entries for a host
        reclist: RRTypeList = [self.dt.data.mx, self.dt.data.cnames, self.dt.data.txt, self.dt.data.dkim,
                               self.dt.data.srv, self.dt.data.sshfp]

        # Determine entries to be excluded
        # - since we added them previously
        for rec in self.dt.data.ns:
            if rec.hostname not in done:
                done.append(rec.hostname)

        # Examine all hosts
        for rec in sorted(self.dt.data.hosts):
            hostname = rec.hostname
            if hostname == '':
                continue

            if hostname in done:
                continue

            done.append(hostname)

            # First do IP addresses
            rec2: vdns.rr.RR
            recs2: Sequence[vdns.rr.RR]

            # The first one includes the hostname part so handle it separately
            is_first: bool = True

            # Do 'A' first, then 'AAAA'
            for rrname in ('A', 'AAAA'):
                for host in self.dt.data.hosts:
                    if host.hostname != hostname:
                        continue
                    if host.rrname != rrname:
                        continue

                    if is_first:
                        ret += host.record()
                        is_first = False
                    else:
                        host2 = copy.deepcopy(host)
                        host2.hostname = ''
                        ret += host2.record()

            # Add additional info here - entries that will have their host part omitted
            for recs2 in reclist:
                for rec2 in recs2:
                    # Look for relevant entries
                    if rec2.associated_hostname != hostname:
                        continue

                    # Entries with a different cooked hostname (like "_spf.host") should not be added here because
                    # we're skipping the hostname part. They will be listed after the empty-hostname entries.
                    if rec2.cooked_hostname != hostname:
                        continue

                    if is_first:
                        ret += rec2.record()
                        is_first = False
                    else:
                        rec3 = copy.deepcopy(rec2)
                        rec3.hostname = ''
                        ret += rec3.record()

            # ------------------------------------------------------------
            # Only entries that have a non-empty hostname below this point
            # ------------------------------------------------------------

            # Add records that relate to this host via associated_hostname
            # - TXT records hold SPF records which are better listed close to the associated host
            # - CNAMEs are special. We look for cnames that are pointing to this host
            # - DKIMs always have a hostname part
            for recs2 in reclist:
                for rec2 in recs2:
                    # Look for relevant entries
                    if rec2.associated_hostname != hostname:
                        continue

                    # Entries with a matching hostname have already been added with an empty hostname
                    if rec2.cooked_hostname == hostname:  # rec2.associated_hostname:
                        continue

                    ret += rec2.record()

        # Now do the rest entries
        last_nl_idx = -1  # Last index that a newline was added
        for idx, recs in enumerate(reclist):
            for rec in sorted(recs):
                if rec.hostname == '':
                    continue
                if rec.associated_hostname not in done:
                    if last_nl_idx != idx:
                        ret += '\n'
                        last_nl_idx = idx
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
        for host in sorted(self.dt.data.hosts):
            # Skip entries that are not designated as reverse
            if not host.reverse:
                continue

            # x['net_domain'] = self.dt['_domain']      # TODO: Is the replacement correct? Is _domain == domain?
            ptr = vdns.rr.PTR.from_host(host, self.dt.domain)
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
