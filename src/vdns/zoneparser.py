import logging
import datetime
import ipaddress
import dataclasses as dc

from pprint import pprint
from typing import Iterable, Optional

__all__ = ['ZoneParser']

import vdns.rr
import vdns.src.src0
import vdns.zone0
import vdns.common
import vdns.parsing
import vdns.keyparser

db = None


@dc.dataclass
class Entry:
    addr1: Optional[str] = ''
    ttl: Optional[datetime.timedelta] = None
    rr: str = ''
    addr2: str = ''


@dc.dataclass
class ParsedDomainData(vdns.src.src0.DomainData):
    """Holds the extra data that parsing produces.
    It produces more data than DomainData can hold, like DS records.
    """
    ds: list[vdns.rr.DS] = dc.field(default_factory=list)


class ZoneParser:
    """
    A class to read and parse a zone file
    """
    dt: ParsedDomainData
    is_reverse: bool

    def __init__(self, fn: Optional[str] = None, zone: Optional[str] = None, is_reverse: bool = False) -> None:
        self.dt = ParsedDomainData()
        self.is_reverse = is_reverse

        if fn is not None:
            self.read(fn, zone)

    def _parse_dkim(self, addr1: str, addr2: str) -> vdns.rr.DKIM:
        addr1_split = addr1.split('.', 2)
        assert addr1_split[1] == '_domainkey'

        if len(addr1_split) > 2:
            hostname = addr1_split[2]
        else:
            hostname = None

        selector = addr1_split[0]
        k: str = ''
        key_pub: str = ''
        g: Optional[str] = None
        t: bool = False
        h: Optional[str] = None
        subdomains: bool = False

        if addr2[0] == '"' and addr2[-1] == '"':
            addr2 = addr2[1:-1]

        for entry in addr2.split(';'):
            entry = entry.strip()
            key, value = entry.split('=', 1)
            if key == 'v':
                assert value == 'DKIM1', f'Only DKIM1 is supported. Found: {value}'
            elif key == 'g':
                g = value
            elif key == 'p':
                key_pub = value
            elif key == 'k':
                k = value
            elif key == 's':
                pass
            elif key == 't':
                if value == 'y':
                    subdomains = True
                    t = True
                elif value == 's:y':
                    subdomains = False
                    t = True
                elif value == 's':
                    t = False
                elif value == '':
                    pass
                else:
                    vdns.common.abort(f'Unhandled t value for DKIM record: "{addr2}"')
            elif key == 'h':
                h = value

        assert k != ''
        assert key_pub != ''

        # Caller must set domain and ttl
        # pylint: disable=unexpected-keyword-arg
        return vdns.rr.DKIM(domain='', hostname=hostname, ttl=None,
                            selector=selector, k=k, key_pub=key_pub, g=g, t=t, h=h, subdomains=subdomains)
        # pylint: enable=unexpected-keyword-arg

    def _parse_dnskey(self, addr: str) -> vdns.rr.DNSKEY:
        now = datetime.datetime.now()

        pl = vdns.parsing.ParsedLine(
            addr1='something',
            addr2=addr,
            rr='DNSKEY',
        )
        r = vdns.keyparser.parse_pub_key_line(pl)

        # Caller must set domain, hostname and ttl.
        # pylint: disable=unexpected-keyword-arg
        dnssec = vdns.rr.DNSSEC(
            domain='',
            hostname='',
            ttl=None,
            keyid=r.keyid,
            ksk=r.ksk,
            algorithm=r.algorithm,
            digest_sha1=r.sha1,
            digest_sha256=r.sha256,
            key_pub=r.key_pub,
            st_key_pub='',
            st_key_priv='',
            ts_created=now,
            ts_activate=now,
            ts_publish=now
        )
        # pylint: enable=unexpected-keyword-arg
        return vdns.rr.DNSKEY.from_dnssec(dnssec)

    def add_entry(self, r: Entry, domain: str) -> None:
        dnssec: vdns.rr.DNSSEC

        # pylint: disable=unexpected-keyword-arg
        if r.rr == 'PTR':
            logging.info('Ignoring PTR: %r', r)
        elif r.rr in ('A', 'AAAA'):
            self.dt.hosts.append(
                vdns.rr.Host(domain=domain, hostname=r.addr1, ip=ipaddress.ip_address(r.addr2),
                             ttl=r.ttl, reverse=False))
        elif r.rr == 'CNAME':
            self.dt.cnames.append(vdns.rr.CNAME(domain=domain, hostname=r.addr1, hostname0=r.addr2, ttl=r.ttl))
        elif r.rr == 'SSHFP':
            dt2 = r.addr2.split(None, 2)
            self.dt.sshfp.append(vdns.rr.SSHFP(domain=domain, hostname=r.addr1, keytype=int(dt2[0]),
                                               hashtype=int(dt2[1]), fingerprint=dt2[2], ttl=r.ttl))
        elif r.rr == 'NS':
            self.dt.ns.append(vdns.rr.NS(domain=domain, hostname=r.addr1, ns=r.addr2, ttl=r.ttl))
        elif r.rr == 'TXT':
            if r.addr1 and (r.addr1.endswith('._domainkey') or '._domainkey.' in r.addr1):
                dkim = self._parse_dkim(r.addr1, r.addr2)
                dkim.domain = domain
                dkim.ttl = r.ttl
                self.dt.dkim.append(dkim)
            else:
                txt = r.addr2
                if txt[0] == '"' and txt[-1] == '"':
                    txt = txt[1:-1]
                self.dt.txt.append(vdns.rr.TXT(domain=domain, hostname=r.addr1, txt=txt, ttl=r.ttl))
        elif r.rr == 'MX':
            dt2 = r.addr2.split(None, 1)
            self.dt.mx.append(
                vdns.rr.MX(domain=domain, hostname=r.addr1, priority=int(dt2[0]), mx=dt2[1], ttl=r.ttl))
        elif r.rr == 'DNSKEY':
            if r.addr1:
                vdns.common.abort(f'Found DNSKEY record with non-empty hostname: {r}')
            dnssec = self._parse_dnskey(r.addr2)
            dnssec.hostname = r.addr1
            dnssec.domain = domain
            dnssec.ttl = r.ttl
            self.dt.dnssec.append(dnssec)
        elif r.rr == 'DS':
            if not r.addr1:
                vdns.common.abort(f'Found DS record without a hostname: {r}')
            now = datetime.datetime.now()

            ds: Optional[vdns.rr.DNSSEC] = None

            ds_split = r.addr2.split(None, 3)
            if len(ds_split) != 4:
                vdns.common.abort(f'Bad DS line: {r.addr2}')

            # Try to find an existing entry first, because DS records have two entries
            for ds in self.dt.ds:
                if ds.keyid == int(ds_split[0]):
                    # These should match
                    if ds.domain != domain or ds.hostname != r.addr1:
                        vdns.common.abort(
                            f'Strange line: {r.addr2}: {ds.domain} != {domain} OR {ds.hostname} != {r.addr1}')
                    break

            if not ds or ds.keyid != int(ds_split[0]):
                dnssec = vdns.rr.DNSSEC(domain=domain, hostname=r.addr1, keyid=int(ds_split[0]), ksk=True, algorithm=8,
                                        digest_sha1='', digest_sha256='', key_pub='', st_key_pub='', st_key_priv='',
                                        ts_created=now, ts_activate=now, ts_publish=now)
                ds = vdns.rr.DS.from_dnssec(dnssec)
                self.dt.ds.append(ds)

            if ds_split[1] != '8':
                vdns.common.abort(f'Cannot handle protocol "{ds_split[1]}"')

            if ds_split[2] == '1':
                ds.digest_sha1 = ds_split[3]
            elif ds_split[2] == '2':
                ds.digest_sha256 = ds_split[3]
            else:
                vdns.common.abort(f'Cannot handle digest type "{ds_split[2]}"')
        else:
            logging.info('Unhandled %s: %r', r.rr, r)
        # pylint: enable=unexpected-keyword-arg

    def _read_file(self, fn: str) -> Optional[list[str]]:
        """Reads the contents of a file, to be mocked in tests."""
        try:
            f = open(fn, encoding='ASCII')  # pylint: disable=consider-using-with
        except OSError:
            logging.error('Failed to open file: %s', fn)
            return None
        return f.readlines()

    def read(self, fn: str, zone: Optional[str] = None) -> None:
        """Reads and parses a file."""
        lines = self._read_file(fn)
        if not lines:
            return
        self.parse(lines, zone)

    def parse(self, lines: Iterable[str], zone: Optional[str] = None) -> None:
        """Parses a set of lines.

        @param lines    A source of lines to parse
        @param zone     Optional zone name. If None then the SOA name is used.
        """

        lastname: Optional[str] = None
        domain: str = ''
        origin: str = ''    # Doesn't include the final dot
        in_parentheses = False

        buffer: list[str] = []  # For parentheses

        if zone is not None:
            domain = zone.strip('.')
            # soa['name'] = domain

        self.dt = ParsedDomainData()

        defttl: datetime.timedelta = datetime.timedelta()
        soattl: Optional[datetime.timedelta] = None

        r: Optional[vdns.parsing.ParsedLine]

        for line0 in lines:
            # Remove comments etc...
            line = vdns.parsing.cleanup_line(line0)

            # Handle special entries
            if line.startswith('$TTL'):
                t = line.split()
                defttl = vdns.parsing.parse_ttl(t[1])
                continue
            if line.startswith('$ORIGIN'):
                t = line.split()
                assert t[1].endswith('.'), f"Origin line doesn't end with dot: {line}"
                origin = t[1].removesuffix('.')
                continue

            # Buffer lines while we're in parentheses
            buffer.append(line)
            in_parentheses = vdns.parsing.line_ends_in_parentheses(line, in_parentheses)
            if in_parentheses:
                continue

            line2 = vdns.parsing.merge_multiline(buffer, merge_quotes=True)
            buffer = []

            r = vdns.parsing.parse_line(line2)

            if r is None:
                continue

            if r.addr1 == '@':
                r.addr1 = origin

            if r.rr == 'SOA':
                if domain:
                    if r.addr1 not in ('@', domain):
                        vdns.common.abort(f"Domain doesn't match! ({domain} - {r.addr1})")
                else:
                    if not r.addr1:
                        # No domain from SOA and not provided as a parameter
                        vdns.common.abort('Could not find domain from SOA')
                    else:
                        domain = r.addr1

                # Domain name was not passed as a parameter and wasn't determined from SOA
                if not domain:
                    vdns.common.abort('Failed to determine domain')

                logging.debug('Domain: %s', domain)

                lastname = None

                if r.ttl is None:
                    soattl = defttl
                else:
                    soattl = vdns.parsing.parse_ttl(r.ttl)

                # Sample r.addr2
                #  hell.gr. root.hell.gr. ( 2012062203 24H 1H 1W 1H )
                # After removal of ( and ):
                #  hell.gr. root.hell.gr. 2012062203 24H 1H 1W 1H
                # Fields:
                #  0: ns0
                #  1: contact
                #  2: serial
                #  3: refresh
                #  4: retry
                #  5: expire
                #  6: minimum

                t = r.addr2.split()

                self.dt.name = domain
                self.dt.soa = vdns.rr.SOA(
                    name=domain,
                    contact=t[1].removesuffix('.'),
                    serial=int(t[2]),
                    ttl=soattl,
                    refresh=vdns.parsing.parse_ttl(t[3]),
                    retry=vdns.parsing.parse_ttl(t[4]),
                    expire=vdns.parsing.parse_ttl(t[5]),
                    minimum=vdns.parsing.parse_ttl(t[6]),
                    ns0=t[0].removesuffix('.'),
                )

                continue

            if lastname is None and (r.addr1 is None or r.addr1 == '@'):
                lastname = None
            elif r.addr1 is not None:
                lastname = r.addr1

            # For reverse we only need the soa
            if self.is_reverse:
                continue

            # r2 = [lastname] + list(r[1:])
            entry = Entry(addr1=lastname, rr=r.rr, addr2=r.addr2)
            entryttl: Optional[datetime.timedelta] = None
            if r.ttl:
                entryttl = vdns.parsing.parse_ttl(r.ttl)

            # Set TTL:
            #   If TTL if not specified:
            #       If current ttl (based on $TTL) is same as SOAs then
            #       leave TTL==None
            #       If current ttl<>SOA's ttl then set ttl as the current ttl
            #   If TTL is specified:
            #       If it is same as SOAs then set it to NULL
            #       Else use the specified TTL
            #
            # TTL is r2[1]
            if entryttl is None:
                if soattl != defttl and defttl is not None:
                    entryttl = defttl

            # Don't convert this to 'else'. This way it will catch cases
            # where r2[1]==None (initially) and soattl!=defttl. In that case
            # r2[1] will become non-null and will be rexamined in case it
            # matches the soattl
            if entryttl is not None:
                entry.ttl = entryttl
                if entry.ttl == soattl:
                    entry.ttl = None

            self.add_entry(entry, domain)

        if buffer:
            vdns.common.abort(f'Zone parsing ended with data in the buffer: {buffer}')

    def show(self) -> None:
        """
        Show the data
        """
        pprint(self.dt)

    def data(self) -> ParsedDomainData:
        """
        Return the data dictionary
        """

        return self.dt

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
