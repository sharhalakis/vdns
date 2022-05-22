#!/usr/bin/env python
# coding=UTF-8
#

import sys
import struct
import base64
import hashlib
import logging
import dataclasses as dc

from pprint import pprint
from typing import Optional, Sequence, Union

__all__ = ['ZoneParser']

db = None

# List if known RRs. We only need to list those that we handle.
RRS = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'TXT', 'SOA', 'DNSKEY', 'PTR']


def is_ttl(st: str) -> bool:
    return (bool(st)
            and st[0] in ('1', '2', '3', '4', '5', '6', '7', '8', '9', '0')
            and st[-1] != '.'
            and 'arpa' not in st)


def cleanup_line(line0: str) -> str:
    """Cleans a line by removing comments and starting/trailing space."""
    line = line0

    # If there's a potential comment then scan the whole string char-by-char.
    # Don't remove quoted semicolons like in 'TXT "v=DKIM1; g=*"'
    if line.find(';') >= 0:
        in_st = False   # Are we in a "" block? If yes then ignore ;
        line = ''
        for ch in line0:
            if not in_st and ch == ';':
                break
            line += ch
            if ch == '"':
                in_st = not in_st

    line = line.strip()

    return line


@dc.dataclass
class ParsedLine:
    addr1: Optional[str] = None
    ttl: Optional[str] = None  # As read. E.g., 1D, 2W
    rr: str = ''
    addr2: str = ''

    def count(self) -> int:
        return sum([bool(self.addr1),
                    bool(self.addr2),
                    bool(self.rr),
                    self.ttl is not None,
                    ])


@dc.dataclass
class Entry:
    addr1: Optional[str] = ''
    ttl: Optional[int] = None   # As read. E.g., 1D, 2W
    rr: str = ''
    addr2: str = ''


def parse_ttl(st: str) -> int:
    """
    Parse ttl and return the duration in seconds
    """
    deltas = {
        'M': 60,
        'H': 3600,
        'D': 86400,
        'W': 86400 * 7,
    }

    # If this is already a number
    if isinstance(st, int):
        ret = st
    elif st[-1].isdigit():
        ret = int(st)
    else:
        ret = int(st[:-1])
        w = st[-1].upper()
        ret *= deltas[w]

    return ret


def parse_line(line0: str) -> Optional[ParsedLine]:
    line = cleanup_line(line0)

    if len(line) == 0 or line[0] == ';':
        return None

    ret = ParsedLine()
    items = line.split()
    addr2idx = 0
    rridx = None

    # Nothing to do for these
    if items[0] in ('RRSIG', 'NSEC'):
        return None

    # Find the type
    for i, item in enumerate(items):
        if item in RRS:
            rridx = i
            addr2idx = i + 1
            break

    if rridx is None:
        return None

    ret.rr = items[rridx]

    # Preserve addr2's spaces. Re-split addr2idx times and get the remainder
    ret.addr2 = line.split(maxsplit=addr2idx)[-1]

    for i in range(rridx):
        if items[i] == 'IN':
            continue

        if ret.ttl is None and is_ttl(items[i]):
            ret.ttl = items[i]
        elif ret.addr1 is None:
            ret.addr1 = items[i]
        else:
            logging.warning('Could not parse line: %s ', line)
            return None

    return ret


def sinn(val: Optional[str], char: str) -> Optional[str]:
    # Strip if not None
    if val is None:
        ret = None
    else:
        ret = val.strip(char)

    return ret


def ein(val: Optional[str]) -> str:
    # Return empty if it's null
    if val is None:
        return ''
    return val


def esinn(val: Optional[str], char: str) -> str:
    return ein(sinn(val, char))


def error(st: str) -> None:
    logging.error(st)
    sys.exit(1)


def insert(tbl: str, fields: Sequence[str], values: Sequence[Optional[Union[str, int]]]) -> str:
    values2 = []
    for v in values:
        if v is None:
            values2.append('NULL')
        elif isinstance(v, str) and len(v) > 0 and v[0] == '\x00':
            values2.append(v[1:])
        else:
            values2.append(f"'{v}'")

    st_fields = ', '.join(fields)
    st_values2 = ', '.join(values2)
    st = f'INSERT INTO {tbl}({st_fields}) VALUES({st_values2});'
    # st = 'INSERT INTO %s(%s) VALUES(%s);' % (tbl, ', '.join(fields), ', '.join(values2))

    return st


def ins_soa(name: str, reverse: str, ttl: int, refresh: str, retry: str, expire: str, minimum: str,
            contact: str, serial: str, ns0: str) -> str:
    name2 = esinn(name, '.')
    contact2 = esinn(contact, '.')
    ns02 = ns0.strip('.')

    ret = insert('domains',
                 ('name', 'reverse', 'ttl', 'refresh', 'retry', 'expire', 'minimum',
                  'contact', 'serial', 'ns0'),
                 (name2, reverse, ttl, refresh, retry, expire, minimum, contact2,
                  serial, ns02))

    return ret


def ins_a(domain: str, host: str, ip: str, ttl: int) -> str:
    host2 = esinn(host, '.')
    domain2 = domain.strip('.')

    ret = insert('hosts', ('ip', 'domain', 'hostname', 'ttl'),
                 (ip, domain2, host2, ttl))

    return ret


def ins_cname(domain: str, host: str, host0: str, ttl: int) -> str:
    host2 = esinn(host, '.')
    host02 = host0.strip('.')
    domain2 = domain.strip('.')

    ret = insert('cnames', ('domain', 'hostname', 'hostname0', 'ttl'),
                 (domain2, host2, host02, ttl))

    return ret


def ins_txt(domain: str, host: str, txt: str, ttl: int) -> str:
    host2 = esinn(host, '.')
    domain2 = domain.strip('.')
    txt2 = txt.strip('"')

    ret = insert('txt', ('domain', 'hostname', 'txt', 'ttl'),
                 (domain2, host2, txt2, ttl))

    return ret


def ins_ns(domain: str, ns: str, ttl: int) -> str:
    domain2 = domain.strip('.')
    ns2 = ns.strip('.')

    ret = insert('ns', ('domain', 'ns', 'ttl'),
                 (domain2, ns2, ttl))

    return ret


def ins_mx(domain: str, hostname: str, priority: str, mx: str, ttl: int) -> str:
    domain2 = domain.strip('.')
    hostname2 = esinn(hostname, '.')
    mx2 = mx.strip('.')

    ret = insert('mx', ('domain', 'hostname', 'priority', 'mx', 'ttl'),
                 (domain2, hostname2, priority, mx2, ttl))

    return ret


def calc_dnssec_keyid(flags: str, protocol: str, algorithm: str, st: str) -> int:
    """
    Calculate the keyid based on the key string
    """

    st2: bytes

    st0 = st.replace(' ', '')
    st2 = struct.pack('!HBB', int(flags), int(protocol), int(algorithm))
    st2 += base64.b64decode(st0)

    cnt = 0
    for idx, ch in enumerate(st2):
        # TODO: verify this. Looks like we don't need the struct.unpack in python3
        # s = struct.unpack('B', ch)[0]
        s = ch
        if (idx % 2) == 0:
            cnt += s << 8
        else:
            cnt += s

    ret = ((cnt & 0xFFFF) + (cnt >> 16)) & 0xFFFF

    return ret


def calc_ds_sigs(owner: str, flags: str, protocol: str, algorithm: str, st: str) -> dict[str, str]:
    """
    Calculate the DS signatures

    Return a dictionary where key is the algorithm and value is the value
    """

    st2: bytes

    st0 = st.replace(' ', '')
    st2 = struct.pack('!HBB', int(flags), int(protocol), int(algorithm))
    st2 += base64.b64decode(st0)

    # Transform owner from A.B.C to <legth of A>A<length of B>B<length of C>C0

    if owner[-1] == '.':
        owner2 = owner
    else:
        owner2 = owner + '.'

    owner3 = b''
    for i in owner2.split('.'):
        owner3 += struct.pack('B', len(i)) + i.encode('ASCII')

    st3: bytes = owner3 + st2

    ret = {
        'sha1': hashlib.sha1(st3).hexdigest().upper(),
        'sha256': hashlib.sha256(st3).hexdigest().upper(),
    }

    return ret


# def ins_dnssec_no(domain, hostname, flags, protocol, algorithm, key_pub):
#     domain2 = domain.strip('.')
#     hostname2 = esinn(hostname, '.')
#
#     keyid = calc_dnssec_keyid(flags, protocol, algorithm, key_pub)
#
#     print('keyid', keyid)
#
#     insert('dnssec',
#            ('domain', 'hostname', 'keyid', 'algorithm', 'key_pub'),
#            (domain2, hostname2, keyid, algorithm, key_pub))


# def handle_entry(domain: str, r: Sequence[str]) -> None:
#     addr1 = r[0]
#     addr2 = r[4]
#     ttl = r[1]
#     rr = r[3]
#
#     if rr == 'PTR':
#         logging.info('Ignoring PTR: %r', r)
#     elif rr in ('A', 'AAAA'):
#         ins_a(domain, addr1, addr2, ttl)
#     elif rr == 'CNAME':
#         ins_cname(domain, addr1, addr2, ttl)
#     elif rr == 'NS':
#         # Don't do NS records for a zone here (i.e. when addr1!='')
#         # We will collect them from the zone itself (i.e when addr1=='')
#         if addr1 is not None and addr1 != '':
#             logging.info('Skipping NS record for %s.%s', addr1, domain)
#         else:
#             ins_ns(domain, addr2, ttl)
#     elif rr == 'TXT':
#         ins_txt(domain, addr1, addr2, ttl)
#     elif rr == 'MX':
#         t = addr2.split(None, 1)
#         ins_mx(domain, addr1, int(t[0]), t[1], ttl)
#     #    elif rr=='DS':
#     #        t=addr2.split(None, 3)
#     #        if (t[2]!='1'):
#     #            msg('Unrecognized DS record: %s' % addr2)
#     #        else:
#     #            ins_ds(domain, addr1, t[0], t[1], t[2], t[3])
#     #    elif rr=='DNSKEY':
#     #        t=addr2.split(None, 3)
#     ##        if (t[2]!='1'):
#     ##            msg('Unrecognized DNSKEY record: %s' % addr2)
#     ##        else:
#     #        ins_dnssec(domain, addr1, t[0], t[1], t[2], t[3])
#     else:
#         logging.info('Unhandled %s: %r', rr, r)


@dc.dataclass
class Data:

    @dc.dataclass
    class SOA:
        name: str = ''
        contact: str = ''
        serial: int = 0
        ttl: int = 0
        refresh: int = 0
        retry: int = 0
        expire: int = 0
        minimum: int = 0
        ns0: str = ''
        reverse: bool = False

    domain: str = ''
    soa: SOA = dc.field(default_factory=SOA)
    a: list[tuple[Optional[str], str, Optional[int]]] = dc.field(default_factory=list)  # addr1, addr2, ttl
    aaaa: list[tuple[Optional[str], str, Optional[int]]] = dc.field(default_factory=list)  # addr1, addr2, ttl
    # ptr: list[]   # Ignored
    cname: list[tuple[Optional[str], str, Optional[int]]] = dc.field(default_factory=list)  # addr1, addr2, ttl
    ns: list[tuple[str, Optional[int]]] = dc.field(default_factory=list)  # addr2, ttl
    txt: list[tuple[Optional[str], str, Optional[int]]] = dc.field(default_factory=list)  # addr1, addr2, ttl
    mx: list[tuple[Optional[str], int, str, Optional[int]]] = dc.field(default_factory=list)  # addr1, addr2-prio, addr2-addr, ttl
    defttl: int = 0


class ZoneParser:
    """
    A class to read and parse a zone file
    """
    # dt: dict[str, Any]
    dt: Data
    is_reverse: bool

    def __init__(self, fn: Optional[str] = None, zone: Optional[str] = None, is_reverse: bool = False) -> None:
        self.dt = Data()
        self.is_reverse = is_reverse

        if fn is not None:
            self.read(fn, zone)

    def add_entry(self, r: Entry) -> None:
        dt: tuple
        if r.rr == 'PTR':
            logging.info('Ignoring PTR: %r', r)
        elif r.rr in ('A', 'AAAA'):
            dt = (r.addr1, r.addr2, r.ttl)
            if r.rr == 'A':
                self.dt.a.append(dt)
            else:
                self.dt.aaaa.append(dt)
        elif r.rr == 'CNAME':
            dt = (r.addr1, r.addr2, r.ttl)
            self.dt.cname.append(dt)
        elif r.rr == 'NS':
            # Don't do NS records for a zone here (i.e. when r.addr1!='')
            # We will collect them from the zone itself (i.e when r.addr1=='')
            if r.addr1 is not None and r.addr1 != '':
                logging.info('Skipping NS record for %s', r.addr1)
            else:
                dt = (r.addr2, r.ttl)
                self.dt.ns.append(dt)
        elif r.rr == 'TXT':
            dt = (r.addr1, r.addr2, r.ttl)
            self.dt.txt.append(dt)
        elif r.rr == 'MX':
            t = r.addr2.split(None, 1)
            dt = (r.addr1, int(t[0]), t[1], r.ttl)
            self.dt.mx.append(dt)
        else:
            logging.info('Unhandled %s: %r', r.rr, r)

    # def add_entry_old(self, r: Entry):
    #     if r.rr == 'PTR':
    #         logging.info('Ignoring PTR: %r', r)
    #     elif r.rr in ('A', 'AAAA'):
    #         dt = [r.addr1, r.addr2, r.ttl]
    #         if r.rr == 'A':
    #             self.dt['a'].append(dt)
    #         else:
    #             self.dt['aaaa'].append(dt)
    #     elif r.rr == 'CNAME':
    #         dt = [r.addr1, r.addr2, r.ttl]
    #         self.dt['cname'].append(dt)
    #     elif r.rr == 'NS':
    #         # Don't do NS records for a zone here (i.e. when r.addr1!='')
    #         # We will collect them from the zone itself (i.e when r.addr1=='')
    #         if r.addr1 is not None and r.addr1 != '':
    #             logging.info('Skipping NS record for %s', r.addr1)
    #         else:
    #             dt = [r.addr2, r.ttl]
    #             self.dt['ns'].append(dt)
    #     elif r.rr == 'TXT':
    #         dt = [r.addr1, r.addr2, r.ttl]
    #         self.dt['txt'].append(dt)
    #     elif r.rr == 'MX':
    #         t = r.addr2.split(None, 1)
    #         dt = [r.addr1, int(t[0]), t[1], r.ttl]
    #         self.dt['mx'].append(dt)
    #     else:
    #         logging.info('Unhandled %s: %r', r.rr, r)

    def _read_file(self, fn: str) -> Optional[list[str]]:
        """Reads the contents of a file, to be mocked in tests."""
        try:
            f = open(fn, encoding='ASCII')  # pylint: disable=consider-using-with
        except OSError:
            logging.error('Failed to open file: %s', fn)
            return None
        return f.readlines()

    def read(self, fn: str, zone: Optional[str] = None) -> None:
        """
        @param zone     Optional zone name. If None then the SOA name is used.
        """

        lastname: Optional[str] = None
        domain: str = ''
        insoa = False

        # soa = {
        #     'name': None,
        #     'defttl': None,
        #     'refresh': None,
        #     'retry': None,
        #     'expire': None,
        #     'minimum': None,
        #     'contact': None,
        #     'serial': None,
        #     'ns0': None,
        # }
        soastr = ''

        if zone is not None:
            domain = zone.strip('.')
            # soa['name'] = domain

        self.dt = Data()

        defttl: int = -1
        soattl: Optional[int] = None

        r: Optional[ParsedLine]

        lines = self._read_file(fn)
        if not lines:
            return

        for line0 in lines:
            # Remove comments etc...
            line = cleanup_line(line0)

            # Handle special entries
            if line.startswith('$TTL'):
                t = line.split()
                defttl = parse_ttl(t[1])
                self.dt.defttl = defttl
                continue

            # If we are in SOA then concatenate the lines until we find a )
            # Then parse the resulting line
            #
            # Don't attempt to parse intermediate SOA lines. Remember that
            # the first line is already parsed.
            #
            # This logic fails if the whole SOA is on one line and there is
            # no empty/comment line after that.
            if insoa:
                soastr += ' '
                soastr += line

                # The end
                if ')' in soastr:
                    insoa = False

                    r = parse_line(soastr)
                    if r is None:
                        raise Exception(f'Failed to parsed SOA: {soastr}')
                    # msg(repr(r))

                    ttl: Optional[int]

                    if r.ttl is None:
                        ttl = None
                    else:
                        ttl = parse_ttl(r.ttl)

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

                    t = r.addr2.replace('(', '').replace(')', '').split()

                    #                    if domain.strip('.')!=t[0].strip('.'):
                    #                        error('Domain doesn't match! (%s - %s)' % \
                    #                            (domain, t[0]))

                    if ttl is None:
                        ttl = defttl

                    soattl = ttl

                    # Domain name was not passed as a parameter and wasn't determined from SOA
                    if not domain:
                        raise Exception('Failed to determine domain')

                    self.dt.domain = domain
                    self.dt.soa = Data.SOA(
                        name=domain,
                        contact=t[1],
                        serial=int(t[2]),
                        ttl=ttl,
                        refresh=parse_ttl(t[3]),
                        retry=parse_ttl(t[4]),
                        expire=parse_ttl(t[5]),
                        minimum=parse_ttl(t[6]),
                        ns0=t[0],
                        reverse=False,
                    )
                #                    ins_soa(name=domain, contact=t[1], serial=t[2], ttl=ttl,
                #                        refresh=t[3], retry=t[4], expire=t[5], minimum=t[6],
                #                        ns0=t[0], reverse=False)

                continue

            r = parse_line(line)

            if r is None:
                continue

            if r.rr == 'SOA':
                if domain:
                    if r.addr1 not in ('@', domain):
                        error(f"Domain doesn't match! ({domain} - {r.addr1})")
                else:
                    if not r.addr1:
                        # No domain from SOA and not provided as a parameter
                        error('Could not find domain from SOA')
                    else:
                        domain = r.addr1

                # domain=r[4].split()[0]

                # if r.addr1 != '@' and domain:
                #     if r.addr1 != domain:
                #         error(f"Domain doesn't match! ({domain} - {r.addr1})")
                #
                # if not domain:
                #     if not r.addr1:
                #         # No domain from SOA and not provided as a parameter
                #         error('Could not find domain from SOA')
                #     else:
                #         domain = r.addr1

                # domain = zone
                lastname = None

                logging.debug('Domain: %s', domain)

                insoa = True
                soastr = line

                continue

            if lastname is None and (r.addr1 is None or r.addr1 == '@'):
                # msg('Zone entry: ' + repr(r))
                lastname = None
            elif r.addr1 is not None:
                lastname = r.addr1

            # For reverse we only need the soa
            if self.is_reverse:
                continue

            # r2 = [lastname] + list(r[1:])
            entry = Entry(addr1=lastname, rr=r.rr, addr2=r.addr2)
            entryttl: Optional[int] = None
            if r.ttl:
                entryttl = parse_ttl(r.ttl)

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

            self.add_entry(entry)

    #            handle_entry(domain, r2)

    '''
    def read_old(self, fn:str, zone: Optional[str] = None) -> None:
        """
        @param zone     Optional zone name. If None then the SOA name is used.
        """

        lastname = None
        domain = None
        insoa = False

        soa = {
            'name': None,
            'defttl': None,
            'refresh': None,
            'retry': None,
            'expire': None,
            'minimum': None,
            'contact': None,
            'serial': None,
            'ns0': None,
        }
        soastr = ''

        if zone is not None:
            domain = zone.strip('.')
            soa['name'] = domain

        self.dt['domain'] = domain

        defttl = -1
        soattl = None

        r: ParsedLine

        try:
            f = open(fn, encoding='ASCII')  # pylint: disable=consider-using-with
        except OSError:
            logging.error('Failed to open file: %s', fn)
            return

        for line0 in f:
            # Remove comments etc...
            line = cleanup_line(line0)

            # Handle special entries
            if line[:4] == '$TTL':
                t = line.split()
                defttl = parse_ttl(t[1])
                self.dt['defttl'] = defttl
                continue

            # If we are in SOA then concatenate the lines until we find a )
            # Then parse the resulting line
            #
            # Don't attempt to parse intermediate SOA lines. Remember that
            # the first line is already parsed.
            #
            # This logic fails if the whole SOA is on one line and there is
            # no empty/comment line after that.
            if insoa:
                soastr += ' '
                soastr += line

                # The end
                if ')' in soastr:
                    insoa = False

                    r = parse_line(soastr)
                    # msg(repr(r))

                    if r.ttl is None:
                        ttl = None
                    else:
                        ttl = parse_ttl(r.ttl)

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

                    t = r.addr2.replace('(', '').replace(')', '').split()

                    #                    if domain.strip('.')!=t[0].strip('.'):
                    #                        error('Domain doesn't match! (%s - %s)' % \
                    #                            (domain, t[0]))

                    if ttl is None:
                        ttl = defttl

                    soattl = ttl

                    self.dt['soa'] = {
                        'name': domain,
                        'contact': t[1],
                        'serial': t[2],
                        'ttl': ttl,
                        'refresh': parse_ttl(t[3]),
                        'retry': parse_ttl(t[4]),
                        'expire': parse_ttl(t[5]),
                        'minimum': parse_ttl(t[6]),
                        'ns0': t[0],
                        'reverse': False
                    }
                #                    ins_soa(name=domain, contact=t[1], serial=t[2], ttl=ttl,
                #                        refresh=t[3], retry=t[4], expire=t[5], minimum=t[6],
                #                        ns0=t[0], reverse=False)

                continue

            r = parse_line(line)

            if r is None:
                continue

            if r.rr == 'SOA':
                # domain=r[4].split()[0]
                if r.addr1 != '@':
                    if r.addr1 != domain:
                        error(f"Domain doesn't match! ({domain} - {r.addr1})")

                domain = zone
                lastname = None

                logging.debug('Domain: %s', domain)

                insoa = True
                soastr = line

                continue

            if lastname is None and (r.addr1 is None or r.addr1 == '@'):
                # msg('Zone entry: ' + repr(r))
                lastname = None
            elif r.addr1 is not None:
                lastname = r.addr1

            # For reverse we only need the soa
            if self.is_reverse:
                continue

            # r2 = [lastname] + list(r[1:])
            entry = Entry(addr1=lastname, rr=r.rr, addr2=r.addr2)
            entryttl = r.ttl

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
                if soattl != defttl:
                    entryttl = defttl

            # Don't convert this to 'else'. This way it will catch cases
            # where r2[1]==None (initially) and soattl!=defttl. In that case
            # r2[1] will become non-null and will be rexamined in case it
            # matches the soattl
            if entryttl is not None:
                entry.ttl = parse_ttl(entryttl)
                if entry.ttl == soattl:
                    entry.ttl = None

            self.add_entry(entry)

    #            handle_entry(domain, r2)
    '''

    def show(self) -> None:
        """
        Show the data
        """
        pprint(self.dt)

#     def make_sql(self) -> None:
#         """
#         Return a list of SQL commands
#         """
#
#         dt = self.dt
#         d = dt.domain
#
#         ret = []
#
#         ret.extend([ins_a(d, *x) for x in dt.a])
#         ret.extend([ins_a(d, *x) for x in dt.aaaa])
#         ret.extend([ins_cname(d, *x) for x in dt.cname])
#         ret.extend([ins_ns(d, *x) for x in dt.ns])
#         ret.extend([ins_txt(d, *x) for x in dt.txt])
#         ret.extend([ins_mx(d, *x) for x in dt.mx])
#         # for x in dt['a']:           ret.append(ins_a(d, *x))
#         # for x in dt['aaaa']:        ret.append(ins_a(d, *x))
#         # for x in dt['cname']:       ret.append(ins_cname(d, *x))
#         # for x in dt['ns']:          ret.append(ins_ns(d, *x))
#         # for x in dt['txt']:         ret.append(ins_txt(d, *x))
#         # for x in dt['mx']:          ret.append(ins_mx(d, *x))
#
#         print('\n'.join(ret))

    def data(self) -> Data:
        """
        Return the data dictionary
        """

        return self.dt

# if __name__=='__main__':
#    # init()
#
#    z=ZoneParser(Config.fn, Config.zone)
#
#    if Config.output=='sql':
#        z.make_sql()
#    elif Config.output=='dump':
#        z.show()


# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
