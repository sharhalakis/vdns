import logging
import dataclasses as dc

from pprint import pprint
from typing import Iterable, Optional

__all__ = ['ZoneParser']

import vdns.common

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


def line_ends_in_parentheses(line: str, in_parentheses: bool) -> bool:
    """Checks whether a line ends with open parentheses or not.

    Args:
        line: The line to parse. The line must be already clean from comments.
        in_parentheses: if True then indicate that it's already in parentheses, for sanity checks.

    Returns:
        True if the line ends while a parentheses is open
    """
    in_quotes = False

    for x in line:
        if in_quotes and x != '"':
            continue
        if x == '"':
            in_quotes = not in_quotes
            continue
        if in_parentheses:
            if x == ')':
                in_parentheses = False
            elif x == '(':
                vdns.common.abort(f'Found "(" while already in parentheses: {line}')
        else:  # not in_parentheses
            if x == '(':
                in_parentheses = True
            elif x == ')':
                vdns.common.abort(f'Found ")" without being in parentheses: {line}')

    if in_quotes:
        vdns.common.abort(f'Line ended up with open quotes: {line}')

    return in_parentheses


def merge_multiline(lines0: Iterable[str], merge_quotes: bool) -> str:
    """Merges multiple lines to a single line, taking care of parentheses and quotes."""
    ret = ''
    in_quotes = False
    in_parentheses = False

    # Merge the lines, removing any comments
    lines: list[str] = []
    for line0 in lines0:
        lines.append(vdns.common.compact_spaces(cleanup_line(line0)))

    # Maintain '\n' for sanity checking quotes. It'll be replaced by space.
    line = '\n'.join(lines)

    for x in line:
        # Quotes must not span multiple lines
        if x == '\n':
            if in_quotes:
                vdns.common.abort(f'Line ended up with open quotes: {line}')
            ret += ' '
            continue

        if in_quotes and x != '"':
            ret += x
            continue
        if x == '"':
            ret += x
            in_quotes = not in_quotes
            continue

        if x == '(':
            if in_parentheses:
                vdns.common.abort(f'Found "(" within "(": {line}')
            in_parentheses = True
        elif x == ')':
            if not in_parentheses:
                vdns.common.abort(f'Found ")" wouthout "(": {line}')
            in_parentheses = False
        elif x in ('\n', '\r'):
            ret += ' '
        else:
            ret += x

    if merge_quotes:
        ret = vdns.common.merge_quotes(ret)
    else:
        ret = vdns.common.compact_spaces(ret)

    return ret


@dc.dataclass
class ParsedLine:
    addr1: Optional[str] = None
    ttl: Optional[str] = None  # As read. E.g., 1D, 2W
    rr: str = ''
    addr2: str = ''


@dc.dataclass
class Entry:
    addr1: Optional[str] = ''
    ttl: Optional[int] = None
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
    elif st[-1].upper() in deltas:
        ret = int(st[:-1])
        w = st[-1].upper()
        ret *= deltas[w]
    else:
        vdns.common.abort(f'Cannot parse ttl "{st}"')

    return ret


def parse_line(line0: str) -> Optional[ParsedLine]:
    """Parses a line. Line can actually be multiple lines."""
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
    addr2 = line.split(maxsplit=addr2idx)[-1]
    ret.addr2 = addr2

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
        in_parentheses = False

        buffer: list[str] = []  # For parentheses

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

            # Buffer lines while we're in parentheses
            buffer.append(line)
            in_parentheses = line_ends_in_parentheses(line, in_parentheses)
            if in_parentheses:
                continue

            line2 = merge_multiline(buffer, merge_quotes=True)
            buffer = []

            r = parse_line(line2)

            if r is None:
                continue

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
                    soattl = parse_ttl(r.ttl)

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

                self.dt.domain = domain
                self.dt.soa = Data.SOA(
                    name=domain,
                    contact=t[1],
                    serial=int(t[2]),
                    ttl=soattl,
                    refresh=parse_ttl(t[3]),
                    retry=parse_ttl(t[4]),
                    expire=parse_ttl(t[5]),
                    minimum=parse_ttl(t[6]),
                    ns0=t[0],
                    reverse=False,
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

        if buffer:
            vdns.common.abort(f'Zone parsing ended with data in the buffer: {buffer}')

    def show(self) -> None:
        """
        Show the data
        """
        pprint(self.dt)

    def data(self) -> Data:
        """
        Return the data dictionary
        """

        return self.dt

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
