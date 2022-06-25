# Common parsing functions

import logging
import dataclasses as dc

from typing import Iterable, Optional

import vdns.rr
import vdns.src.src0
import vdns.zone0
import vdns.common

# List if known RRs. We only need to list those that we handle.
RRS = ['A', 'AAAA', 'NS', 'CNAME', 'DKIM', 'DS', 'MX', 'SSHFP', 'TXT', 'SOA', 'DNSKEY', 'PTR']


@dc.dataclass
class ParsedLine:
    addr1: Optional[str] = None
    ttl: Optional[str] = None  # As read. E.g., 1D, 2W
    rr: str = ''
    addr2: str = ''


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
                vdns.common.abort(f'Found ")" without "(": {line}')
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
