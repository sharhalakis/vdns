#!/usr/bin/env python
# coding=UTF-8
#

import re
import logging
import datetime
import ipaddress
import dataclasses as dc

from typing import Any, Optional, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPInterface = Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class AbortError(Exception):
    def __init__(self, *args: Any, excode: int = 1, **kwargs: Any):
        """Indicates a program abort with exit code."""
        self.excode = excode
        super().__init__(*args, **kwargs)


def reverse_name(net: str) -> str:
    """
    Form the domain name of an IP network/address

    @param net      Is in the form 10.0.0.0/8
    """

    network: IPNetwork = ipaddress.ip_network(net)
    ip: IPAddress = network.network_address

    if network.version == 4:
        octet_size = 8
        octet_number = 4
    elif network.version == 6:
        octet_size = 4
        octet_number = 32
    else:
        logging.error('Bad address family: %s', network.version)
        abort('I cannot handle this address type')

    if network.prefixlen % octet_size != 0:
        logging.error('Mask must be multiple of %d for IPv%d', octet_size, network.version)
        abort("I don't know what to do")

    num = network.prefixlen // octet_size
    octets = ip.reverse_pointer.split('.')
    st = '.'.join(octets[(octet_number - num):])

    return st


@dc.dataclass
class FmttdReturn:
    value: str = ''
    human_readable: str = ''


def zone_fmttd(td: datetime.timedelta) -> FmttdReturn:
    """
    Format a timedelta value to something that's appropriate for
    zones
    """

    ret = FmttdReturn()

    lst = ((1, '', 'second', 'seconds'),
           (60, 'M', 'minute', 'minutes'),
           (3600, 'H', 'hour', 'hours'),
           (86400, 'D', 'day', 'days'),
           (86400 * 7, 'W', 'week', 'weeks'))

    ts = int(td.total_seconds())

    if ts == 0:
        raise ValueError("Timedelta can't be 0")

    # Find the first value that doesn't give an exact result
    ent = lst[0]
    for i in lst:
        if (ts % i[0]) != 0:
            break
        ent = i

    ts_scaled = int(ts / ent[0])
    suffix = ent[1]
    ret.value = f'{ts_scaled}{suffix}'

    # Now form the human readable string
    rem = ts
    ret2 = []
    for i in reversed(lst):
        t, rem = divmod(rem, i[0])

        if t == 0:
            continue

        if t == 1:
            unit = i[2]
        else:
            unit = i[3]

        st = f'{t} {unit}'

        ret2.append(st)

        # Speadup
        if rem == 0:
            break

    ret.human_readable = ', '.join(ret2)

    return ret


def fmtrecord(name: str, ttl: Optional[datetime.timedelta], rr: str, data: str) -> str:
    """Formats a record.

    This is a dump function that concatenates data, translating ttl

    Use mkrecord instead

    @param name     The hostname
    @param ttl      The TTL in seconds
    @param rr       The type of the record
    @param data     A freeform string
    @return The formed entry
    """

    if ttl is None:
        ttl2 = ''
    else:
        t = zone_fmttd(ttl)
        ttl2 = ' ' + t.value

    ret = f'{name:16s}{ttl2}	IN	{rr}	{data}'

    return ret


def split_txt(data: str) -> str:
    """Splits TXT data to chunks of max 255 bytes to comply with bind.

    @param data     An unquoted string of arbitrary length
    @return A quoted string to be used as TXT record
    """
    limit = 255

    items = []
    data2 = data
    while len(data2) > limit:
        items.append(data2[:limit])
        data2 = data2[limit:]
    items.append(data2)

    ret = '"' + '" "'.join(items) + '"'

    return ret


def spaces2tabs(st: str) -> str:
    # ret = st.expandtabs()
    ret = st
    ret = ret.replace('        ', '\t')
    return ret


def compact_spaces(st: str) -> str:
    """Replaces all spaces with a single space and strips leading and trailing spaces."""
    return re.sub(r'\s+', ' ', st).strip()


def abort(reason: str) -> None:
    logging.error('%s', reason)
    raise AbortError(reason, excode=1)


def validate_dataclass(d: object) -> None:
    fields = dc.fields(d)
    for field in fields:
        value = getattr(d, field.name)
        if not isinstance(value, field.type):
            raise Exception(f'Field {field.name} has value {value} which is not of type {field.type} in: {d}')


if __name__ == '__main__':
    pass

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
