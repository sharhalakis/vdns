# Copyright (c) 2014-2016 Stefanos Harhalakis <v13@v13.gr>
# Copyright (c) 2016-2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import datetime
import ipaddress
import dataclasses as dc

from typing import Any, NoReturn, Sequence, Optional, Type, Union, get_origin, get_args

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPInterface = Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class AbortError(Exception):
    excode: int
    error_shown: bool

    def __init__(self, *args: Any, excode: int = 1, error_shown: bool = False, **kwargs: Any):
        """Indicates a program abort with exit code."""
        self.excode = excode
        self.error_shown = error_shown
        super().__init__(*args, **kwargs)


class DataclassValidationError(Exception):
    def __init__(self, field: dc.Field, value: object, data: object) -> None:
        super().__init__(f'Field {field.name} has type {type(value).__name__}, value {value} '
                         f'which is not of type {field.type} in: {data}')


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


def tabify(st: str, width: int) -> str:
    """Adds tabs at the end of a string.

    Ensures that the string has as many tabs at its end as needed to reach "width".
    Always adds a tab at the end, even if len(st) >= width.

    Args:
        st: The string to add tabs to.
        width: The width to add padding to. Must be a multiple of 8.
    Returns:
        The padded string.
    """
    assert width % 8 == 0
    if len(st) >= width:
        # Ensure some empty space at the end
        return f'{st}\t'
    padding = width - len(st)
    tabcount = padding // 8
    if padding % 8 > 0:
        tabcount += 1
    return st + ('\t' * tabcount)


def fmtrecord(name: str, ttl: Optional[datetime.timedelta], rr: str, data: str,
              multiline_data: Sequence[str] = (), comment: Optional[str] = None) -> str:
    """Formats a record.

    This is a dump function that concatenates data, translating ttl

    Use mkrecord instead

    @param name             The hostname
    @param ttl              The TTL in seconds
    @param rr               The type of the record
    @param data             A freeform string
    @param multiline_data   Additional data to be added as multiple-lines in parentheses
    @param comment          An optional comment to be added to the line at the end
    @return The formed entry
    """

    if ttl is None:
        ttl2 = ''
    else:
        t = zone_fmttd(ttl)
        ttl2 = t.value

    # Make more room for the hostname if there's no ttl. Saves adding an extra tab to hostnames over 24 characters long.
    if ttl2 != '':
        name = tabify(name, 24)
        ttl2 = tabify(ttl2, 8)
    else:
        name = tabify(name, 32)

    rr = tabify(rr, 8)

    if multiline_data:
        prefix = '\n' + ('\t' * ((len(name.expandtabs()) + len(ttl2.expandtabs()) + len(rr.expandtabs()) + 8) // 8))
        data_lines = []
        if data:
            if len(multiline_data) > 1:
                data_lines.append(f'{data} (')
            else:
                data_lines.append(data)
            data_lines.extend(multiline_data)
        else:
            # Don't split if there's just one line
            if len(multiline_data) > 1:
                data_lines.append(f'( {multiline_data[0]}')
                data_lines.extend(multiline_data[1:])
                prefix += '  '
            else:
                data_lines.extend(multiline_data)

        if comment:
            if len(multiline_data) > 1:
                data_lines.append(f') ; {comment}')
            else:
                data_lines.append(f' ; {comment}')
        else:
            if len(multiline_data) > 1:
                data_lines[-1] = f'{data_lines[-1]} )'

        data = prefix.join(data_lines)
    else:
        if comment:
            data = f'{data} ; {comment}'

    ret = f'{name}{ttl2}IN\t{rr}{data}'

    return ret


def split_txt(data: str) -> str:
    """Splits TXT data to chunks of max 255 bytes to comply with bind.

    @param data     An unquoted string of arbitrary length
    @return A quoted string to be used as TXT record
    """
    items = split_txt_multiline(data)
    ret = ' '.join(items)

    return ret


def split_txt_multiline(data: str) -> list[str]:
    """Splits TXT data to chunks of max 255 bytes to comply with bind.

    @param data     An unquoted string of arbitrary length
    @return A list of quoted strings to be used as TXT record
    """
    limit = 255

    items = []
    data2 = data
    while len(data2) > limit:
        items.append(f'"{data2[:limit]}"')
        data2 = data2[limit:]
    items.append(f'"{data2}"')

    return items


def compact_spaces(st: str) -> str:
    """Replaces all spaces with a single space and strips leading and trailing spaces.

    Doesn't change spaces within quotes.
    """
    st = st.strip()
    ret = ''
    in_quotes = False
    added_space = False
    for x in st:
        if x == '"':
            in_quotes = not in_quotes
            added_space = False
            ret += x
        elif in_quotes:
            ret += x
        elif x in ('\t', '\n', '\r', ' '):
            if not added_space:
                ret += ' '
                added_space = True
        else:
            added_space = False
            ret += x

    return ret


def merge_quotes(st: str) -> str:
    st = compact_spaces(st)

    ret = ''
    in_quotes = False
    for x in st:
        if x == '"':
            if not in_quotes:
                if ret[-2:] == '" ':
                    ret = ret[:-2]
                else:
                    ret += x
            else:
                ret += x
            in_quotes = not in_quotes
        else:
            ret += x

    if in_quotes:
        abort(f'String ended with open quotes: {st}')

    return ret


def abort(reason: str) -> NoReturn:
    logging.error('%s', reason)
    raise AbortError(reason, excode=1, error_shown=True)


def _validate_value_type(value: Any, expected: Sequence[Type]) -> bool:
    """Implements strict type checking (no subclasses).

    It addresses the problem of ipaddress.IPv4Address being an instance of ipaddress.IPv4Network.

    May need to be relaxed and only check equality when comparing ipaddress classes.
    """

    for entry in expected:
        if get_origin(entry) is None:
            if type(value) == entry:  # pylint: disable=unidiomatic-typecheck
                return True
            continue
        if _validate_value_type(value, get_args(entry)):
            return True
    return False


def validate_dataclass(d: object) -> None:
    assert dc.is_dataclass(d)
    fields = dc.fields(d)
    for field in fields:
        value = getattr(d, field.name)
        isok = _validate_value_type(value, [field.type])
        if not isok:
            raise DataclassValidationError(field, value, d)


if __name__ == '__main__':
    pass

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
