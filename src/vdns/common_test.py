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

import datetime
import unittest
import ipaddress
import dataclasses as dc
import parameterized
from parameterized import param

import vdns.common

from typing import Optional, Sequence, Type, Union

AbortError = vdns.common.AbortError

# Helpers
td_1h = datetime.timedelta(hours=1)
td_1d = datetime.timedelta(days=1)


@dc.dataclass
class DCTest1:
    st: str
    ost: Optional[str] = None
    onum: Optional[int] = None
    ip: Optional[ipaddress.IPv4Address] = None
    net: Optional[ipaddress.IPv4Network] = None
    iface: Optional[ipaddress.IPv4Interface] = None
    uniopt: Union[Optional[str], int] = None


class CommonTest(unittest.TestCase):

    @parameterized.parameterized.expand([
        ('10.0.0.0', '0.0.0.10.in-addr.arpa'),
        ('10.0.0.0/32', '0.0.0.10.in-addr.arpa'),
        ('10.0.0.0/24', '0.0.10.in-addr.arpa'),
        ('10.0.0.0/16', '0.10.in-addr.arpa'),
        ('10.0.0.0/8', '10.in-addr.arpa'),
        ('10.0.0.0/31', AbortError),
        ('10.0.0.0/15', AbortError),
        ('2001:4860:4860::8888', '8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa'),
        ('2001:4860:4860::8888/128', '8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa'),
        ('2001:4860:4860::/64', '0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa'),
        ('2001:4860::/32', '0.6.8.4.1.0.0.2.ip6.arpa'),
        ('2001::/16', '1.0.0.2.ip6.arpa'),
        ('2001:4860:4860::8888/127', AbortError),
        ('10.0.0.0.0', ValueError),
        ('', ValueError),
        ('something something', ValueError),
    ])
    def test_reverse_name(self, st: str, result: Union[str, Type]) -> None:

        if isinstance(result, str):
            r = vdns.common.reverse_name(st)
            self.assertEqual(r, result)
        elif issubclass(result, Exception):
            with self.assertRaises(result):
                _ = vdns.common.reverse_name(st)
        else:
            raise Exception('Error... error... error...')

    @parameterized.parameterized.expand([
        (datetime.timedelta(seconds=1000), ('1000', '16 minutes, 40 seconds')),
        (datetime.timedelta(seconds=1200), ('20M', '20 minutes')),
        (datetime.timedelta(seconds=7200), ('2H', '2 hours')),
        (datetime.timedelta(100), ('100D', '14 weeks, 2 days')),
        (datetime.timedelta(100, 1), ('8640001', '14 weeks, 2 days, 1 second')),
        (datetime.timedelta(14), ('2W', '2 weeks')),
    ])
    def test_fmttd(self, dt: datetime.timedelta, output: str) -> None:
        self.assertEqual(vdns.common.zone_fmttd(dt), vdns.common.FmttdReturn(value=output[0], human_readable=output[1]))

    def test_fmttd_invalid(self) -> None:
        with self.assertRaises(ValueError):
            vdns.common.zone_fmttd(datetime.timedelta(0))

    @parameterized.parameterized.expand([
        param('host', 'A', '10.1.1.1', 'host IN A 10.1.1.1'),
        param('host', 'A', '10.1.1.1', 'host 1D IN A 10.1.1.1', ttl=td_1d),
        param('host', 'A', '10.1.1.1', 'host IN A 10.1.1.1 ; comment', comment='comment'),

        # multiline_data
        param('host', 'TXT', 'some text', 'host IN TXT some text ( line1\nline2 )', multiline_data=('line1', 'line2')),
        param('host', 'TXT', '', 'host IN TXT ( line1\nline2 )', multiline_data=('line1', 'line2')),
        param('host', 'TXT', 'some text', 'host IN TXT some text line1', multiline_data=('line1',)),

        # comment with multiline data
        param('host', 'TXT', '', 'host IN TXT line1 ; comment', multiline_data=('line1',), comment='comment'),
        param('host', 'TXT', 'some text', 'host IN TXT some text line1 ; comment',
              multiline_data=('line1',), comment='comment'),
        param('host', 'TXT', 'some text', 'host IN TXT some text ( line1\nline2 ) ; comment',
              multiline_data=('line1', 'line2'), comment='comment'),

        # tabulation works ok
        param('host', 'A', '10.1.1.1', 'host\t\t\t\tIN\tA\t10.1.1.1', ignorespaces=False),
        param('host', 'A', '10.1.1.1', 'host\t\t\t1D\tIN\tA\t10.1.1.1', ttl=td_1d, ignorespaces=False),
        # ttl's tab is skipped for hostnames > 24 characters
        param('very-very-very-long-hostname', 'A', '10.1.1.1', 'very-very-very-long-hostname\tIN\tA\t10.1.1.1',
              ignorespaces=False),
    ])
    def test_fmtrecord(self, name: str, rr: str, data: str, expected: str,
                       ttl: Optional[datetime.timedelta] = None, multiline_data: Sequence[str] = (),
                       comment: Optional[str] = None, ignorespaces: bool = True) -> None:
        res = vdns.common.fmtrecord(name=name, ttl=ttl, rr=rr, data=data, multiline_data=multiline_data,
                                    comment=comment)
        if ignorespaces:
            res = vdns.common.compact_spaces(res)
            expected = vdns.common.compact_spaces(expected)
        self.assertEqual(res, expected)

    @parameterized.parameterized.expand([
        ('a b c', 'a b c'),
        ('abc', 'abc'),
        ('a   b\tc', 'a b c'),
        ('   a     b c   ', 'a b c'),
        ('\ta \t b c \t ', 'a b c'),
        # Handle quotes
        ('  "a b c " ', '"a b c "'),
        # Preserve spaces in quotes
        (' "  a  b  c" ', '"  a  b  c"'),
    ])
    def test_compact_spaces(self, line: str, result: str) -> None:
        self.assertEqual(vdns.common.compact_spaces(line), result)

    @parameterized.parameterized.expand([
        # Simple case
        ('"ab" "cd" "ef"', '"abcdef"'),
        # Preserve spaces in quotes
        ('"ab "  "cd"  "   ef"', '"ab cd   ef"'),
        ('"ab "  " cd "  "   ef"', '"ab  cd    ef"'),
        # Unterminated strings
        ('"ab "  "cd"  "   ef', None),
        ('"ab', None),
    ])
    def test_merge_quotes(self, line: str, result: Optional[str]) -> None:
        if result is None:
            with self.assertRaises(vdns.common.AbortError):
                vdns.common.merge_quotes(line)
        else:
            self.assertEqual(vdns.common.merge_quotes(line), result)

    @parameterized.parameterized.expand([
        ('test', 8, 'test\t'),
        ('test', 24, 'test\t\t\t'),
        ('', 8, '\t'),
        ('', 16, '\t\t'),
        ('12345678', 8, '12345678\t'),
        ('12345678', 16, '12345678\t'),
    ])
    def test_tabify(self, st: str, width: int, out: str) -> None:
        self.assertEqual(vdns.common.tabify(st, width), out)

    def test_tabify_bad(self) -> None:
        with self.assertRaises(Exception):
            vdns.common.tabify('test', 15)

    @parameterized.parameterized.expand([
        ({'st': 'a'}, False),
        # ipaddress stuff
        ({'st': 'a', 'ip': ipaddress.ip_address('1.1.1.1')}, False),
        ({'st': 'a', 'net': ipaddress.ip_address('1.1.1.1')}, True),
        ({'st': 'a', 'iface': ipaddress.ip_address('1.1.1.1')}, True),
        ({'st': 'a', 'ip': ipaddress.ip_network('1.1.1.0/24')}, True),
        ({'st': 'a', 'net': ipaddress.ip_network('1.1.1.0/24')}, False),
        ({'st': 'a', 'iface': ipaddress.ip_network('1.1.1.0/24')}, True),
        ({'st': 'a', 'ip': ipaddress.ip_interface('1.1.1.1/32')}, True),
        ({'st': 'a', 'net': ipaddress.ip_interface('1.1.1.1/32')}, True),
        ({'st': 'a', 'iface': ipaddress.ip_interface('1.1.1.1/32')}, False),
        # wrong type on required field
        ({'st': 1}, True),
        ({'st': b'1'}, True),
        ({'st': None}, True),
        # wrong type on optional field
        ({'st': 'a', 'ost': 'b'}, False),
        ({'st': 'a', 'ost': None}, False),
        ({'st': 'a', 'ost': 1}, True),
        # Union of optional
        ({'st': 'a', 'uniopt': None}, False),
        ({'st': 'a', 'uniopt': 1}, False),
        ({'st': 'a', 'uniopt': 'aa'}, False),
        ({'st': 'a', 'uniopt': b'bytes'}, True),
    ])
    def test_validate_dataclass(self, dt: dict, fail: bool) -> None:
        if fail:
            with self.assertRaises(vdns.common.DataclassValidationError):
                d1 = DCTest1(**dt)
                vdns.common.validate_dataclass(d1)
        else:
            d1 = DCTest1(**dt)
            vdns.common.validate_dataclass(d1)
