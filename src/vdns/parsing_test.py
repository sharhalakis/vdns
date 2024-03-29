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
import textwrap
import unittest
import ipaddress
import parameterized

import vdns.rr
import vdns.common
from vdns import parsing

from typing import Optional, Union


def td(seconds: Optional[int]) -> Optional[datetime.timedelta]:
    if seconds is None:
        return None
    return datetime.timedelta(seconds=seconds)


def ip(addr: str) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
    return ipaddress.ip_address(addr)


class FuncTest(unittest.TestCase):

    @parameterized.parameterized.expand([
        ('asdf', False),
        ('', False),
        ('100', True),
        ('1w', True),
        ('10.in-addr.arpa', False),
        ('20.', False),
        ('3._domainkey', False),
    ])
    def test_is_ttl(self, st: str, res: bool) -> None:
        self.assertEqual(parsing.is_ttl(st), res)

    @parameterized.parameterized.expand([
        ('', ''),
        ('h IN A 10.1.1.1', 'h IN A 10.1.1.1'),
        ('h IN A 10.1.1.1 ; comment', 'h IN A 10.1.1.1'),
        ('   h IN A 10.1.1.1   ', 'h IN A 10.1.1.1'),
    ])
    def test_cleanup_line(self, line: str, res: str) -> None:
        self.assertEqual(parsing.cleanup_line(line), res)

    @parameterized.parameterized.expand([
        ('abc', False, False),
        ('abc', True, True),
        ('(abc', False, True),
        ('abc)', True, False),
        ('(abc)', False, False),

        # Multiple parentheses
        ('(abc) (cde) (efg)', False, False),
        ('(abc) (cde) (efg', False, True),
        ('abc) (cde) (efg', True, True),

        # Quotes
        ('abc) "(cde) (efg"', True, False),
        ('abc "(")', True, False),

        # Invalid
        ('(abc)', True, None),
        ('abc)', False, None),
        ('abc"(', False, None),
    ])
    def test_line_ends_in_parentheses(self, line: str, in_perentheses: bool, expected: Optional[bool]) -> None:
        if expected is None:
            with self.assertRaises(vdns.common.AbortError):
                parsing.line_ends_in_parentheses(line, in_perentheses)
        else:
            res = parsing.line_ends_in_parentheses(line, in_perentheses)
            self.assertEqual(res, expected)

    @parameterized.parameterized.expand([
        ('', None, None, None, None),
        ('host1 IN A 10.1.1.1', 'host1', None, 'A', '10.1.1.1'),
        ('      IN MX mx', None, None, 'MX', 'mx'),
        ('      1800 IN NS ns1.', None, '1800', 'NS', 'ns1.'),
        ('      1D IN NS ns1.', None, '1D', 'NS', 'ns1.'),
        ('      IN TXT "ab cd ef"', None, None, 'TXT', '"ab cd ef"'),
        ('      1H IN TXT "ab cd ef"', None, '1H', 'TXT', '"ab cd ef"'),
        ('host2 1H IN TXT "ab cd ef"', 'host2', '1H', 'TXT', '"ab cd ef"'),
        ('host2 IN TXT "ab cd ef"', 'host2', None, 'TXT', '"ab cd ef"'),
    ])
    def test_parse_line(self, line: str, addr1: Optional[str], ttl: Optional[str], rr: str, addr2: str) -> None:
        r = parsing.parse_line(line)
        if addr1 is None and ttl is None and rr is None and addr2 is None:
            self.assertIsNone(r)
        else:
            self.assertEqual(r, parsing.ParsedLine(addr1=addr1, ttl=ttl, rr=rr, addr2=addr2))

    @parameterized.parameterized.expand([
        ('10', 10),
        ('2H', 7200),
        ('2h', 7200),
        ('1D', 86400),
        ('2W', 86400 * 14),
    ])
    def test_parse_ttl(self, st: str, seconds: int) -> None:
        self.assertEqual(parsing.parse_ttl(st), datetime.timedelta(seconds=seconds))

    @parameterized.parameterized.expand([
        ('''\
@               1D      IN      SOA     ns1.example.com. v13.v13.gr. (
                                2021010302      ; serial
                                1D              ; refresh (1 day)
                                1H              ; retry (1 hour)
                                90D             ; expire (12 weeks, 6 days)
                                1M              ; minimum (1 minute)
                                )''',
         '@ 1D IN SOA ns1.example.com. v13.v13.gr. 2021010302 1D 1H 90D 1M'),

        ('@ 1D IN SOA ns1.example.com. v13.v13.gr. (2021010302 1D 1H 90D 1M)',
         '@ 1D IN SOA ns1.example.com. v13.v13.gr. 2021010302 1D 1H 90D 1M'),

        ('@ 1D IN SOA ns1.example.com. v13.v13.gr. ((2021010302 1D 1H 90D 1M)', None),
        ('@ 1D IN SOA ns1.example.com. v13.v13.gr. (2021010302 1D 1H 90D 1M))', None),

        ('@ 1D IN SOA ns1.example.com. v13.v13.gr. (2021010302 1D 1H 90D) (1M)',
         '@ 1D IN SOA ns1.example.com. v13.v13.gr. 2021010302 1D 1H 90D 1M'),

        ('''@   IN  TXT  ("abcd" "bcde"
                          "cdef"
                          "ghi")''',
         '@ IN TXT "abcd" "bcde" "cdef" "ghi"'),

        ('''@   IN  TXT  ("abcd" "bcde"
                          "cdef"
                          "ghi")''',
         '@ IN TXT "abcdbcdecdefghi"', True),

        ('''@   IN  TXT  ("abcd " "bcde"
                          "cdef  "
                          "ghi ")''',
         '@ IN TXT "abcd bcdecdef  ghi "', True),

        ('''@   IN  TXT  ("abcd
                           cdef"''',
         None),

        # pylint: disable=line-too-long
        ('''IN      DNSKEY  256 3 8 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                                    bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
                                    cccccc''',
         'IN DNSKEY 256 3 8 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb cccccc'),
        # pylint: enable=line-too-long
    ])
    def test_merge_multiline(self, st: str, exp: Optional[str], merge_quotes: bool = False) -> None:
        lines = st.splitlines()
        if exp is None:
            with self.assertRaises(vdns.common.AbortError):
                parsing.merge_multiline(lines, merge_quotes)
        else:
            res = parsing.merge_multiline(lines, merge_quotes)
            self.assertEqual(res, exp)

    def test_parse_pub_key_line(self) -> None:
        # ; This is a zone-signing key, keyid 18688, for example.com.
        # ; Created: 20220619004748 (Sun Jun 19 01:47:48 2022)
        # ; Publish: 20220619004748 (Sun Jun 19 01:47:48 2022)
        # ; Activate: 20220619004748 (Sun Jun 19 01:47:48 2022)
        st = textwrap.dedent('''
        example.com. IN DNSKEY 256 3 8 ( AwEAAakscd0AGk+m8PuYVe6yVzpugNCAkaqNA/R+VnoLnUYRRMrDnP5J
                                         /MgbOUC+7X/zSX0iY9MKzlSKVg5qIh9D/P3NpDAzC7V4Oceurdr98nYj
                                         S/YQj8THgyBsmSjoJ232eeeYIS4P/uIFTDz7HAmsSUPCoiewr4X7e085
                                         LaAwHitgBQZ2uNXDs19SCeXnycz7SGeWMJyK3RwUIXUDkTekB+3F2mAU
                                         l5lviz2VUr12rQHtuId31+Z0T/X+tf6/G3mISyZQ99GOss/niSlLp8uX
                                         oeCbwX52IOeUK+ZYD1A9PXF3F2sCvT/EoU+M/c+7stYAjKhNKo7qqWgV
                                         VOuRnsR0+FM=0 )
        ''')
        dt = vdns.parsing.parse_line(st)
        assert dt is not None  # Should never happen with a valid st
        res = vdns.parsing.parse_pub_key_line(dt)
        self.assertEqual(res.zone, 'example.com.')
        self.assertEqual(res.flags, 256)
        self.assertEqual(res.keyid, 18688)
        self.assertEqual(res.ksk, False)
        self.assertEqual(res.sha1, 'C6931D9DA68E25BF01144904184B9D5D28D7E5C4')
        self.assertEqual(res.sha256, '47A3D29C73C2791D6FCD8DEFC908FA0759CDBA6039784BCAC438D2687E8EDD2E')
