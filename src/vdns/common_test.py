import datetime
import unittest
import parameterized

import vdns.common

from typing import Type, Union

AbortError = vdns.common.AbortError


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
        ('a b c', 'a b c'),
        ('abc', 'abc'),
        ('a   b\tc', 'a b c'),
        ('   a     b c   ', 'a b c'),
        ('\ta \t b c \t ', 'a b c'),
    ])
    def test_compact_spaces(self, line: str, result: str) -> None:
        self.assertEqual(vdns.common.compact_spaces(line), result)

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
