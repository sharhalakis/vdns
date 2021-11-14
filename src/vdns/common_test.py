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
    def test_reverse_name(self, st: str, result: Union[str, Type]):

        if isinstance(result, str):
            r = vdns.common.reverse_name(st)
            self.assertEqual(r, result)
        elif issubclass(result, Exception):
            with self.assertRaises(result):
                r = vdns.common.reverse_name(st)
        else:
            raise Exception('Error... error... error...')
