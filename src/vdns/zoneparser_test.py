import unittest
import parameterized

from vdns import zoneparser

from typing import Optional
from unittest import mock

ZoneParser = zoneparser.ZoneParser
Data = zoneparser.Data
SOA = zoneparser.Data.SOA


class FuncTest(unittest.TestCase):

    @parameterized.parameterized.expand([
        ('asdf', False),
        ('', False),
        ('100', True),
        ('1w', True),
        ('10.in-addr.arpa', False),
        ('20.', False),
    ])
    def test_is_ttl(self, st: str, res: bool) -> None:
        self.assertEqual(zoneparser.is_ttl(st), res)

    @parameterized.parameterized.expand([
        ('', ''),
        ('h IN A 10.1.1.1', 'h IN A 10.1.1.1'),
        ('h IN A 10.1.1.1 ; comment', 'h IN A 10.1.1.1'),
        ('   h IN A 10.1.1.1   ', 'h IN A 10.1.1.1'),
    ])
    def test_cleanup_line(self, line: str, res: str) -> None:
        self.assertEqual(zoneparser.cleanup_line(line), res)

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
        r = zoneparser.parse_line(line)
        if addr1 is None and ttl is None and rr is None and addr2 is None:
            self.assertIsNone(r)
        else:
            self.assertEqual(r, zoneparser.ParsedLine(addr1=addr1, ttl=ttl, rr=rr, addr2=addr2))

    @parameterized.parameterized.expand([
        ('10', 10),
        ('2H', 7200),
        ('2h', 7200),
        ('1D', 86400),
        ('2W', 86400 * 14),
    ])
    def test_parse_ttl(self, st: str, seconds: int) -> None:
        self.assertEqual(zoneparser.parse_ttl(st), seconds)


class ZoneParserTest(unittest.TestCase):

    @parameterized.parameterized.expand([
        ('''
$ORIGIN         v13.gr.
$TTL            1D      ; 1 day
@               1D      IN      SOA     ns1.example.com. v13.v13.gr. (
                                2021010302      ; serial
                                1D              ; refresh (1 day)
                                1H              ; retry (1 hour)
                                90D             ; expire (12 weeks, 6 days)
                                1M              ; minimum (1 minute)
                                )

                 1H     IN      NS      ns1.dns.example.com
                 1H     IN      NS      ns2.dns.example.com
                 1H     IN      MX      1    aspmx.l.google.com.
                 1H     IN      MX      5    alt1.aspmx.l.google.com.
                 1H     IN      MX      5    alt2.aspmx.l.google.com.
                        IN      DNSKEY  256 3 8 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb cccccc
                        IN      DNSKEY  257 3 8 zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz yyyyyyyyyyyyyyyyy
                        IN      TXT     "v=spf1 include:_spf.google.com ~all"
                 1H     IN      A       192.168.1.1
                 1H     IN      A       192.168.1.2

sub              5M     IN      NS      ns1.example.com.
sub              5M     IN      NS      ns2.example.com.
sub                     IN      DS      15814 8 1 112233445566778899AABBCCDDEEFF1122334455
sub                     IN      DS      15814 8 2 112233445566778899AABBCCDDEEFF112233445566778899AABBCCDDEEFF00112233

host1                   IN      A       10.1.1.1
host2            1H     IN      A       10.1.1.2
host3            15M    IN      A       10.1.1.3
                        IN      SSHFP   1 1 1234567890abcdef1234567890abcdef12345678
                        IN      SSHFP   2 1 01234567890abcdef1234567890abcdef1234567
host3._domainkey.host3  IN      TXT     "v=DKIM1; g=*; k=rsa; s=email; t=s; h=sha256; p=ABFKJIOEWRLAJSHDFLLASJDHFhiewhasdFK2389ASDFJASDFWEwio"
host3            15M    IN      AAAA    2001:db8:2c1:3212::1
host3                   IN      AAAA    2001:db8:2c1:12::1
host4                   IN      AAAA    2001:db8:2c1:13::1

apps                    IN      CNAME   ghs.google.com.
www                     IN      CNAME   host1
ldap             1M     IN      CNAME   host2.v13.gr.
''',  # noqa: E501
         False,
         Data(
             domain='v13.gr',
             defttl=86400,
             soa=SOA(
                 name='@',
                 ttl=86400,
                 contact='v13.v13.gr.',
                 ns0='ns1.example.com.',
                 serial=2021010302,
                 refresh=86400,
                 retry=3600,
                 expire=90 * 86400,
                 minimum=60,
             ),
             a=[
                 (None, '192.168.1.1', 3600),
                 (None, '192.168.1.2', 3600),
                 ('host1', '10.1.1.1', None),
                 ('host2', '10.1.1.2', 3600),
                 ('host3', '10.1.1.3', 900),
             ],
             aaaa=[
                 ('host3', '2001:db8:2c1:3212::1', 900),
                 ('host3', '2001:db8:2c1:12::1', None),
                 ('host4', '2001:db8:2c1:13::1', None),
             ],
             cname=[
                 ('apps', 'ghs.google.com.', None),
                 ('www', 'host1', None),
                 ('ldap', 'host2.v13.gr.', 60)
             ],
             ns=[
                 ('ns1.dns.example.com', 3600),
                 ('ns2.dns.example.com', 3600),
                 # The "sub" NS entries are intentionally not parsed. See ZoneParser.add_entry()
             ],
             txt=[
                 (None, '"v=spf1 include:_spf.google.com ~all"', None),
                 ('host3._domainkey.host3',
                  '"v=DKIM1; g=*; k=rsa; s=email; t=s; h=sha256; p=ABFKJIOEWRLAJSHDFLLASJDHFhiewhasdFK2389ASDFJASDFWEwio"',
                  None),  # noqa: E501
             ],
             mx=[
                 (None, 1, 'aspmx.l.google.com.', 3600),
                 (None, 5, 'alt1.aspmx.l.google.com.', 3600),
                 (None, 5, 'alt2.aspmx.l.google.com.', 3600),
             ]
         )),
    ])
    def test_add_entry(self, contents: str, is_reverse: bool, res: Data) -> None:
        with mock.patch.object(ZoneParser, '_read_file', return_value=contents.splitlines()):
            zp = ZoneParser(fn='somefile', is_reverse=is_reverse)
        dt = zp.data()
        print(dt)
        self.assertEqual(dt.soa, res.soa)
        self.assertEqual(dt.defttl, res.defttl)
        self.assertCountEqual(dt.a, res.a)
        self.assertCountEqual(dt.aaaa, res.aaaa)
        self.assertCountEqual(dt.cname, res.cname)
        self.assertCountEqual(dt.ns, res.ns)
        self.assertCountEqual(dt.txt, res.txt)
        self.assertCountEqual(dt.mx, res.mx)
