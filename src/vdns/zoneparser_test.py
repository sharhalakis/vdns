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
import ipaddress
import unittest
import parameterized

import vdns.rr
import vdns.src.src0
from vdns import zoneparser

from typing import Union
from unittest import mock

ZoneParser = zoneparser.ZoneParser


def td(seconds: int) -> datetime.timedelta:
    return datetime.timedelta(seconds=seconds)


def ip(addr: str) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
    return ipaddress.ip_address(addr)


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

                 1H     IN      NS      ns1.dns.example.com.
                 1H     IN      NS      ns2.dns.example.com.
                 1H     IN      MX      1    aspmx.l.google.com.
                 1H     IN      MX      5    alt1.aspmx.l.google.com.
                 1H     IN      MX      5    alt2.aspmx.l.google.com.
                        IN      DNSKEY  256 3 8 AwEAAbX1gMNEWxK6RL5VnwaKCRJNTis329C5tbJ0qRGhOfqRyfoPbwNi MnZX0Jhsxpsalz+PvzKgA5WADmCW7tCjHlFvSdFckUR0FA+VWyzijD2I ANjNjrmhLclQWbwzvDR29fs+hYvN3QcgPFUzrQrZOkSFzJy+q08fqXYO BZTsoTzTab/yxcO2BCpq0h+xNth3h/dLR923ZmHnpPUZDRcXSqUPDF0H Q8j5A93iTa65l3r/40ylS7ShGW9wv2K1mWbGrw8rP8PysVDu7PGytYy8 cR8g0vke4dmCNBgWCbXzfRlQipZGY3IrcEo+m9YUgra9lAt6BZF6161+ Uho2N4yasd0=
                        IN      DNSKEY  257 3 8 ( AwEAAeDje/m8q6RwX8MoYm3gzdAw0UQiaLWS16jMdbIm/AURyEHrU3pr
                                                  5wm7ZyaWzFeQP+F8bvpep4rQkxuOm/IlEIjoCrHViBhVe1PRBHxVbZEI
                                                  zNoJsoGm3OtXdEqAzYAIWn7to1vUAL2m8LrFuSVlXbNjs5KW0U/gjKZO
                                                  agnFhp4F4zjNYJdca5MAQDW/LiMPRogJNNQdPAk7jYC7ZLSjUW0BlfHo
                                                  UIfvv34ebOPlHwncskiJIGXAKHoWYaO3LAb7GMjQIftDQP5zOJrN2ziK
                                                  wO8r8RfMb3fO8sAzJenExOUstokJLr43mrrKgBrWDOs0u2xc7cJVXHEl
                                                  P6s+LwKAypc= )
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
''',
         False,
         vdns.src.src0.DomainData(
             name='v13.gr',
             soa=vdns.rr.SOA(
                 name='v13.gr',
                 ttl=td(86400),
                 contact='v13.v13.gr',
                 ns0='ns1.example.com',
                 serial=2021010302,
                 refresh=td(86400),
                 retry=td(3600),
                 expire=td(90 * 86400),
                 minimum=td(60),
             ),
             # pylint: disable=unexpected-keyword-arg
             hosts=[
                 vdns.rr.Host(domain='v13.gr', hostname=None, ip=ip('192.168.1.1'), ttl=td(3600), reverse=False),
                 vdns.rr.Host(domain='v13.gr', hostname=None, ip=ip('192.168.1.2'), ttl=td(3600), reverse=False),
                 vdns.rr.Host(domain='v13.gr', hostname='host1', ip=ip('10.1.1.1'), reverse=False),
                 vdns.rr.Host(domain='v13.gr', hostname='host2', ip=ip('10.1.1.2'), ttl=td(3600), reverse=False),
                 vdns.rr.Host(domain='v13.gr', hostname='host3', ip=ip('10.1.1.3'), ttl=td(900), reverse=False),
                 vdns.rr.Host(domain='v13.gr', hostname='host3', ip=ip('2001:db8:2c1:3212::1'), ttl=td(900), reverse=False),
                 vdns.rr.Host(domain='v13.gr', hostname='host3', ip=ip('2001:db8:2c1:12::1'), reverse=False),
                 vdns.rr.Host(domain='v13.gr', hostname='host4', ip=ip('2001:db8:2c1:13::1'), reverse=False),
             ],
             cnames=[
                 vdns.rr.CNAME(domain='v13.gr', hostname='apps', hostname0='ghs.google.com.'),
                 vdns.rr.CNAME(domain='v13.gr', hostname='www', hostname0='host1'),
                 vdns.rr.CNAME(domain='v13.gr', hostname='ldap', hostname0='host2.v13.gr.', ttl=td(60)),
             ],
             ns=[
                 vdns.rr.NS(domain='v13.gr', ns='ns1.dns.example.com.', ttl=td(3600)),
                 vdns.rr.NS(domain='v13.gr', ns='ns2.dns.example.com.', ttl=td(3600)),
                 vdns.rr.NS(domain='v13.gr', hostname='sub', ns='ns1.example.com.', ttl=td(300)),
                 vdns.rr.NS(domain='v13.gr', hostname='sub', ns='ns2.example.com.', ttl=td(300)),
             ],
             txt=[
                 vdns.rr.TXT(domain='v13.gr', txt='v=spf1 include:_spf.google.com ~all'),
             ],
             dkim=[
                 vdns.rr.DKIM(domain='v13.gr', hostname='host3', selector='host3',
                              g='*', k='rsa', subdomains=False, h='sha256', t=False,
                              key_pub='ABFKJIOEWRLAJSHDFLLASJDHFhiewhasdFK2389ASDFJASDFWEwio'),
             ],
             mx=[
                 vdns.rr.MX(domain='v13.gr', priority=1, mx='aspmx.l.google.com.', ttl=td(3600)),
                 vdns.rr.MX(domain='v13.gr', priority=5, mx='alt1.aspmx.l.google.com.', ttl=td(3600)),
                 vdns.rr.MX(domain='v13.gr', priority=5, mx='alt2.aspmx.l.google.com.', ttl=td(3600)),
             ],
             sshfp=[
                 vdns.rr.SSHFP(domain='v13.gr', hostname='host3',
                               hashtype=1, keytype=1, fingerprint='1234567890abcdef1234567890abcdef12345678'),
                 vdns.rr.SSHFP(domain='v13.gr', hostname='host3',
                               hashtype=1, keytype=2, fingerprint='01234567890abcdef1234567890abcdef1234567'),
             ],
             # pylint: enable=unexpected-keyword-arg
         )),
    ])
    def test_add_entry(self, contents: str, is_reverse: bool, res: vdns.src.src0.DomainData) -> None:
        with mock.patch.object(ZoneParser, '_read_file', return_value=contents.splitlines()):
            zp = ZoneParser(fn='somefile', is_reverse=is_reverse)
        dt = zp.data()
        print(dt)
        self.maxDiff = 8192
        self.assertEqual(dt.soa, res.soa)
        self.assertCountEqual(dt.hosts, res.hosts)
        self.assertCountEqual(dt.cnames, res.cnames)
        self.assertCountEqual(dt.ns, res.ns)
        self.assertCountEqual(dt.txt, res.txt)
        self.assertCountEqual(dt.mx, res.mx)
        self.assertCountEqual(dt.dkim, res.dkim)
        self.assertCountEqual(dt.sshfp, res.sshfp)
