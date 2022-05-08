import re
import datetime
import unittest
import ipaddress
# import parameterized

from vdns import rr

# from typing import Type, Union

# pylint: disable=protected-access

# Just a datetime so that we don't repeat this
a_time = datetime.datetime(year=2000, month=10, day=13, hour=12, minute=0, second=0)


def clean(st: str) -> str:
    ret = st.removesuffix('\n')
    ret = re.sub(r'\s+', ' ', ret)
    ret = ret.removeprefix(' ')
    return ret


class StringRecordTest(unittest.TestCase):

    def test_constructor(self):
        s = rr._StringRecord('data')
        self.assertEqual(s.st, 'data')
        self.assertIsNone(s.hostname)
        self.assertEqual(s.autodot, 0)

    def test_needsdot(self):
        s = rr._StringRecord('data')
        self.assertEqual(s.needsdot, False)

        s = rr._StringRecord('data', needsdot=True)
        self.assertEqual(s.needsdot, True)

        s = rr._StringRecord('data')
        s.needsdot = True
        self.assertEqual(s.needsdot, True)

        s = rr._StringRecord('data', needsdot=True)
        s.needsdot = False
        self.assertEqual(s.needsdot, False)

    def test_autodot(self):
        s = rr._StringRecord('data')
        self.assertEqual(s.needsdot, False)

        s = rr._StringRecord('data', autodot=1)
        self.assertEqual(s.needsdot, False)

        s = rr._StringRecord('data.some.domain', autodot=1)
        self.assertEqual(s.needsdot, True)

        s = rr._StringRecord('data.some.domain')
        self.assertEqual(s.needsdot, False)


class SimpleRRTest(unittest.TestCase):

    def test_mx(self):
        mx = rr.MX(hostname='mail', domain='dom.com', ttl=datetime.timedelta(seconds=3600),
                   priority=10, mx='mx1')
        rec = clean(mx.record())
        self.assertEqual(rec, 'mail 1H IN MX 10 mx1')

        mx.mx = 'mx1.google.com'
        mx.ttl = None
        rec = clean(mx.record())
        self.assertEqual(rec, 'mail IN MX 10 mx1.google.com.')

    def test_ns(self):
        ns = rr.NS(hostname='sub', domain='dom.com', ttl=datetime.timedelta(seconds=3600),
                   ns='srv1')
        rec = clean(ns.record())
        self.assertEqual(rec, 'sub 1H IN NS srv1')

        ns.ns = 'ns1.google.com'
        ns.ttl = None
        rec = clean(ns.record())
        self.assertEqual(rec, 'sub IN NS ns1.google.com.')

    def test_host(self):
        host = rr.Host(hostname='srv1', domain='dom.com', ttl=datetime.timedelta(seconds=3600),
                       ip=ipaddress.IPv4Address('10.1.1.2'), reverse=False)
        rec = clean(host.record())
        self.assertEqual(rec, 'srv1 1H IN A 10.1.1.2.')

    def test_ptr(self):
        ptr = rr.PTR(hostname='srv1', domain='dom.com', ttl=datetime.timedelta(seconds=3600),
                     ip=ipaddress.IPv4Address('10.1.1.2'), reverse=True, net_domain='1.10.in-addr.arpa')
        rec = clean(ptr.record())
        self.assertEqual(rec, '2.1 1H IN PTR srv1.dom.com.')

        ptr.reverse = False
        with self.assertRaises(rr.BadRecordError):
            ptr.record()

    def test_cname(self):
        ptr = rr.CNAME(hostname='ns1', domain='dom.com', ttl=datetime.timedelta(seconds=3600),
                       hostname0='srv1')
        rec = clean(ptr.record())
        self.assertEqual(rec, 'ns1 1H IN CNAME srv1')

        ptr.hostname0 = 'some.host.com'
        rec = clean(ptr.record())
        self.assertEqual(rec, 'ns1 1H IN CNAME some.host.com.')

    def test_txt(self):
        txt = rr.TXT(hostname='ns1', domain='dom.com', ttl=datetime.timedelta(seconds=3600),
                     txt='ho ho ho')
        rec = clean(txt.record())
        self.assertEqual(rec, 'ns1 1H IN TXT "ho ho ho"')

    def test_dnssec(self):
        created = a_time
        dt = dict(domain='dom.com', keyid=10, ksk=False, algorithm=8,
                  digest_sha1='digest_sha1', digest_sha256='digest_sha256',
                  key_pub='AwEpubkey', st_key_pub='pubkey', st_key_priv='privkey',
                  ts_created=created, ts_activate=created, ts_publish=created)

        dnssec = rr.DNSKEY(**dt)
        rec = clean(dnssec.record())
        self.assertEqual(rec, 'IN DNSKEY 256 3 8 AwEpubkey')

        dnssec.ksk = True
        rec = clean(dnssec.record())
        self.assertEqual(rec, 'IN DNSKEY 257 3 8 AwEpubkey')

        ds = rr.DS(**dt)
        ds.hostname = 'sub'
        reclines = [clean(x) for x in ds.record().splitlines()]
        self.assertIn('sub IN DS 10 8 1 digest_sha1', reclines)
        self.assertIn('sub IN DS 10 8 2 digest_sha256', reclines)

    def test_dkim(self):
        pubkey = 'pubkey'
        dkim = rr.DKIM(domain='dom.com', selector='google', k='rsa',
                       key_pub=pubkey, g='*', t=False, subdomains=False)
        rec = clean(dkim.record())
        self.assertEqual(rec, f'google._domainkey IN TXT "v=DKIM1; g=*; k=rsa; s=email; t=s; p={pubkey}"')

        maxdiff = self.maxDiff
        self.maxDiff = 5000  # So that the output is fully shown if the test fails
        # pylint: disable=line-too-long
        pubkey = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArgfNQ7zQSn5ALRG1usOotYIqHkbFVE1lo+9oATcHVz4YXlyGNAU1fvmaS5V4KAdOAMIHrWQllWR54NybF/gFqxgfCfTa+dZkO3bMTIVo0mwTWAmqEY+8C3vwWWiaGtBVbcNW1m5V1cHcg4PnFhH/sJLSqQ3BfnLTwIEwRQF6bsCt493+QSTquX5eoc/FdVCK/Y+y+Imi4zKSm/Txk0OPllsvS5KAxRUimX34iG2dSfHlYwEDJAGQuh2crIEp1KQXMGmi0iu1KbIlaQ3nPVHn5PJ2Wka6F2AjL1GzRyN2a+frIAYufesTWV+CDyyTSvfk/HbVrrIpj6W0l7TTJ10gjQIDAQAB'  # noqa: E501
        txt = '"v=DKIM1; g=*; k=rsa; s=email; t=s; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArgfNQ7zQSn5ALRG1usOotYIqHkbFVE1lo+9oATcHVz4YXlyGNAU1fvmaS5V4KAdOAMIHrWQllWR54NybF/gFqxgfCfTa+dZkO3bMTIVo0mwTWAmqEY+8C3vwWWiaGtBVbcNW1m5V1cHcg4PnFhH/sJLSqQ3BfnLTwIEwRQF6bsCt49" "3+QSTquX5eoc/FdVCK/Y+y+Imi4zKSm/Txk0OPllsvS5KAxRUimX34iG2dSfHlYwEDJAGQuh2crIEp1KQXMGmi0iu1KbIlaQ3nPVHn5PJ2Wka6F2AjL1GzRyN2a+frIAYufesTWV+CDyyTSvfk/HbVrrIpj6W0l7TTJ10gjQIDAQAB"'  # noqa: E501
        # pylint: enable=line-too-long
        dkim.key_pub = pubkey
        rec = clean(dkim.record())
        self.assertEqual(rec, f'google._domainkey IN TXT {txt}')
        self.maxDiff = maxdiff

    def test_srv(self):
        srv = rr.SRV(domain='dom.com', protocol='tcp', service='xmpp-client',
                     priority=5, weight=0, port=5222, target='targethost')
        rec = clean(srv.record())
        self.assertEqual(rec, '_xmpp-client._tcp IN SRV 5 0 5222 targethost')

    def test_soa(self):
        soa = rr.SOA(name='dom.com', ttl=datetime.timedelta(days=1),
                     refresh=datetime.timedelta(hours=24), retry=datetime.timedelta(hours=1),
                     expire=datetime.timedelta(days=30), minimum=datetime.timedelta(minutes=1),
                     contact='v13@v13.gr', serial=2022050801, ns0='ns1.dom.com',
                     ts=a_time, reverse=False, updated=a_time)

        rec = soa.record()
        lines = [clean(x) for x in rec.splitlines()]

        # $ORIGIN         dom.com.
        # $TTL            1D      ; 1 day
        # @               1D      IN      SOA     ns1.dom.com. v13@v13.gr. (
        #                                 2022050801      ; serial
        #                                 1D              ; refresh (1 day)
        #                                 1H              ; retry (1 hour)
        #                                 30D             ; expire (4 weeks, 2 days)
        #                                 1M              ; minimum (1 minute)
        #                                 )

        self.assertIn('$ORIGIN dom.com.', lines)
        self.assertIn('$TTL 1D ; 1 day', lines)
        self.assertIn('@ 1D IN SOA ns1.dom.com. v13@v13.gr. (', lines)
        self.assertIn('2022050801 ; serial', lines)
        self.assertIn('1D ; refresh (1 day)', lines)
        self.assertIn('1H ; retry (1 hour)', lines)
        self.assertIn('30D ; expire (4 weeks, 2 days)', lines)
        self.assertIn('1M ; minimum (1 minute)', lines)
        self.assertIn(')', lines)
