import datetime
import textwrap
import unittest
import parameterized

import vdns.rr
import vdns.common
import vdns.zoneparser
from vdns import keyparser

from typing import Iterable

# pylint: disable=protected-access

_DEFAULT_IGNORED_FIELDS = ('st_key_pub', 'set_key_priv', 'ttl')


class KeyparserTest(unittest.TestCase):

    def assertDNSSECEqual(self, result: vdns.rr.DNSSEC, expected: vdns.rr.DNSSEC,
                          ignored: Iterable[str] = _DEFAULT_IGNORED_FIELDS) -> None:
        # Scan each item separately to have a readable error output
        for k in set(result.rrfields) | set(expected.rrfields):
            if k in ignored:
                continue
            self.assertEqual(getattr(result, k), getattr(expected, k), f'{k} differs')

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
        dt = vdns.zoneparser.parse_line(st)
        assert dt is not None  # Should never happen with a valid st
        res = keyparser.parse_pub_key_line(dt)
        self.assertEqual(res.zone, 'example.com.')
        self.assertEqual(res.flags, 256)
        self.assertEqual(res.keyid, 18688)
        self.assertEqual(res.ksk, False)
        self.assertEqual(res.sha1, 'C6931D9DA68E25BF01144904184B9D5D28D7E5C4')
        self.assertEqual(res.sha256, '47A3D29C73C2791D6FCD8DEFC908FA0759CDBA6039784BCAC438D2687E8EDD2E')

    def test_parse_ts(self) -> None:
        st = '20220102102030'
        dt = datetime.datetime(year=2022, month=1, day=2, hour=10, minute=20, second=30, tzinfo=datetime.timezone.utc)
        res = keyparser.parse_ts(st)
        self.assertEqual(res, dt)

        # Missing day
        with self.assertRaises(vdns.common.AbortError):
            keyparser.parse_ts(st[:-2])

        # Extra numbers
        with self.assertRaises(vdns.common.AbortError):
            keyparser.parse_ts(st + '00')

        # Bogus string
        with self.assertRaises(vdns.common.AbortError):
            keyparser.parse_ts('abcd')

        # Invalid month
        with self.assertRaises(ValueError):
            keyparser.parse_ts('20223001000000')

    # pylint: disable=line-too-long,unexpected-keyword-arg
    @parameterized.parameterized.expand([
        # dnssec-keygen -a RSASHA256 test2.example.com
        ('''
         ; This is a zone-signing key, keyid 52396, for test2.example.com.
         ; Created: 20220619004301 (Sun Jun 19 01:43:01 2022)
         ; Publish: 20220619004301 (Sun Jun 19 01:43:01 2022)
         ; Activate: 20220619004301 (Sun Jun 19 01:43:01 2022)
         test2.example.com. IN DNSKEY 256 3 8 ( AwEAAcivnbSxgMkTvzCTA/Py2qqo3EANPUwqL4HalAfNmuDGuFaOu+xT
                                                KlXjiLyfUMKcuy+jKPamGn//z+B5Zsy4j6a1KAaT5u9fli8BH5C1r2Pg
                                                qXKvT6YTwk2M5djuLXdeoe9d5rFzcd7tu01ifFsrh3s7pARkOpjV26Fq
                                                NkxPTiKLidsdAjviHRI5SGAyEx6ouKN1b54HO0uZXPB2xewzjNtWNL37
                                                PW0l/lAeCba78CUu4X4510J2J/BzQ3e7ST6UOQE3gU7pvsM4agZIoiC/
                                                UQ+DFODNrdtfU8UAceMl7L6AZgCN8x7H6KOr3phuAzbg3/u+eNyxEu7c
                                                9baFjzcc63c= )
         ''', '''
         Private-key-format: v1.3
         Algorithm: 8 (RSASHA256)
         Modulus: yK+dtLGAyRO/MJMD8/LaqqjcQA09TCovgdqUB82a4Ma4Vo677FMqVeOIvJ9Qwpy7L6Mo9qYaf//P4HlmzLiPprUoBpPm71+WLwEfkLWvY+Cpcq9PphPCTYzl2O4td16h713msXNx3u27TWJ8WyuHezukBGQ6mNXboWo2TE9OIouJ2x0CO+IdEjlIYDITHqi4o3Vvngc7S5lc8HbF7DOM21Y0vfs9bSX+UB4JtrvwJS7hfjnXQnYn8HNDd7tJPpQ5ATeBTum+wzhqBkiiIL9RD4MU4M2t219TxQBx4yXsvoBmAI3zHsfoo6vemG4DNuDf+7543LES7tz1toWPNxzrdw==
         PublicExponent: AQAB
         PrivateExponent: t+SceVfxr89lcUg15hMSJjGHaTX4hlNdpvq4jJHtqqzNe5tdPgdTEtLlmBnQchQWPmefAKxiOgoZ3RLBjTRNhbAYVjau9Ye8YaQA3aRua/IQs2NLc95FPLSwZWCSzwArGOENpGsp2+IxsI5fb1dq1RRojhGd1DCbCcT+rlw5N9LPoMJNGwbRiHoqHOKUN3IEuT8TRvOYw1QkD/kSaJELiNd7Y21r+m4QjNChtgTsRzbodmxqNchLi1uVZiFRSOaa50+PQIt8/LsxUz1pQrqbFLHxEAKMek7Th0nsebTRTZjlTQXOVe7nGA5IOcgyg2Gw6YVJSJApsDAzgfm3T9eBGQ==
         Prime1: 7IRo13gacaaOk1qGArUpNblNu5TvOn0S9v6dUOEzNkGyyDzPPTbrXvqhDTPMX/WdvO6kARgfYFeJUpMXagm8DZM7cdNgeNWArhbDOr+mg3pwpjZpKEexTLyTYuSq7IgVPTTOXvwvltEftGx/eSedspadXmqGiO3epsuE7YS+B50=
         Prime2: 2TecSFf4tSfhJFBB1QnOyJhMuoTvkzQfhRw9OXmIOwlmFpcoDlBrig3WLCwUq6auHn9kHIT7sEj1VAcyR+cAAvU/rjPlH6WUg4gF9CgfsD5mCqZNS6Cq5RqfVhND33naQnAF5vbkBjy0dwo7VHbF91T/Zbq8Y48+G6+ItwnqFSM=
         Exponent1: l97F+2VxhXyvnErKNj7hgU/FbCfMHUBmxxbjKSYR3kr9Y7o4UFRNeqVweKvEFfH/IWwS/2jf7NsIoG823630hLr/tq1GCxD9Gcwf/D9HyrD6WKAjkevHG0ETWrL+Vfdju/OGeFNys2MA+reYetFHX396+T9pt88V4wBYELPl2bk=
         Exponent2: b5EVjz7H+lviUqF6Pq7L69H1zvNKjgP+kILhm2yloRUBv2ah50A9C+pxb7ywXT2+PuHVjKRtFa1TfHY5yB6IrfxDWflDnM6SCkDKNg6JwB88kAm8t7RtMkFLR42blePjS654CZoTonR5iI7TzF047wFUMG8KJeTD1LqC8OiBt5s=
         Coefficient: w0DxreD+qChic3PPqLlYQZF80bxuOYshzP7wBkB+re5QyUqrtFN9F1IUAwlc6QTCEWQXY6NswDbSlCxxrN4+9Q+qcX6UlcCu+HkZMBNFiPvjPGtUYbsmlukxqQ1Gf9aJlBLFKYZUbuzY78L2OdRr+yCnvNGuXPlqGoJOEi0OQog=
         Created: 20220619004301
         Publish: 20220619004301
         Activate: 20220619004301
         ''',
         vdns.rr.DNSSEC(
             domain='test2.example.com',
             ksk=False,
             keyid=52396,
             algorithm=8,
             # dnssec-dsfromkey -1 Ktest2.example.com.+008+52396.key
             digest_sha1='1DCE328AA7CD9D3B26E7C31861B860B2C0310A2D',
             # dnssec-dsfromkey -2 Ktest2.example.com.+008+52396.key
             digest_sha256='79474CCB104B61AE55532BE9DE3D443C5A38FD2E3D9F125DCD97C0AA58F9A653',
             key_pub='AwEAAcivnbSxgMkTvzCTA/Py2qqo3EANPUwqL4HalAfNmuDGuFaOu+xT KlXjiLyfUMKcuy+jKPamGn//z+B5Zsy4j6a1KAaT5u9fli8BH5C1r2Pg qXKvT6YTwk2M5djuLXdeoe9d5rFzcd7tu01ifFsrh3s7pARkOpjV26Fq NkxPTiKLidsdAjviHRI5SGAyEx6ouKN1b54HO0uZXPB2xewzjNtWNL37 PW0l/lAeCba78CUu4X4510J2J/BzQ3e7ST6UOQE3gU7pvsM4agZIoiC/ UQ+DFODNrdtfU8UAceMl7L6AZgCN8x7H6KOr3phuAzbg3/u+eNyxEu7c 9baFjzcc63c=',
             st_key_pub='',
             st_key_priv='',
             ts_created=datetime.datetime(year=2022, month=6, day=19, hour=0, minute=43, second=1,
                                          tzinfo=datetime.timezone.utc),
             ts_publish=datetime.datetime(year=2022, month=6, day=19, hour=0, minute=43, second=1,
                                          tzinfo=datetime.timezone.utc),
             ts_activate=datetime.datetime(year=2022, month=6, day=19, hour=0, minute=43, second=1,
                                           tzinfo=datetime.timezone.utc),
         )),
        # dnssec-keygen -a RSASHA256 -f KSK test2.example.com
        ('''
         ; This is a key-signing key, keyid 27869, for test2.example.com.
         ; Created: 20220619010855 (Sun Jun 19 02:08:55 2022)
         ; Publish: 20220619010855 (Sun Jun 19 02:08:55 2022)
         ; Activate: 20220619010855 (Sun Jun 19 02:08:55 2022)
         test2.example.com. IN DNSKEY 257 3 8 AwEAAaFplLMHAtp1G51nt1eyEC0SHx07gpD/ccEyyCZuTyaNgd8gVPjV phYtph0EVY5VxKAVFyRmvAhEPRqmuCioupIf8L0Qb49PjPJ/i2pqQXbS BwPlrP1CpXk5n1mOcNlS0mg8n1VT1nWAVS3ub72Zt8NHBPWZEtJLPY3M YdhN765WviUzvmYHrimVJ3Dd3rlVvOY4Xd/cG/PdO5KVKm+FeGmgdSwl tO15XEL9cdusQdnURW4n7USuQi3apZK3Sh+aMCVjzuZmmtuSmPPYLMVz wy12PCORZuegHApLYVA+d0S10eVbtxFPJOtluzcsfZk5b5BHMQUvptyN X9pXWEqWrUk=
         ''', '''
         Private-key-format: v1.3
         Algorithm: 8 (RSASHA256)
         Modulus: oWmUswcC2nUbnWe3V7IQLRIfHTuCkP9xwTLIJm5PJo2B3yBU+NWmFi2mHQRVjlXEoBUXJGa8CEQ9Gqa4KKi6kh/wvRBvj0+M8n+LampBdtIHA+Ws/UKleTmfWY5w2VLSaDyfVVPWdYBVLe5vvZm3w0cE9ZkS0ks9jcxh2E3vrla+JTO+ZgeuKZUncN3euVW85jhd39wb8907kpUqb4V4aaB1LCW07XlcQv1x26xB2dRFbiftRK5CLdqlkrdKH5owJWPO5maa25KY89gsxXPDLXY8I5Fm56AcCkthUD53RLXR5Vu3EU8k62W7Nyx9mTlvkEcxBS+m3I1f2ldYSpatSQ==
         PublicExponent: AQAB
         PrivateExponent: UcESSeMhNNjf1cf0evx7aPimvb2okhxv13ULHzv75wEBaKwNncNIzi7s1gGd++vBHXvRLuTCFEXL1TXgTOe5J835tykd+C5Iq4KicJHE+pPCbdzk05nwCgh/h3K4AbsLSzR5V1SRaQ5JFmyQOC4lf0j3YBXaDJ2DXdDJNi+zWE9VC5E/AG5tzZrAb6elbwbe58M7KlVBLi3VLYmHxuH1Z15ORVWP/MYhPeJ0RIe/c8km3PMTyOjFceY0lEInDj/CSmnBzRSrjvtjkbxCVsDQYmgiitFwOd9M6zLNjBNcn1Y5Y3Xfl149nay/jyMtQRAE20jL830pWfJJ8soCMD/YAQ==
         Prime1: 0v/PJqUCjQVWxhCcIw5TLywuA+Uh6V/2krmA8yOs3miXEmy++Ia/5RuHJdqFwAA3ItVMUZDmnDU+TsT/IWUy6X6FGKASGGGFJbUJh8MpgHnY74lbA9Mx9N9aq2PazRb5UtPki9rxxu+jFqzMhVj+uvzgyZHZF0o0+zcGaSIv3ck=
         Prime2: w9Zq2cnkvHsv6XKUlb/cjFlb2OU0+upJImXOcONY6mLcZTPzLlbaDqc5sWW7uUYW6AeTPxAfNdhwHQkNOvjhthejT4qQeaA0k+vPNvaDJxUX1uAdxuWa8IfIRv/NPWpRLsVWA3Qz5gcn/MjqWudruZgXe6OTyh1Krntl34PyE4E=
         Exponent1: QjJxei1Q1I91PuSdJ75pyKXytdQgRIiP4k6Cr0VlCc4Ef4pQi8Yy1B1D1FNvnOI0aiBDNl/gieeGac4SQRbv1yOTfDtUEgQecssOd2J6Vc1kixorzNJonOuqFZVZYvivNhY2YM5LBl/OaeHCtJ9MI7wMhhDU7CKi5qHHyBoqrEk=
         Exponent2: cx7PLvl0oauUjZmSaLkhL8uzpzuNulYQ6cyI32l1skqtHjy8nifmBSkeS/7urEncW0dgsniKsD9sIFVa1qjJHh6lHLPqm+SmI7JB3CBrFoVavzB9sJb2TqCzBbGHd6vQzzqnhl4/x9+7DOkagpd5ht82JrMQxIYViZ32U78fhYE=
         Coefficient: M8YBFWPrlDazyuhLdqpZ+mCxIEi0eAO2g+K1yyDGK6G11LRPqgPF0peNeUKzRYEiYqA2e83ywhDq2fL5ViHiylghvebTrHEgiqUFWSxVYakWOVJrJ5dzvwOgYpJHvbxNRJ7/c03fV15OB2F9L0napvyxehvhg9SUHexwQ0cEDIY=
         Created: 20220619010855
         Publish: 20220619010855
         Activate: 20220619010855
         ''',
         vdns.rr.DNSSEC(
             domain='test2.example.com',
             ksk=True,
             keyid=27869,
             algorithm=8,
             # dnssec-dsfromkey -1 Ktest2.example.com.+008+27869.key
             digest_sha1='FBE2B3BA11A26B44E9D1096BE721316F15178994',
             # dnssec-dsfromkey -2 Ktest2.example.com.+008+27869.key
             digest_sha256='EFA2940C4E4768D8A9A113C9F5A6BA7543E15A18095126CA71AFFEB6DE8AA48B',
             key_pub='AwEAAaFplLMHAtp1G51nt1eyEC0SHx07gpD/ccEyyCZuTyaNgd8gVPjV phYtph0EVY5VxKAVFyRmvAhEPRqmuCioupIf8L0Qb49PjPJ/i2pqQXbS BwPlrP1CpXk5n1mOcNlS0mg8n1VT1nWAVS3ub72Zt8NHBPWZEtJLPY3M YdhN765WviUzvmYHrimVJ3Dd3rlVvOY4Xd/cG/PdO5KVKm+FeGmgdSwl tO15XEL9cdusQdnURW4n7USuQi3apZK3Sh+aMCVjzuZmmtuSmPPYLMVz wy12PCORZuegHApLYVA+d0S10eVbtxFPJOtluzcsfZk5b5BHMQUvptyN X9pXWEqWrUk=',
             st_key_pub='',
             st_key_priv='',
             ts_created=datetime.datetime(year=2022, month=6, day=19, hour=1, minute=8, second=55,
                                          tzinfo=datetime.timezone.utc),
             ts_publish=datetime.datetime(year=2022, month=6, day=19, hour=1, minute=8, second=55,
                                          tzinfo=datetime.timezone.utc),
             ts_activate=datetime.datetime(year=2022, month=6, day=19, hour=1, minute=8, second=55,
                                           tzinfo=datetime.timezone.utc),
         )),
    ])
    # pylint: enable=line-too-long,unexpected-keyword-arg
    def test_parse(self, st_pub: str, st_priv: str, rr: vdns.rr.DNSSEC) -> None:
        st_pub2 = textwrap.dedent(st_pub)
        st_priv2 = textwrap.dedent(st_priv)

        res = keyparser._parse(rr.domain, st_pub2, st_priv2)
        self.assertIsNotNone(res)
        assert res is not None  # for pylint

        rr.st_key_pub = st_pub2
        rr.st_key_priv = st_priv2

        self.assertDNSSECEqual(res, rr, ignored=())
