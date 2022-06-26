# import datetime
# import textwrap
import unittest
import parameterized

import vdns.dnssec

# pylint: disable=protected-access


class DNSSECTest(unittest.TestCase):

    @parameterized.parameterized.expand([
        (256, 3, 8, ('AwEAAcivnbSxgMkTvzCTA/Py2qqo3EANPUwqL4HalAfNmuDGuFaOu+xT'
                     'KlXjiLyfUMKcuy+jKPamGn//z+B5Zsy4j6a1KAaT5u9fli8BH5C1r2Pg'
                     'qXKvT6YTwk2M5djuLXdeoe9d5rFzcd7tu01ifFsrh3s7pARkOpjV26Fq'
                     'NkxPTiKLidsdAjviHRI5SGAyEx6ouKN1b54HO0uZXPB2xewzjNtWNL37'
                     'PW0l/lAeCba78CUu4X4510J2J/BzQ3e7ST6UOQE3gU7pvsM4agZIoiC/'
                     'UQ+DFODNrdtfU8UAceMl7L6AZgCN8x7H6KOr3phuAzbg3/u+eNyxEu7c'
                     '9baFjzcc63c='), 52396),
        # With spaces
        (256, 3, 8, ('AwEAAcivnbSxgMkTvzCTA/Py2qqo3EANPUwqL4HalAfNmuDGuFaOu+xT '
                     'KlXjiLyfUMKcuy+jKPamGn//z+B5Zsy4j6a1KAaT5u9fli8BH5C1r2Pg '
                     'qXKvT6YTwk2M5djuLXdeoe9d5rFzcd7tu01ifFsrh3s7pARkOpjV26Fq '
                     'NkxPTiKLidsdAjviHRI5SGAyEx6ouKN1b54HO0uZXPB2xewzjNtWNL37 '
                     'PW0l/lAeCba78CUu4X4510J2J/BzQ3e7ST6UOQE3gU7pvsM4agZIoiC/ '
                     'UQ+DFODNrdtfU8UAceMl7L6AZgCN8x7H6KOr3phuAzbg3/u+eNyxEu7c '
                     '9baFjzcc63c='), 52396),
        (257, 3, 8, ('AwEAAaFplLMHAtp1G51nt1eyEC0SHx07gpD/ccEyyCZuTyaNgd8gVPjV'
                     'phYtph0EVY5VxKAVFyRmvAhEPRqmuCioupIf8L0Qb49PjPJ/i2pqQXbS'
                     'BwPlrP1CpXk5n1mOcNlS0mg8n1VT1nWAVS3ub72Zt8NHBPWZEtJLPY3M'
                     'YdhN765WviUzvmYHrimVJ3Dd3rlVvOY4Xd/cG/PdO5KVKm+FeGmgdSwl'
                     'tO15XEL9cdusQdnURW4n7USuQi3apZK3Sh+aMCVjzuZmmtuSmPPYLMVz'
                     'wy12PCORZuegHApLYVA+d0S10eVbtxFPJOtluzcsfZk5b5BHMQUvptyN'
                     'X9pXWEqWrUk='), 27869),
    ])
    def test_clac_dnssec_keyid(self, flags: int, protocol: int, algorithm: int, st: str, keyid: int) -> None:
        res = vdns.dnssec.calc_dnssec_keyid(flags, protocol, algorithm, st)
        self.assertEqual(res, keyid)


    @parameterized.parameterized.expand([
        ('test2.example.com', 256, 3, 8, 'AwEAAcivnbSxgMkTvzCTA/Py2qqo3EANPUwqL4HalAfNmuDGuFaOu+xT '
                                         'KlXjiLyfUMKcuy+jKPamGn//z+B5Zsy4j6a1KAaT5u9fli8BH5C1r2Pg '
                                         'qXKvT6YTwk2M5djuLXdeoe9d5rFzcd7tu01ifFsrh3s7pARkOpjV26Fq '
                                         'NkxPTiKLidsdAjviHRI5SGAyEx6ouKN1b54HO0uZXPB2xewzjNtWNL37 '
                                         'PW0l/lAeCba78CUu4X4510J2J/BzQ3e7ST6UOQE3gU7pvsM4agZIoiC/ '
                                         'UQ+DFODNrdtfU8UAceMl7L6AZgCN8x7H6KOr3phuAzbg3/u+eNyxEu7c '
                                         '9baFjzcc63c=',
         '1DCE328AA7CD9D3B26E7C31861B860B2C0310A2D',
         '79474CCB104B61AE55532BE9DE3D443C5A38FD2E3D9F125DCD97C0AA58F9A653'),
        ('test2.example.com', 257, 3, 8, 'AwEAAaFplLMHAtp1G51nt1eyEC0SHx07gpD/ccEyyCZuTyaNgd8gVPjV'
                                         'phYtph0EVY5VxKAVFyRmvAhEPRqmuCioupIf8L0Qb49PjPJ/i2pqQXbS'
                                         'BwPlrP1CpXk5n1mOcNlS0mg8n1VT1nWAVS3ub72Zt8NHBPWZEtJLPY3M'
                                         'YdhN765WviUzvmYHrimVJ3Dd3rlVvOY4Xd/cG/PdO5KVKm+FeGmgdSwl'
                                         'tO15XEL9cdusQdnURW4n7USuQi3apZK3Sh+aMCVjzuZmmtuSmPPYLMVz'
                                         'wy12PCORZuegHApLYVA+d0S10eVbtxFPJOtluzcsfZk5b5BHMQUvptyN'
                                         'X9pXWEqWrUk=',
         'FBE2B3BA11A26B44E9D1096BE721316F15178994',
         'EFA2940C4E4768D8A9A113C9F5A6BA7543E15A18095126CA71AFFEB6DE8AA48B'),
    ])
    def test_calc_ds_sigs(self, owner: str, flags: int, protocol: int, algorithm: int, st: str,
                          sha1: str, sha256: str) -> None:
        res = vdns.dnssec.calc_ds_sigs(owner, flags, protocol, algorithm, st)
        self.assertEqual(res.sha1, sha1)
        self.assertEqual(res.sha256, sha256)
