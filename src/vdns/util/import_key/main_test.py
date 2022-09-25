# Copyright (c) 2022 Google LLC
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
import tempfile
import unittest

from vdns import db_testlib
import vdns.db
import vdns.util.import_key.main

PUBLICKEY = '''\
; This is a zone-signing key, keyid 22833, for test.gr.
; Created: 20220925152812 (Sun Sep 25 16:28:12 2022)
; Publish: 20220925152812 (Sun Sep 25 16:28:12 2022)
; Activate: 20220925152812 (Sun Sep 25 16:28:12 2022)
test.gr. IN DNSKEY 256 3 8 AwEAAdCK4LkO0Xcg2zAiMx/mBkMye3HPZ/+Jka432LX33OvRasGYm+vQ z3L1H0Nl1jHsGAGYOWrrKE/sY6LSC2COFbzIdBpH1edcQVCKjhg7TYW8 u9NiiMsnVGHwAJ/NtRZvu3M3ODwXdzUyjEUpWZLBbhXuVFyQohEAoSJD JZZ2mHvFdikhAVfwYpbG25/nx5SEDyWqVb2AbU2J5MATZ7jsFFMCyzL6 NvfrgXJr1tWZtstV8zOLGeckGsu/ruuSqBDUjZYK2mdGX3LIK7EvpjgP DUeKnchZL5onlqU2zODb3ZFKvaEViv6P3o4yt3G0PvzaJs8/b+QK8H5P ZqS1gGylybE=
'''

PRIVATEKEY = '''\
Private-key-format: v1.3
Algorithm: 8 (RSASHA256)
Modulus: 0IrguQ7RdyDbMCIzH+YGQzJ7cc9n/4mRrjfYtffc69FqwZib69DPcvUfQ2XWMewYAZg5ausoT+xjotILYI4VvMh0GkfV51xBUIqOGDtNhby702KIyydUYfAAn821Fm+7czc4PBd3NTKMRSlZksFuFe5UXJCiEQChIkMllnaYe8V2KSEBV/Bilsbbn+fHlIQPJapVvYBtTYnkwBNnuOwUUwLLMvo29+uBcmvW1Zm2y1XzM4sZ5yQay7+u65KoENSNlgraZ0ZfcsgrsS+mOA8NR4qdyFkvmieWpTbM4NvdkUq9oRWK/o/ejjK3cbQ+/Nomzz9v5Arwfk9mpLWAbKXJsQ==
PublicExponent: AQAB
PrivateExponent: AYt91bEf6R+DsCwYr9xO4JGPq4yrSw/UVfOQ9ewjpVWUUmHUid8uoj3hoOiwuQb0OJLNnham4kywgkTHE8yJqa/ceFNe6MtcqoGUQuaxkNOQmqTIuaSNcfpKruRhuoxSWaynjH5qAilhM6P2R2mKbLwqwNLLeI/GIdBYh3BSedw9ryc9H92FetD08z52ICmSCErF8RIFhMHcC7Qu9XB1domk6hxAM2dPeKLEGf4vR/9xhj1KxxQ4JZONOMV59YRXvoHsmDa5dwfhL53rEOKS5Ucp02viwvoxP38caNMUOQycFS3j4+Ug8w62GXn0ZEx48eedEB2rKV2rnemWcqq2aQ==
Prime1: 0n+vb6slM6gsUbRehqRSmSUHN9o4j5Ab3XA66bIRkrKxpzVhdAdHa5tDuwG7bBXvFc8Ibm79kEbfsT03Jj/HUmnKsgs+WjRv97SqPVDJKluI2w+G4hyIlqNYtVGDuOWcLcdGqWCDOmQJn+V6JX+RnLdbFJvKXU/dXgx1LRKcWHU=
Prime2: /Z7wPHZn3t6OAcXhpMtxbJVvlSNds6xbaeHI2flzeO2CNDPSEnrJD84RT12ap2pob1sdrzp1hAke2FYx/kLJmaMQ6UaB/oSOZlg3ArZswgtZf/mRFe8DVIm4LTaAdMBVpMpEbkD48ykFasLF5rxdxCj/h3Qos1P4xADPjxCopM0=
Exponent1: j0EYat3Fhp9H8h7XSbhhAhpCDE+1uHYxkIUFgu+NqBF2d74LYYRmpaPX91fZbliLCoOIUGe2ps6lA6EOfDhhdQPMT1j5iTgwjxpj1TC6htoejD7H4+/ZQPNPtq4P//A7VqhMvY6SIFXeevQYKZbkyQu7r43KrbBhjdTald8ZidU=
Exponent2: ZkX9oqQs5tbgdR6TC51us9bfFEkatCXBB0WhdST+x7kfVGXBROp2wgTbPiIFB5YFX0JjChKM6R20bpDzwBC2s1nqq+de7IAP3H2eUV23Jdjl0pGVTD8CHMkcmD7uNiaJYtaeGcfhnEziflbk71LujPfrc3gIIaivHHsnOA4Ds9E=
Coefficient: fW9iPJzbBuh0rmA0NJhecoOEkvZ4zcc3di6+sFFfx9pgogNjsKSXN80ebmhOfvgFVSZ+x0CS0T2t32BYNF2wiuEPJBk21OcaHn5Vtc3cnlK/QVRmwqXMw2TU48QaiWE07Ff35GlcG4rkgXSJizUfArY7rc/yR540KgVG4d+lMWA=
Created: 20220925152812
Publish: 20220925152812
Activate: 20220925152812
'''


class TestlibTest(unittest.TestCase):
    _db: db_testlib.DB

    def setUp(self) -> None:
        db_testlib.init()
        vdns.db.init_db()
        self._db = db_testlib.get_db()
        db_testlib.add_test_data()

    def test_parse_one(self) -> None:
        domain = 'test.gr'
        ttl = datetime.timedelta(hours=1)

        with tempfile.TemporaryDirectory() as d:
            privfn = f'{d}/test.private'
            pubfn = f'{d}/test.key'
            with open(privfn, 'wt', encoding='utf-8') as f:
                f.write(PRIVATEKEY)
            with open(pubfn, 'wt', encoding='utf-8') as f:
                f.write(PUBLICKEY)
            vdns.util.import_key.main.parse_one(privfn, domain, ttl)

        dt_all = self._db.dnssec.read_flat()
        self.assertEqual(len(dt_all), 1)

        dt = dt_all[0]
        self.assertEqual(dt.domain, 'test.gr')
        self.assertEqual(dt.keyid, 22833)
        self.assertEqual(dt.ksk, False)
        self.assertEqual(dt.algorithm, 8)

        # From dnssec-dsfromkey -1 -2 Ktest.gr.+008+22833.key
        self.assertEqual(dt.digest_sha1, 'EB09F8387535EE217514B858289ABA9C0F715C72')
        self.assertEqual(dt.digest_sha256, '9421E7D08C5E8DA892026F61E407317ED091AF811F0D37C486B45ED9A1B764E9')
        self.assertEqual(dt.key_pub, 'AwEAAdCK4LkO0Xcg2zAiMx/mBkMye3HPZ/+Jka432LX33OvRasGYm+vQ '
                                     'z3L1H0Nl1jHsGAGYOWrrKE/sY6LSC2COFbzIdBpH1edcQVCKjhg7TYW8 '
                                     'u9NiiMsnVGHwAJ/NtRZvu3M3ODwXdzUyjEUpWZLBbhXuVFyQohEAoSJD '
                                     'JZZ2mHvFdikhAVfwYpbG25/nx5SEDyWqVb2AbU2J5MATZ7jsFFMCyzL6 '
                                     'NvfrgXJr1tWZtstV8zOLGeckGsu/ruuSqBDUjZYK2mdGX3LIK7EvpjgP '
                                     'DUeKnchZL5onlqU2zODb3ZFKvaEViv6P3o4yt3G0PvzaJs8/b+QK8H5P '
                                     'ZqS1gGylybE=')
        self.assertEqual(dt.st_key_pub, PUBLICKEY)
        self.assertEqual(dt.st_key_priv, PRIVATEKEY)
