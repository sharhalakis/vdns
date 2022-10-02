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

import unittest

import vdns.util.config


class MergeConfigTest(unittest.TestCase):

    def test_merge(self) -> None:
        class Obj1:
            t1 = 1
            t2 = 1

        class Obj2:
            t1 = 2
            t3 = 2
            t4 = None

        o1 = Obj1()
        o2 = Obj2()

        mo = vdns.util.config.MergedConfig(o1, o2)

        self.assertEqual(mo.t1, 1)
        self.assertEqual(mo.t2, 1)
        self.assertEqual(mo.t3, 2)
        self.assertIsNone(mo.t4)

        mo.t1 = 9
        self.assertEqual(mo.t1, 9)
        self.assertEqual(o1.t1, 9)
        self.assertEqual(o2.t1, 2)

        mo.t2 = 9
        self.assertEqual(mo.t2, 9)
        self.assertEqual(o1.t2, 9)

        mo.t3 = 9
        self.assertEqual(mo.t3, 9)
        self.assertEqual(o2.t3, 9)

        mo.t4 = 9
        self.assertEqual(mo.t4, 9)
        self.assertEqual(o2.t4, 9)
