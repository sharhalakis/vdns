# pylint: disable=protected-access
#
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

import typing
import datetime
import unittest

from vdns import db_testlib
import vdns.db

from typing import Optional


class TestlibTest(unittest.TestCase):

    _db: db_testlib.DB

    def setUp(self) -> None:
        db_testlib.init()
        vdns.db.init_db()
        self._db = db_testlib.get_db()
        db_testlib.add_test_data()

    def test_init(self) -> None:
        self.assertIsInstance(vdns.db._db, db_testlib.DB)

    def test_bad_domain(self) -> None:
        self.assertEqual(len(self._db.cnames.read_flat({'domain': 'baddomain'})), 0)

        with self.assertRaises(Exception):
            self._db.store_serial('baddomain', 10)

        self.assertFalse(self._db.is_dynamic('baddomain'))

    def test_read_table(self) -> None:
        rows = self._db.cnames.read_flat()
        self.assertGreaterEqual(len(rows), 3)

        for row in rows:
            self.assertIsInstance(row.ttl, typing.get_args(Optional[datetime.timedelta]))

    def test_is_dynamic(self) -> None:
        self.assertFalse(self._db.is_dynamic('unknowndomain'))
        self.assertFalse(self._db.is_dynamic('dom1'))
        self.assertTrue(self._db.is_dynamic('dyn.v13.gr'))
