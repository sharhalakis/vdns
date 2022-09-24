# Copyright (c) 2005-2016 Stefanos Harhalakis <v13@v13.gr>
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

# pylint: disable=protected-access

import unittest
import unittest.mock
import parameterized

from . import db as vdb_db
from .db import DB0


class DBTest(unittest.TestCase):

    def setUp(self) -> None:
        super().setUp()

        # Failsafes in case _get_db() isn't used or doesn't work
        connect = unittest.mock.patch.object(vdb_db.psycopg2, 'connect')
        extras = unittest.mock.patch.object(vdb_db.psycopg2, 'extras')
        self._psycopg2_connect = connect.start()
        self._psycopg2_extras = extras.start()
        self.addCleanup(unittest.mock.patch.stopall)

    def _get_db(self) -> DB0:
        with unittest.mock.patch.object(DB0, '_connect'):
            ret = DB0(dbname='__no_such_db', dbuser='__no_such_user')

        # Ensure that we didn't try to call an actual connect
        self._psycopg2_connect.assert_not_called()

        return ret

    @parameterized.parameterized.expand([
        ('select', None, {'k1': 'v1', 'k2': 'v2'}, None, 'SELECT * FROM table WHERE k1=v1 AND k2=v2'),
        ('select', None, {'k1': 'v1', 'k2': 'v2'}, ['k1'], 'SELECT * FROM table WHERE k1=v1 AND k2=v2 ORDER BY k1'),
        ('select', None, {'k1': 'v1', 'k2': 'v2'}, ['-k1'],
         'SELECT * FROM table WHERE k1=v1 AND k2=v2 ORDER BY k1 DESC'),
        ('insert', {'k1': 'v1', 'k2': 'v2'}, None, None, 'INSERT INTO table(k1, k2) VALUES (v1, v2)'),
        ('update', {'k1': 'v3', 'k2': 'v2'}, {'k1': 'v1'}, None, 'UPDATE table SET k1=v3, k2=v2 WHERE k1=v1'),
        ('delete', None, {'k1': 'v1'}, None, 'DELETE FROM table WHERE k1=v1'),
        ('delete', None, {'k1': 'v1', 'k2': 'v2'}, None, 'DELETE FROM table WHERE k1=v1 AND k2=v2'),
    ])
    def test_form_query(self, what: str, values: dict, where: dict, sort: list, result: str) -> None:
        """Tests _form_query

        The result contains unquoted values because of how the args are expanded for the test.
        """
        db = self._get_db()
        query, args = db._form_query(what, 'table', values, where, sort)
        st = query % args
        self.assertEqual(st, result)
