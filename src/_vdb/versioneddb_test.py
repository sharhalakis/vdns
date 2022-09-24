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

from typing import Callable, Mapping, Optional

import psycopg2
import textwrap
import unittest.mock
import dataclasses as dc

from . import db_testlib
from .table import Schema
from .common import SupportedTypes
from .schemadb import DB
from .versioneddb import DBVersions, VersionedDB, DBUpgradeNeededError

STATEMENT1 = "INSERT INTO tbl1 VALUES(1, 'a');"
STATEMENT2 = "INSERT INTO tbl1 VALUES(2, 'b');"


@dc.dataclass
class Tbl1(Schema):
    key: int
    st: Optional[str]


class MyVersionedDB(VersionedDB):
    _files: dict = {
        'sql/test_mod1.sql': f'''
        -- BEGIN: 1
        {STATEMENT1}
        -- END: 1
        -- BEGIN: 2
        {STATEMENT2}
        -- END: 2
        '''
    }

    def __init__(self, db: DB) -> None:
        super().__init__(db, 'test', sql_files_dir='sql')

    def _get_modules(self) -> list[tuple[str, int, Optional[Callable]]]:
        return [
            ('mod1', 2, None),
        ]

    def _readfile(self, fn: str) -> str:
        return textwrap.dedent(self._files[fn])


class MyTestDB(db_testlib.TestDB):

    def _exec(self, query: str, args: Optional[Mapping[str, SupportedTypes]] = None) -> psycopg2.extensions.cursor:
        if STATEMENT1 in query:
            self.insert('tbl1', {'key': 1, 'st': 'a'})
        elif STATEMENT2 in query:
            self.insert('tbl1', {'key': 2, 'st': 'b'})
        elif 'CREATE' in query:
            pass
        else:
            raise Exception(f'Unexpected exec: {query}')


class VersionedDBTest(unittest.TestCase):

    def setUp(self) -> None:
        db = MyTestDB()
        self._db = db

        db.set_table_schema('vdb_dbversions', DBVersions)
        db.set_table_schema('tbl1', Tbl1)

    def test_no_dbversions(self) -> None:
        vdb = MyVersionedDB(self._db)
        with self.assertRaises(DBUpgradeNeededError):
            vdb.init_db()
        vdb.upgrade_db()

        dbversions = self._db.get_data('vdb_dbversions')
        self.assertCountEqual(dbversions, [('vdb', 'dbversions', 1), ('test', 'mod1', 2)])
