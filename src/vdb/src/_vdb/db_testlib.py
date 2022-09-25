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

# Emulates a fake db for tests. Normal usage:
#
# def setUp(self) -> None:
#   db = db_testlib.TestDB()
#   db.set_data(...)
#   self._db = db
#
# def test_something(self) -> None:
#   with db_testlib.fake_db(self._db):
#     ... do stuff that want to use the database ...
#
# Alternative:
#
# def setUp(self) -> None:
#   db = db_testlib.TestDB()
#   db.set_data(...)
#   patcher = db_testlib.fake_db(db)
#   patcher.start()
#   self.addCleanup(patcher.stop)
#   self._db = db
#   self._db_patcher = patcher

# pylint: disable=protected-access

import ipaddress
from typing import Mapping, NoReturn, Optional, Sequence, Type, TypeVar, Union, overload

import types
import logging
import psycopg2
import unittest
import unittest.mock
import dataclasses as dc

from . import db
from .table import Table, TSchema
from .common import OrderParam, ResultDict, ResultsDict, SupportedTypes, ValueParam, WhereParam
from .schemadb import DB

_orig_psycopg2: Optional[types.ModuleType] = None
_mocks: dict[str, object] = {}

Row = Sequence[SupportedTypes]
Rows = list[Row]

T = TypeVar('T')


def fail() -> NoReturn:
    raise Exception('Should not have been called')


def _patch_psycopg2() -> None:
    global _orig_psycopg2

    if _orig_psycopg2 is not None:
        return

    _orig_psycopg2 = psycopg2

    connect = unittest.mock.patch.object(db, 'psycopg2', side_effect=fail, spec=True)
    connect.start()
    _mocks['connect'] = connect


class TestDB(DB):
    __test__ = False

    # A dict of table -> column_names
    _columns: dict[str, Sequence[str]]
    # A dict of table -> contents where contents is a list(rows) of lists(columns)
    _data: dict[str, Rows]
    # A dict of seq_name -> value
    _sequences: dict[str, int]

    def __init__(self) -> None:
        _patch_psycopg2()
        super().__init__('NoDB', 'NoUser', 'NoPass', 'NoHost')

        self._columns = {}
        self._data = {}
        self._sequences = {}

    def _connect(self, dbname: str, dbuser: Optional[str], dbpass: Optional[str], dbhost: Optional[str],
                 dbport: Optional[int]) -> psycopg2.extensions.connection:
        assert _orig_psycopg2 is not None
        ret = unittest.mock.MagicMock(_orig_psycopg2.extensions.connection)
        return ret

    def set_data(self, table: str, columns: Sequence[str], data: Rows) -> None:
        self.set_table_schema(table, columns)
        self._data[table] = [list(x) for x in data]

    def set_data_only(self, table: str, data: Rows) -> None:
        self._data[table] = [list(x) for x in data]

    def get_data(self, table: str) -> list[tuple[SupportedTypes, ...]]:
        """Returns all rows of a table as tuples."""
        return [tuple(x) for x in self._data[table]]

    @overload
    def set_table_schema(self, table: str, columns: Sequence[str]) -> None:
        ...

    @overload
    def set_table_schema(self, table: str, columns: Type[T]) -> Table[T]:
        ...

    def set_table_schema(self, table: str, columns: Union[Sequence[str], Type[T]] = ()) -> Optional[Table[T]]:
        """Sets the table schema either from a dataclass or from a sequence of field names."""
        ret: Optional[Table[T]]

        if isinstance(columns, Sequence):
            if not columns:
                raise Exception('Empty columns list')
            self._columns[table] = columns
            self._data.setdefault(table, [])
            ret = None
        elif dc.is_dataclass(columns):
            # self._columns[table] = [x.name for x in dc.fields(columns)]
            # Get table sets the schema
            ret = self.get_table(table, columns)
        else:
            raise Exception(f'Bad column definition: {type(columns)}: {columns}')

        self._data.setdefault(table, [])
        return ret

    def get_table(self, table: str, schema: Type[TSchema]) -> Table[TSchema]:
        # Use the opportunity to set the schema on get_table()
        self._columns[table] = [x.name for x in dc.fields(schema)]
        self._data.setdefault(table, [])
        return super().get_table(table, schema)

    def _read_raw(self, query: str, kwargs: Optional[dict[str, str]] = None) -> ResultsDict:
        fail()

    def _exec(self, query: str, args: Optional[Mapping[str, SupportedTypes]] = None) -> psycopg2.extensions.cursor:
        fail()

    def begin(self) -> None:
        pass

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def read_q(self, query: str, args: Optional[Mapping[str, SupportedTypes]] = None) -> ResultsDict:
        fail()

    def _matches_where(self, row: ResultDict, where: Optional[WhereParam]) -> bool:
        if not where:
            return True

        for k, v in where.items():
            if k not in row:
                raise Exception(f'Missing column {k}: {row}')
            if row[k] != v:
                return False

        return True

    def _sort_results(self, data: ResultsDict, sort: Optional[OrderParam]) -> None:
        if sort is None:
            return

        def _key(x: ResultDict) -> tuple:
            assert sort is not None
            ret: list[Union[SupportedTypes, tuple]] = []
            for k in sort:
                if x is None:
                    ret.append(None)
                # elif dc.is_dataclass(x):
                #     ret.append(getattr(x, k))
                elif isinstance(x, dict):
                    dt: Union[SupportedTypes, tuple] = x[k]
                    if isinstance(dt, (ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
                        dt = (dt.ip.version, dt)
                    ret.append(dt)
                else:
                    raise Exception('WTF?')
            return tuple(ret)

        data.sort(key=_key)

    def read_flat(self, table: str, where: Optional[WhereParam] = None,
                  sort: Optional[OrderParam] = None) -> ResultsDict:
        if table not in self._columns:
            raise Exception(f'Unknown table: {table}')
        if table not in self._data:
            return []

        ret: ResultsDict = []
        for row in self._data[table]:
            zipped: dict[str, SupportedTypes] = dict(zip(self._columns[table], row))
            logging.debug('zipped %s: %s', table, zipped)
            if not self._matches_where(zipped, where):
                continue
            ret.append(zipped)

        logging.debug('Read from %s where %s: %s', table, where, ret)

        self._sort_results(ret, sort)

        return ret

    def table_exists(self, table: str) -> bool:
        return table in self._columns

    def get_seq(self, sequence: str) -> int:
        return self._sequences.get(sequence, 1)

    def get_seq_next(self, sequence: str) -> int:
        if sequence not in self._sequences:
            ret = 1
            self._sequences[sequence] = 2
        else:
            ret = self._sequences[sequence]
            self._sequences[sequence] += 1
        return ret

    def insert(self, table: str, values: ValueParam) -> int:
        assert not (set(values.keys()) - set(self._columns[table])), \
            f'Bad columns in values: {values}, expected: {self._columns[table]}'
        logging.debug('FakeDB Insert to %s: %s', table, values)
        self._data[table].append([values.get(x, None) for x in self._columns[table]])
        return 1

    def update(self, table: str, values: ValueParam, where: WhereParam) -> int:
        if table not in self._columns:
            raise Exception(f'Unknown table: {table}')
        if table not in self._data:
            return 0
        ret = 0
        for idx, row in enumerate(self._data[table]):
            zipped = dict(zip(self._columns[table], row))
            if not self._matches_where(zipped, where):
                continue
            # The copy ensures that it's a list and not a tuple
            new_row = list(row)
            for idx2, column in enumerate(self._columns[table]):
                if column in values:
                    new_row[idx2] = values[column]
            self._data[table][idx] = new_row
            ret += 1
        return ret

    def delete(self, table: str, where: WhereParam) -> int:
        data = []
        ret: int = 0
        for row in self._data[table]:
            zipped = dict(zip(self._columns[table], row))
            if self._matches_where(zipped, where):
                ret += 1
            else:
                data.append(row)
        self._data[table] = data
        return ret
