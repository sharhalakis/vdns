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

from typing import Optional

import unittest.mock
import ipaddress
import dataclasses as dc

from . import db_testlib
from .table import RowNotLikeSchemaError
from .common import ParamDict


@dc.dataclass
class TableT1:
    id: int
    name: str
    age: float
    mail: bool
    ip4: ipaddress.IPv4Interface
    ip6: ipaddress.IPv6Interface
    jdata: dict
    empty: Optional[int]


@dc.dataclass
class TableT1_BadType:
    id: int
    name: int
    age: float
    mail: bool
    ip4: ipaddress.IPv4Network
    ip6: ipaddress.IPv6Network
    jdata: dict
    empty: Optional[int]


@dc.dataclass
class TableT1_MissingField:
    id: int
    name: str
    age: float
    # mail: bool
    ip4: ipaddress.IPv4Interface
    ip6: ipaddress.IPv6Interface
    jdata: dict
    empty: Optional[int]


class DBTestSchema(unittest.TestCase):
    _insert_data: ParamDict

    def setUp(self) -> None:
        db = db_testlib.TestDB()
        self._db = db

        db.set_data('t1', ('id', 'name', 'age', 'mail', 'ip4', 'ip6', 'jdata', 'empty'),
                    [(1, 'Stef', 13.3, True, ipaddress.ip_interface('10.1.1.1/32'),
                      ipaddress.ip_interface('2001::1/128'),
                      {'a': 'aaa', 'b': 'bbb'}, None)])
        # Sample data to be used in inserts
        self._insert_data = {'id': 2, 'name': 'Albert', 'age': 19.0, 'mail': False,
                             'ip4': ipaddress.ip_interface('10.2.1.1/32'), 'ip6': ipaddress.ip_interface('2001::2/128'),
                             'jdata': {}, 'empty': None}

    def test_schema(self) -> None:
        t1 = self._db.get_table('t1', TableT1)
        dt = t1.read_flat()
        self.assertTrue(dc.is_dataclass(dt[0]))
        t1.insert(values=self._insert_data)  # dict insert
        t1.insert(values=TableT1(**self._insert_data))  # type: ignore  # dataclass insert
        t1.update({'id': 2}, {'name': 'Goofy'})
        t1.delete({'id': 2})

    def test_schema_bad_type(self) -> None:
        t1 = self._db.get_table('t1', TableT1_BadType)
        with self.assertRaises(RowNotLikeSchemaError):
            t1.read_flat()
        with self.assertRaises(RowNotLikeSchemaError):
            t1.insert(values=self._insert_data)
        with self.assertRaises(RowNotLikeSchemaError):
            t1.update({'id': 2}, {'age': 'thirteen'})
        with self.assertRaises(RowNotLikeSchemaError):
            t1.delete({'id': 'something'})

    def test_schema_missing_field(self) -> None:
        t1 = self._db.get_table('t1', TableT1_MissingField)
        with self.assertRaises(RowNotLikeSchemaError):
            t1.read_flat()
        with self.assertRaises(RowNotLikeSchemaError):
            t1.insert(values=self._insert_data)
        with self.assertRaises(RowNotLikeSchemaError):
            t1.update({'id': 2}, {'mail': True})
        with self.assertRaises(RowNotLikeSchemaError):
            t1.delete({'mail': False})
