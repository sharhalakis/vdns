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

from typing import Type

from .db import DB0
from .table import TSchema, Table


class DB(DB0):
    # def __init__(self, db: DB) -> None:  # Emulates a copy constructor
    #     self.db = db.db
    #     self.transaction_depth = 0
    #     self.transaction_rollback = False
    #
    #     # Don't copy when something's in progress
    #     assert db.transaction_depth == 0
    #     assert db.transaction_rollback is False

    def get_table(self, table: str, schema: Type[TSchema]) -> 'Table[TSchema]':
        return Table(db=self, table=table, schema=schema)
