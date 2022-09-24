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

from typing import Generic, Mapping, Optional, Type, TypeVar, Union
from typing import get_args, get_origin, get_type_hints

from .db import DB0
from .common import OrderParam, ResultDict, ResultsDict, ParamDict, SupportedTypes, ValueParam, VDBError, WhereParam

import dataclasses as dc

TSchema = TypeVar('TSchema')


class Schema:
    """Helper that instantiates derived dataclasses from a dictionary."""

    # Derived classes can override this to transform the read dictionary to a dataclass-compatible one
    @classmethod
    def transform_data(cls, data: ParamDict) -> ValueParam:  # dict[str, object]:
        return data  # type: ignore

    # This should do the opposite of transform_data(). Used for storing data from a schema object
    @classmethod
    def transform_data_inverse(cls, data: dict[str, object]) -> ParamDict:
        return data  # type: ignore


class SchemaTableError(VDBError):
    pass


class RowNotLikeSchemaError(VDBError):
    def __init__(self, table: str, msg: str) -> None:
        super().__init__(f"{table}: Row doesn't match schema: {msg}")


class Table(Generic[TSchema]):
    """Adapter class for tables with schema.

    Transformations:
        Supports transformations through Schema.transform_*().
        The transformation happens before the schema is checked. It is meant to postprocess the db data and make
        them suitable to be stored in the schema dataclass.

        When transform_data() is implemented, transform_data_inverse() must also be implemented, even if it is
        just to throw NotImplementedError, or else it will attempt to store the wrong fields or the wrong data.
    """
    schema: Type[TSchema]
    db: DB0
    table: str

    def __init__(self, db: DB0, table: str, schema: Type[TSchema]) -> None:
        self.db = db
        self.table = table
        self.schema = schema

    def _check_schema(self, dt: Optional[ValueParam]) -> None:
        if dt is None:
            return
        row_fields = set(dt.keys())
        schema_fields = set(self.schema.__annotations__.keys())
        if row_fields - schema_fields:
            raise RowNotLikeSchemaError(self.table, f'Unhandled fields: {row_fields - schema_fields}')
        for k, v in dt.items():
            badfield = False
            hints = get_type_hints(self.schema)

            # For lists we can't use instance(). Do it manually and check every item
            if isinstance(v, list):
                origin = get_origin(hints[k])
                if origin is None or not issubclass(list, origin):
                    badfield = True
                else:
                    for item in v:
                        if not isinstance(item, get_args(hints[k])):
                            raise RowNotLikeSchemaError(self.table,
                                                        f'List item for field {k} is not of type "{hints[k]}": {item}')
            # TODO: Do the same for dicts
            elif not isinstance(v, self.schema.__annotations__[k]):
                badfield = True

            if badfield:
                raise RowNotLikeSchemaError(self.table, f'Field {k} is "{type(v)}" instead of "{hints[k]}"')

    # def _transform(self, data: Optional[ResultDict]) -> Optional[dict[str, object]]:
    def _transform(self, data: Optional[ResultDict]) -> Optional[ValueParam]:
        if data is None:
            return None
        if issubclass(self.schema, Schema):
            return self.schema.transform_data(data)
        return data  # type: ignore

    def _transform_inverse(self, data: dict[str, object]) -> ParamDict:
        if issubclass(self.schema, Schema):
            return self.schema.transform_data_inverse(data)
        return data  # type: ignore

    def _resultsdict_to_schemalist(self, results: ResultsDict) -> list[TSchema]:
        ret: list[TSchema] = []
        for res in results:
            res2 = self._transform(res)
            self._check_schema(res2)
            ret.append(self.schema(**res2))
        return ret

    def exists(self) -> bool:
        return self.db.table_exists(self.table)

    def read_q(self, query: str, args: Optional[Mapping[str, SupportedTypes]] = None) -> list[TSchema]:
        r = self.db.read_q(query, args)
        return self._resultsdict_to_schemalist(r)

    def read_one(self, where: WhereParam, sort: Optional[OrderParam] = None) -> Optional[TSchema]:
        self._check_schema(where)
        r = self.db.read_one(self.table, where, sort)
        if r is None:
            return None
        r2 = self._transform(r)
        self._check_schema(r2)
        return self.schema(**r2)

    def read_flat(self, where: Optional[WhereParam] = None, sort: Optional[OrderParam] = None) -> list[TSchema]:
        self._check_schema(where)
        r = self.db.read_flat(self.table, where, sort)
        return self._resultsdict_to_schemalist(r)

    def insert(self, values: Union[ValueParam, TSchema]) -> int:
        if dc.is_dataclass(values):
            values2 = self._transform_inverse(dc.asdict(values))
        elif isinstance(values, dict):
            self._check_schema(values)
            values2 = values
        else:
            raise SchemaTableError('Unhandled value type {type(values)}: {values}')
        return self.db.insert(self.table, values2)

    def update(self, values: ValueParam, where: WhereParam) -> int:
        self._check_schema(values)
        self._check_schema(where)
        return self.db.update(self.table, values, where)

    def delete(self, where: WhereParam) -> int:
        self._check_schema(where)
        return self.db.delete(self.table, where)


class QueryTable(Table):
    """A table that comes from a query."""

    def __init__(self, db: DB0, schema: Type[TSchema]) -> None:
        super().__init__(db, 'NoSuchTable', schema)
