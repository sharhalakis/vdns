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

from typing import Mapping, Optional

from .common import OrderParam, ResultDict, ResultsDict, SupportedTypes, ValueParam, WhereParam
from .common import VDBError

import logging
import psycopg2
import psycopg2.extras
import psycopg2.errorcodes


class DB0:
    """!
    Base database object
    """

    db: Optional[psycopg2.extensions.connection]

    # Holds the depth of begin()s
    transaction_depth: int

    # True if there was a rollback
    transaction_rollback: bool

    def __init__(self, dbname: str, dbuser: str, dbpass: Optional[str] = None, dbhost: Optional[str] = None):
        logging.debug('Connecting to %s@%s (user=%s)', dbname, dbhost, dbuser)

        self.db = self._connect(dbname=dbname, dbuser=dbuser, dbpass=dbpass, dbhost=dbhost)
        self.transaction_depth = 0
        self.transaction_rollback = False

    def _connect(self, dbname: str, dbuser: str, dbpass: Optional[str],
                 dbhost: Optional[str]) -> psycopg2.extensions.connection:
        # psycopg2.extras.register_inet()
        psycopg2.extras.register_ipaddress()

        db = psycopg2.connect(
            database=dbname,
            user=dbuser,
            password=dbpass,
            host=dbhost,
        )

        if db is None:
            raise VDBError('Failed to connect to db')

        try:
            psycopg2.extras.register_json(db)
        except psycopg2.ProgrammingError:
            # Don't fail if there is no json datatype in the DB
            pass

        db.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        db.set_client_encoding('utf-8')

        logging.debug('Connected to %s@%s (user=%s)', dbname, dbhost, dbuser)

        return db

    def close(self) -> None:
        if self.db is not None:
            self.db.close()
            self.db = None

    def _read_raw(self, query: str, kwargs: Optional[dict[str, str]] = None) -> ResultsDict:
        """
        No logging version
        """
        assert self.db is not None

        logging.debug('_read_raw(): query="%s", args="%s"', query, kwargs)
        cur = self.db.cursor()
        cur.execute(query, kwargs)

        ret = []
        for x in cur:
            dt = {}
            for idx, v in enumerate(cur.description):
                dt[v.name] = x[idx]
            ret.append(dt)

        return ret

    def _exec(self, query: str, args: Optional[Mapping[str, SupportedTypes]] = None) -> psycopg2.extensions.cursor:
        """
        Internal function

        Execute a query and return the cursor
        """
        assert self.db is not None

        logging.debug('_exec(): query="%s", args="%s"', query, args)
        cur = self.db.cursor()
        # logging.debug('Executing: %s' % (query,))
        cur.execute(query, args)

        return cur

    def _form_query(self, what: str, tbl: str,
                    values: Optional[ValueParam] = None,
                    where: Optional[WhereParam] = None,
                    sort: Optional[OrderParam] = None,
                    limit: Optional[int] = None) -> tuple[str, dict[str, SupportedTypes]]:
        """
        Form a query

        @param what     One of 'select', 'update', 'delete'
        @param values   The new values to insert in case of an update
                        or the values to insert in case of insert
        @param where    A dictionary of k/v pairs
        @param sort     A list of column names to use for sorting.
                        If they start with - then it means descending
        @param limit    The maximum number of entries to return.
        @return A tuple of (query, args)
        """

        args: dict[str, SupportedTypes] = {'table': tbl}

        if what == 'select':
            q = f'SELECT * FROM {tbl}'
        elif what == 'update':
            q = f'UPDATE {tbl} SET'
        elif what == 'delete':
            q = f'DELETE FROM {tbl}'
        elif what == 'insert':
            q = f'INSERT INTO {tbl}'
        else:
            raise VDBError

        if what == 'insert':
            t = []
            assert values is not None
            for v in values:
                name2 = 'v_' + v
                args[name2] = values[v]
                t.append(f'%({name2})s')
            q += '(' + ', '.join(list(values.keys())) + ') VALUES (' + ', '.join(t) + ')'
        elif what == 'update':
            t = []
            assert values is not None
            for v in values:
                name2 = 'v_' + v
                args[name2] = values[v]
                t.append(f'{v}=%({name2})s')
            q += ' ' + ', '.join(t)

        if what in ('select', 'update', 'delete') and where:
            q += ' WHERE '
            t = []
            for w, w_value in where.items():
                if w_value is None:
                    t.append(f'{w} IS NULL')
                else:
                    name2 = 'w_' + w
                    args[name2] = w_value
                    t.append(f'{w}=%({name2})s')
            q += ' AND '.join(t)

        if sort:
            q += ' ORDER BY '
            t = []
            for s in sort:
                if s[0] == '-':
                    name2 = f'{s[1:]} DESC'
                else:
                    name2 = s
                t.append(name2)
            q += ', '.join(t)

        if limit is not None:
            q += f' LIMIT {limit}'

        ret = (q, args)
        return ret

    # ---------------------------------------------------------------------
    # API

    def begin(self) -> None:
        if self.transaction_depth == 0:
            self._exec('BEGIN')
            self.transaction_rollback = False
        self.transaction_depth += 1

    def commit(self) -> None:
        self.transaction_depth -= 1
        if self.transaction_depth == 0:
            if self.transaction_rollback:
                self._exec('ROLLBACK')
            else:
                self._exec('COMMIT')
            self.transaction_rollback = False

    def rollback(self) -> None:
        # self.db.rollback()
        self.transaction_depth -= 1
        if self.transaction_depth == 0:
            self._exec('ROLLBACK')
            self.transaction_rollback = False
        else:
            self.transaction_rollback = True

    def read_q(self, query: str, args: Optional[Mapping[str, SupportedTypes]] = None) -> ResultsDict:
        """!
        Execute a query and return all results
        """
        cur = self._exec(query, args)

        dt0 = cur.fetchall()
        ret: ResultsDict = []

        labels = [x.name for x in cur.description]
        for d in dt0:
            r: ResultDict = dict(list(zip(labels, d)))
            ret.append(r)

        return ret

    def read_flat(self, table: str, where: Optional[WhereParam] = None,
                  sort: Optional[OrderParam] = None) -> ResultsDict:
        """!
        Read from a table

        @param table        The table name
        @param where        Dictionary for the WHERE clause
        @param sort         List of items to be sorted. If an entry starts
                            with a dash then it will be descending
        @return A list of entries. Each entry is a dictionary.
        """
        query, args = self._form_query('select', table, where=where, sort=sort)

        ret = self.read_q(query, args)

        return ret

    def read_one(self, table: str, where: WhereParam, sort: Optional[OrderParam] = None) -> Optional[ResultDict]:
        """!
        Same as read_flat but assume there's only one result

        @return The result of None if none found
        """
        # query, args = self._form_query('select', table, where=where, sort=sort)
        #
        # r = self.read_q(query, args)
        r = self.read_flat(table, where, sort)

        if len(r) == 0:
            ret = None
        elif len(r) == 1:
            ret = r[0]
        else:
            raise VDBError(f'Found more than one results in table "{table}", where: {where}')

        return ret

    def update(self, table: str, values: ValueParam, where: WhereParam) -> int:
        """!
        Run an update on a table

        @return Number of affected rows
        """
        query, args = self._form_query('update', table, values=values, where=where)

        c = self._exec(query, args)

        return c.rowcount

    def insert(self, table: str, values: ValueParam) -> int:
        query, args = self._form_query('insert', table, values=values)

        c = self._exec(query, args)

        return c.rowcount

    def delete(self, table: str, where: WhereParam) -> int:
        if len(where) == 0:
            raise VDBError(f'Attempt to delete everything from {table}')
        query, args = self._form_query('delete', table, where=where)

        c = self._exec(query, args)

        return c.rowcount

    #    def read_NOTREADY(self, table, keys, where={}, sort=[]):
    #        """!
    #        Same as read_flat but return a dictionary instead
    #        """
    #        query, args = self._form_query(table, where, sort)
    #
    #        # TODO

    def table_exists(self, table: str) -> bool:
        """!
        Check if a table exists

        @return True if a table exists, False if not
        """
        q = f'SELECT 1 FROM {table} LIMIT 1'

        try:
            _ = self._exec(q)
            ret = True
        except psycopg2.ProgrammingError as e:
            if e.pgcode == psycopg2.errorcodes.UNDEFINED_TABLE:
                ret = False
            else:
                raise

        return ret

    def get_seq(self, sequence: str) -> int:
        """!
        @param The sequence name
        @return The current value of the sequence
        """
        query = f"SELECT CURVAL('{sequence}')"
        cur = self._exec(query, None)

        dt0 = cur.fetchall()

        ret = dt0[0][0]

        return ret

    def get_seq_next(self, sequence: str) -> int:
        """!
        Allocate a new number from a sequence

        @param The sequence name
        @return The value to use
        """
        query = f"SELECT NEXTVAL('{sequence}')"
        cur = self._exec(query, None)

        dt0 = cur.fetchall()

        ret = dt0[0][0]

        return ret

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
