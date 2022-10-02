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

# Implements versioning for a database
# Reads the SQL schema from files that contains per-version blocks. Each file should be named major_minor.sql,
# where major/minor comprise the module name
#
# -- BEGIN: 1
# ... sql commands for version 1 here
# -- END: 1
#
# -- BEGIN: 2
#   ... Incremental sql commands for version 2
#   ... Alterations to existing tables should be in the form of ALTER
# -- END: 2
#
# Anything outside such blocks will be ignored.
#
# Inherit VersionedDB and implement the missing pieces. Each major group of modules should have a single VersionedDB.
# Each VersionedDB should list the needed upgrades in the result of _get_modules(). Order matters.
# Each upgrade step may have a callback
#
# class TestDB(VersionedDB):
#
#     def __init__(self, db: DB):
#         super().__init__(db, 'test1', 'sql/')
#
#     def _get_modules(self) -> list[tuple[str, int, Optional[Callable]]]:
#         return [
#             ('mod1', 1, None),  # Upgrade for minor module name "mod1", version 1
#             ('mod2', 1, None),  # Upgrade for minor module name "mod2", version 1
#             ('mod1', 2, self._upgrade_mod1_1_to_2),  # Upgrade for minor module name "mod1", version 2
#         ]
#
#     def _upgrade_mod1_1_to_2(self):
#        ... Use self._db in here to access the db object ...
#        ... Everything is already part of a transaction ...

from typing import Callable, Optional, Protocol, Sequence, Type

from .db import DB0
from .common import ParamDict, VDBError
from .table import Schema, Table
from .schemadb import DB

import abc
import logging
import dataclasses as dc

_MYDB = '''
-- BEGIN: 1

--
-- Table that holds all module versionsma
--

CREATE TABLE XXX_dbversions (
    major       VARCHAR(64),
    minor       VARCHAR(64),
    dbversion   INTEGER
                DEFAULT 1,
    PRIMARY KEY (major, minor)
) WITHOUT OIDS;

CREATE OR REPLACE FUNCTION func_XXX_db_set_version(varchar, varchar, integer)
    RETURNS void
    AS '
        INSERT INTO XXX_dbversions(major, minor, dbversion)
            VALUES($1, $2, $3);
    ' LANGUAGE 'sql';

-- END: 1
'''


class VersionedDBError(VDBError):
    pass


class UnfinishedBlockError(VersionedDBError):
    pass


class DBUpgradeNeededError(VersionedDBError):
    def __init__(self) -> None:
        super().__init__('Database needs to be upgraded')


class DBUpgradeFailedError(VersionedDBError):
    def __init__(self) -> None:
        super().__init__('Database upgrade failed')


@dc.dataclass
class DBVersions(Schema):
    major: str
    minor: str
    dbversion: Optional[int]


class VersionedDB(abc.ABC):
    """!
    Vadm database
    """

    _c_versions: Optional[dict[str, dict[str, int]]]
    _db: DB

    # The major module name of this VersionedDB instance
    # It is used as the major version. It is also used as the first part of the sql file names "major_minor.sql"
    _major: str

    _sql_files_dir: str

    _dbversions_table: Table[DBVersions]
    _dbversions_table_name: str
    _dbversions_table_name_prefix: str

    # A list of (minor_module_name, target_version, upgrade_callback)
    # multiple entries for the same module are permitted for different versions, in order to have separate callbacks
    # Order matters. Upgraded will happen in the listed order
    _modules: list[tuple[str, int, Optional[Callable]]]

    def __init__(self, db: DB, name: str, sql_files_dir: str, dbversions_table_name_prefix: str = 'vdb') -> None:
        """
        Params:
            db: The DB connection object
            name: A unique name for this VersionedDB. It'll be used as the "major" module name
        """
        # Caches
        self._c_versions = None
        self._db = db
        self._major = name
        self._sql_files_dir = sql_files_dir

        self._dbversions_table_name_prefix = dbversions_table_name_prefix

        self._dbversions_table_name = f'{dbversions_table_name_prefix}_dbversions'
        self._dbversions_table = db.get_table(self._dbversions_table_name, DBVersions)

        self._modules = self._get_modules()

    # ---------------------------------------------------------------------
    # Subclasses must override these

    def _get_modules(self) -> list[tuple[str, int, Optional[Callable]]]:
        raise NotImplementedError

    # ---------------------------------------------------------------------
    # Upgrade handling

    def mkfilename(self, major: str, minor: str) -> str:
        return f'{self._sql_files_dir}/{major}_{minor}.sql'

    def _readfile(self, fn: str) -> str:
        with open(fn, 'rt', encoding='utf-8') as f:
            return f.read()

    def get_versions(self, force: bool = False) -> Optional[dict[str, dict[str, int]]]:
        """!
        Return all module versions.

        @param force    Force database reread. Otherwise results may be cached
        @return A dictionary of major => minor => version
        """
        if not force and self._c_versions is not None:
            return self._c_versions

        if not self._dbversions_table.exists():
            return None

        ret: dict[str, dict[str, int]] = {}

        # Needs to read all, not just for a certain major because it's also used for upgrading dbversions.
        vers = self._dbversions_table.read_flat()

        for i in vers:
            if i.major not in ret:
                ret[i.major] = {}
            assert i.dbversion is not None
            ret[i.major][i.minor] = i.dbversion

        self._c_versions = ret

        return ret

    def get_version(self, major: str, minor: str) -> int:
        """!
        Return the current version of a module

        @return The version number (0 if not found)
        """
        vers = self.get_versions()
        if vers is None:
            ret = 0
        else:
            ret = vers.get(major, {}).get(minor, 0)

        return ret

    def set_version(self, major: str, minor: str, version: int) -> None:
        """!
        Set the module database version
        """
        k: ParamDict = {'major': major, 'minor': minor}
        v: ParamDict = {'dbversion': version}

        # r = self.update(self._dbversions_table, v, k)
        r = self._dbversions_table.update(v, k)
        if r == 0:
            v.update(k)
            # r = self.insert(self._dbversions_table, v)
            self._dbversions_table.insert(v)

    def get_sql_block(self, st: str, label: str) -> Optional[str]:
        """!
        Return the sql block that corresponds to a label from
        an SQL file

        @param st       The string to parse
        @param label    The label to look for
        @return None if no such block was found or the block contents
        """
        inblock = False
        block: Optional[str] = None
        for line in st.splitlines():
            if not inblock and line.startswith('-- BEGIN: '):
                l2 = line[9:]
                l2 = l2.strip()
                if l2 != label:
                    continue
                inblock = True
                block = ''
            elif inblock and line.startswith('-- END: '):
                l2 = line[7:]
                l2 = l2.strip()
                if l2 != label:
                    continue
                inblock = False
                break
            elif inblock:
                l2 = line.strip()
                if len(l2) == 0 or l2.startswith('--'):
                    continue
                assert block is not None
                block += line

        if inblock:
            raise UnfinishedBlockError(f'Unfinished block "{label}"')

        return block

    def needs_upgrade(self, major: str, minor: str, version: int) -> bool:
        """!
        Check whether we need an upgrade

        @param major    The major module name
        @param minor    The minor module name
        @param version  The version that the  DB should be at (integer)
        @return True or False
        """
        curver = self.get_version(major, minor)
        if curver >= version:
            return False

        return True

    def upgrade_one(self, st: str, major: str, minor: str, version: int, upgrade: bool = True,
                    cb: Optional[Callable] = None) -> bool:
        """!
        Perform an upgrade for this version if needed

        The following assumptions are made:
        - There's a file called major_minor.sql
        - The file contains a block named after the version

        @param major    The major module name
        @param minor    The minor module name
        @param version  The version to upgrade to (integer)
        @param upgrade  If False then no upgrade will be performed.
                        Instead just the status will be returned.
        @param cb       A callback to call. The callback must return True
                        for success or False for error. In case of error
                        there will be a rollback. It may be None.
        @return False if no upgrade was needed, True if it was needed
        """
        if not self.needs_upgrade(major, minor, version):
            return False
        if not upgrade:
            return True

        dt = self.get_sql_block(st, str(version))
        if dt is not None:
            ok = True
            self._db.begin()
            try:
                self._db._exec(dt)  # pylint: disable=protected-access
                self.set_version(major, minor, version)
                if cb is not None:
                    if not cb():
                        ok = False
            except Exception:
                self._db.rollback()
                raise

            if ok:
                self._db.commit()
            else:
                self._db.rollback()
                raise DBUpgradeFailedError()
        else:
            raise VersionedDBError(f'No such version for {major}:{minor}: {version}')

        # Re-read versions
        self.get_versions(force=True)

        return True

    def upgrade_one_from_file(self, major: str, minor: str, version: int, upgrade: bool = True,
                              cb: Optional[Callable] = None) -> bool:
        if not self.needs_upgrade(major, minor, version):
            return False
        if not upgrade:
            return True

        fn = self.mkfilename(major, minor)
        st = self._readfile(fn)
        return self.upgrade_one(st, major=major, minor=minor, version=version, upgrade=upgrade, cb=cb)

    def upgrade_all(self, st: str, major: str, minor: str, version: int, upgrade: bool = False,
                    cb: Optional[Callable] = None) -> bool:
        """!
        Perform an upgrade up to this version

        @return True if upgrade was needed or False if not
        """
        if not self.needs_upgrade(major, minor, version):
            return False
        if not upgrade:
            return True

        curver = self.get_version(major, minor)

        ok = True
        self._db.begin()
        try:
            for ver in range(curver + 1, version + 1):
                logging.info('Upgrading %s:%s to %s', major, minor, ver)

                dt = self.get_sql_block(st, str(ver))
                if dt is not None:
                    self._db._exec(dt)  # pylint: disable=protected-access
                    self.set_version(major, minor, ver)
                else:
                    raise VersionedDBError(f'No such version for {major}:{minor}: {ver}')

            if cb is not None:
                logging.debug('Running upgrade callback')
                if not cb():
                    logging.debug('Upgrade callback failed')
                    ok = False
        except Exception:
            # Rollback on all errors
            self._db.rollback()
            raise

        if ok:
            self._db.commit()
        else:
            self._db.rollback()
            raise DBUpgradeFailedError()

        # Re-read versions
        self.get_versions(force=True)

        return True

    def upgrade_all_from_file(self, major: str, minor: str, version: int, upgrade: bool = False,
                              cb: Optional[Callable] = None) -> bool:
        """!
        Perform an upgrade up to this version

        @return True if upgrade was needed or False if not
        """
        fn = self.mkfilename(major, minor)
        st = self._readfile(fn)
        try:
            return self.upgrade_all(st, major=major, minor=minor, version=version, upgrade=upgrade, cb=cb)
        except VersionedDBError as e:
            raise VersionedDBError(f'Failure for file "{fn}": {e}') from e

    def _do_upgrade(self, upgrade: bool) -> bool:
        """
        Check for an upgrade or actually upgrade

        @param upgrade  If true then really upgrade
        @return True if an upgrade was performed or False if not
        """
        # Order matters
        # If things need to be interleaved then it can be done.
        # E.g:
        #   ('servers', 2)
        #   ('ssh', 1)
        #   ('servers', 3)
        # This will upgrade servers to 2 then ssh to 1 then servers to 3.
        # Thus if ssh depends on servers#2 and servers#3 depends on ssh#1
        # there won't be any problem
        ret = False
        for mod, ver, cb in self._modules:
            r = self.upgrade_all_from_file(self._major, mod, ver, upgrade=upgrade, cb=cb)
            if r:
                logging.info('%s needed upgrade to version %d', mod, ver)
            ret = r or ret

        return ret

    def init_db(self) -> None:
        """!
        Initialize the database:
        - Check if an upgrade is needed
        - Exit if it's actually needed
        """
        if self._do_upgrade(False):
            logging.debug('Database needs to be upgraded')
            raise DBUpgradeNeededError()

    def upgrade_db(self) -> None:
        self._upgrade_myself()
        if self._do_upgrade(True):
            logging.info('Database was upgraded')
        else:
            logging.debug('No database upgrade needed')

    def _upgrade_myself(self) -> None:
        st = _MYDB.replace('XXX', self._dbversions_table_name_prefix)
        self.upgrade_all(st, self._dbversions_table_name_prefix, 'dbversions', version=1, upgrade=True, cb=None)


class VersionedDBSub(Protocol):

    def __init__(self, db: DB0) -> None:  # pylint: disable=super-init-not-called
        ...

    def init_db(self) -> None:
        ...

    def upgrade_db(self) -> None:
        ...


def init_db(db: DB0, vdbs: Sequence[Type[VersionedDBSub]], upgrade: bool = False) -> bool:
    """!
    Default database object initialization. Performs upgrades if needed.

    @param upgrade  If true then upgrade the database if needed
    @return True if database was upgraded, False if no upgrade was needed
    """
    ret = False

    for vdb_type in vdbs:
        vdb = vdb_type(db)
        try:
            vdb.init_db()
        except DBUpgradeNeededError:
            if upgrade:
                vdb.upgrade_db()
                vdb.init_db()
                ret = True
            else:
                raise

    return ret
