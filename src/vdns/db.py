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

import logging
import argparse
import dataclasses as dc

from vdns import db_tables
import vdns.vdb
import vdns.util.config
import vdns.common

from typing import Any, Optional

_db: Optional['DB'] = None


class NoDatabaseConnectionError(Exception):
    def __init__(self) -> None:
        Exception.__init__(self, 'No database connection')


@dc.dataclass
class _Config:
    dbname: str = 'dns'
    dbuser: Optional[str] = None
    dbpass: Optional[str] = None
    dbhost: Optional[str] = None
    dbport: int = 5432


DBReadRow = dict[str, Any]
DBReadResults = list[DBReadRow]
QueryArgs = dict[str, Any]

Table = vdns.vdb.Table


class DB:
    db: Optional[vdns.vdb.DB]

    cnames: Table[db_tables.CName]
    domains: Table[db_tables.Domain]
    dkim: Table[db_tables.DKIM]
    dnssec: Table[db_tables.DNSSEC]
    dynamic: Table[db_tables.Dynamic]
    hosts: Table[db_tables.Host]
    mx: Table[db_tables.MX]
    networks: Table[db_tables.Network]
    ns: Table[db_tables.NS]
    srv: Table[db_tables.SRV]
    sshfp: Table[db_tables.SSHFP]
    txt: Table[db_tables.TXT]

    net_hosts: Table[db_tables.Host]
    subdomains: Table[db_tables.Domain]

    def __init__(self, dbname: str, dbuser: Optional[str] = None, dbpass: Optional[str] = None,
                 dbhost: Optional[str] = None, dbport: Optional[int] = None) -> None:

        db = self._connect(dbname=dbname, dbuser=dbuser, dbpass=dbpass, dbhost=dbhost, dbport=dbport)
        logging.debug('Connected to db')

        self.db = db
        self._init_tables()

    def _connect(self, dbname: str, dbuser: Optional[str] = None, dbpass: Optional[str] = None,
                 dbhost: Optional[str] = None, dbport: Optional[int] = None) -> vdns.vdb.DB:
        try:
            ret = vdns.vdb.DB(dbname=dbname, dbuser=dbuser, dbpass=dbpass, dbhost=dbhost, dbport=dbport)
        except vdns.vdb.VDBError:
            vdns.common.abort('Failed to connect to db')
        return ret

    def _init_tables(self) -> None:
        assert self.db is not None
        db = self.db
        self.cnames = db.get_table('cnames', db_tables.CName)
        self.domains = db.get_table('domains', db_tables.Domain)
        self.dkim = db.get_table('dkim', db_tables.DKIM)
        self.dnssec = db.get_table('dnssec', db_tables.DNSSEC)
        self.dynamic = db.get_table('dynamic', db_tables.Dynamic)
        self.hosts = db.get_table('hosts', db_tables.Host)
        self.mx = db.get_table('mx', db_tables.MX)
        self.networks = db.get_table('networks', db_tables.Network)
        self.ns = db.get_table('ns', db_tables.NS)
        self.srv = db.get_table('srv', db_tables.SRV)
        self.sshfp = db.get_table('sshfp', db_tables.SSHFP)
        self.txt = db.get_table('txt', db_tables.TXT)

        self.net_hosts = vdns.vdb.QueryTable(db, db_tables.Host)
        self.subdomains = vdns.vdb.QueryTable(db, db_tables.Domain)

    def close(self) -> None:
        if self.db is not None:
            self.db.close()
            self.db = None

    def store_serial(self, domain: str, newserial: int) -> None:
        """
        Store a new serial number for a domain and update ts
        """
        query = 'UPDATE domains SET serial=%(newserial)s, ts=updated WHERE name=%(domain)s'
        args: vdns.vdb.WhereParam = {'domain': domain, 'newserial': newserial}

        assert self.db is not None
        self.db.exec(query, args)

    def is_dynamic(self, domain: str) -> bool:
        """
        Is this a domain with dynamic entries?

        @return True when a domain has at least one dynamic entry
        """
        res = self.dynamic.read_one({'domain': domain})
        return bool(res)

    def get_subdomains(self, domain: str) -> list[db_tables.Domain]:
        """
        Return the direct subdomain records of a domain
        """
        query = """SELECT * FROM domains d1 WHERE name LIKE %(st)s
            AND NOT EXISTS (
                SELECT name FROM domains d2 WHERE name LIKE %(st)s
                    AND d1.name LIKE '%%.' || d2.name )"""
        args = {'st': '%.' + domain}

        res = self.subdomains.read_q(query, args)

        return res

    def get_domains(self) -> list[db_tables.Domain]:
        """!
        @return all domains
        """
        return self.domains.read_flat()

    def get_networks(self) -> list[db_tables.Network]:
        """!
        @return all networks
        """
        return self.networks.read_flat()

    def get_net_hosts(self, net: vdns.common.IPNetwork) -> list[vdns.db_tables.Host]:
        """
        Return all host entries that belong to that network
        """
        query = 'SELECT * FROM hosts WHERE ip << %(net)s'
        args: vdns.vdb.WhereParam = {'net': net}

        res = self.hosts.read_q(query, args)  # TODO: IPNetwork is valid for Where

        return res


def add_args(parser: argparse.ArgumentParser) -> None:
    """Helper to be used by modules that want a DB connections."""
    config = _Config()
    vdns.util.config.set_module_config('db', config)

    parser.add_argument('--dbname', default=config.dbname, help='Database name (def: %(default)s)')
    parser.add_argument('--dbuser', default=config.dbuser, help='Database user (def: %(default)s)')
    parser.add_argument('--dbhost', default=config.dbhost, help='Database host (def: %(default)s)')
    parser.add_argument('--dbport', default=config.dbport, help='Database port (def: %(default)s)')


def handle_args(args: argparse.Namespace) -> None:
    """Helper to be used by modules that want a DB connections."""
    config = vdns.util.config.get_config()

    config.dbname = args.dbname
    config.dbuser = args.dbuser
    config.dbhost = args.dbhost
    config.dbport = args.dbport


def init_db() -> DB:
    global _db

    if _db is not None:
        _db.close()

    config = vdns.util.config.get_config()

    _db = DB(
        dbname=config.dbname,
        dbuser=config.dbuser,
        dbhost=config.dbhost,
        dbport=config.dbport,
    )

    return _db


def get_db() -> DB:
    if _db is None:
        raise NoDatabaseConnectionError()

    return _db

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
