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

# pylint: disable=protected-access

import datetime
import ipaddress

import vdns.db
import vdns.common
import vdns.db_tables

from typing import Any, Optional, Sequence, Union

DBReadResults = vdns.db.DBReadResults
DBRow = vdns.db.DBReadRow
QueryArgs = vdns.db.QueryArgs

_table_columns: dict[str, tuple[str, ...]] = {
    'cnames': ('domain', 'hostname', 'hostname0', 'ttl'),
    'domains': ('name', 'reverse', 'ttl', 'refresh', 'retry', 'expire', 'minimum', 'contact', 'serial', 'ns0', 'ts',
                'updated'),
    'dynamic': ('domain', 'hostname'),
    'hosts': ('ip', 'domain', 'hostname', 'reverse', 'ttl'),
    'mx': ('domain', 'hostname', 'priority', 'mx', 'ttl'),
    'networks': ('domain', 'network'),
    'ns': ('domain', 'ns', 'ttl'),
    'sshfp': ('domain', 'hostname', 'keytype', 'hashtype', 'fingerprint', 'ttl'),
    'txt': ('domain', 'hostname', 'txt', 'ttl'),
}


class DB(vdns.db.DB):
    """Replacement class for vdns.db.DB, for tests."""

    _tables: dict[str, DBReadResults]
    _serials: dict[str, int]

    def __init__(self) -> None:
        super().__init__('testdb')

        self._tables = {
            'cnames': [],
            'dkim': [],
            'dnssec': [],
            'domains': [],
            'dynamic': [],
            'hosts': [],
            'mx': [],
            'networks': [],
            'ns': [],
            'srv': [],
            'sshfp': [],
            'txt': [],
        }
        self._serials = {}
        self._init_tables()

    def _connect(self, dbname: str, dbuser: Optional[str] = None, dbpass: Optional[str] = None,
                 dbhost: Optional[str] = None, dbport: Optional[int] = None) -> vdns.vdb.DB:
        return vdns.vdb.TestDB()

    def set_data(self, tbl: str, rows: DBReadResults) -> None:
        """Sets data for a table, removing the old ones."""
        assert self.db is not None
        assert tbl in self._tables, f'Bad table name: {tbl}'
        self._tables[tbl] = []
        for row in rows:
            self.db.insert(tbl, row)

    def set_data_tuples(self, tbl: str, rows: Sequence[Sequence[Any]]) -> None:
        """Convenience method to mass-set the data using tuples instead of dictionaries for rows."""
        assert tbl in self._tables, f'Bad table name: {tbl}'
        self._tables[tbl] = []
        for row in rows:
            self.add_data_tuple(tbl, row)

    def add_data_tuple(self, tbl: str, rows: Sequence[Any]) -> None:
        assert self.db is not None
        colnames = _table_columns[tbl]
        for row in rows:
            drow: DBRow = dict(zip(colnames, row))
            self.db.insert(tbl, drow)

    def add_host(self, ip: vdns.common.IPInterface, domain: str, hostname: str, reverse: bool = False,
                 ttl: Optional[int] = None) -> None:
        """Convenience function for adding a host entry."""
        dt: vdns.vdb.ParamDict = {'ip': ip, 'domain': domain, 'hostname': hostname, 'reverse': reverse, 'ttl': ttl}
        self.hosts.insert(dt)

    def close(self) -> None:
        pass

    def get_subdomains(self, domain: str) -> list[vdns.db_tables.Domain]:
        res = self.domains.read_flat()
        matching_domains = [x for x in res if x.name.endswith(f'.{domain}')]
        ret = []
        for r in matching_domains:
            # Skip those entries that have a longer match in the results
            if [x for x in matching_domains if x.name.endswith(f'.{r.name}')]:
                continue
            ret.append(r)
        return ret

    def get_net_hosts(self, net: vdns.common.IPNetwork) -> list[vdns.db_tables.Host]:
        ret: list[vdns.db_tables.Host] = []
        hosts = self.hosts.read_flat()
        for row in hosts:
            if row.ip in net:
                ret.append(row)
        return ret


_db: Optional[DB] = None


def init_db(**kwargs: Any) -> DB:
    """Sets vdns.db._db and returns the DB object (as vdns.db_testlib.DB and not as vdns.db.DB)."""
    global _db

    if vdns.db._db is None:
        vdns.db._db = DB(**kwargs)
        _db = vdns.db._db

    assert isinstance(vdns.db._db, DB), 'An actual DB object was instantiated.'

    return vdns.db._db


def get_db() -> DB:
    assert _db is not None, 'init_db() not called.'
    return _db


def init() -> None:
    global _db
    _db = None
    vdns.db._db = None
    vdns.db.init_db = init_db


def add_test_data() -> None:
    def subd(domain: str, serial: int, ns0: str, reverse: bool
             ) -> tuple[str, bool, datetime.timedelta, datetime.timedelta, datetime.timedelta, datetime.timedelta,
                        datetime.timedelta, str, int, str, datetime.datetime, Optional[datetime.datetime]]:
        """Helper to return a domain tuple."""
        ts = datetime.datetime.fromtimestamp(1654363945, datetime.timezone.utc)
        updated = None
        day = datetime.timedelta(days=1)
        hour = datetime.timedelta(hours=1)
        minute = datetime.timedelta(minutes=1)
        # name, reverse, ttl, refresh, retry, expire, minimum, contact, serial, ns0, ts, updated
        return (domain, reverse, day, day, hour, 30 * day, minute, f'dns.{domain}', serial, ns0, ts, updated)

    def ttl(x: int) -> datetime.timedelta:
        return datetime.timedelta(seconds=x)

    def i(x: str) -> Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface]:
        return ipaddress.ip_interface(x)

    def net(x: str) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
        return ipaddress.ip_network(x)

    # db = get_db().db
    db = get_db()
    db.add_data_tuple(
        'domains',
        # domain, serial, ns0, reverse
        [subd('v13.gr', 2022060400, 'ns1.dns.example.com', False),
         subd('dyn.v13.gr', 2022060420, 'ns1.example.com', False),
         subd('sub.v13.gr', 2022060400, 'ns1.example.com', False),
         subd('10.in-addr.arpa', 2022060400, 'ns1.dns.example.com', True),
         subd('8.b.d.0.1.0.0.2.ip6.arpa', 2022060400, 'ns1.dns.example.com', True),
         ])
    db.add_data_tuple(
        'networks',
        # ('domain', 'network'),
        [('10.in-addr.arpa', net('10.0.0.0/8')),
         ('8.b.d.0.1.0.0.2.ip6.arpa', net('2001:db8::/32')),
         ])
    db.add_data_tuple(
        'cnames',
        # ('domain', 'hostname', 'hostname0', 'ttl'),
        [('v13.gr', 'apps', 'ghs.google.com.', None),
         ('v13.gr', 'www', 'host1', None),
         ('v13.gr', 'ldap', 'host2.v13.gr.', datetime.timedelta(days=30)),
         ('sub.v13.gr', 'ns1', 'host1', None),
         ])
    db.add_data_tuple(
        'hosts',
        # ('ip', 'domain', 'hostname', 'reverse', 'ttl'),
        [(i('192.168.1.1'), 'v13.gr', '', False, ttl(3600)),
         (i('192.168.1.2'), 'v13.gr', '', False, ttl(3600)),
         (i('10.0.0.1'), 'v13.gr', '', True, None),
         (i('2001:db8:1::1'), 'v13.gr', '', True, None),
         (i('10.1.1.1'), 'v13.gr', 'host1', True, None),
         (i('10.1.1.2'), 'v13.gr', 'host2', True, ttl(3600)),
         (i('10.1.1.3'), 'v13.gr', 'host3', True, ttl(900)),
         (i('2001:db8:2c1:3212::1'), 'v13.gr', 'host3', True, ttl(900)),
         (i('2001:db8:2c1:12::1'), 'v13.gr', 'host3', True, None),
         (i('2001:db8:2c1:13::1'), 'v13.gr', 'host4', False, None),  # Two hostnames with the same IP
         (i('2001:db8:2c1:13::1'), 'v13.gr', 'host5', True, None),
         (i('10.1.2.1'), 'sub.v13.gr', 'host1', True, None),
         (i('10.1.2.2'), 'sub.v13.gr', 'ns2', True, None),
         ])
    db.add_data_tuple(
        'sshfp',
        # ('domain', 'hostname', 'keytype', 'hashtype', 'fingerprint', 'ttl'),
        [('v13.gr', 'host3', 1, 1, '1234567890abcdef1234567890abcdef12345678', None),
         ('v13.gr', 'host3', 2, 1, '01234567890abcdef1234567890abcdef1234567', None),
         ('v13.gr', 'host100', 1, 1, '234567890abcdef1234567890abcdef123456789', None),  # Non-existent host
         ])
    db.add_data_tuple(
        'txt',
        # ('domain', 'hostname', 'txt', 'ttl'),
        [('v13.gr', '', 'v=spf1 include:_spf.google.com ~all', None),
         ('v13.gr', 'host3', 'v=spf1 include:_spf.google.com ~all', None),
         ('v13.gr', 'host100', 'v=spf1 include:_spf.google.com ~all', None),
         ])
    db.add_data_tuple(
        'ns',
        # ('domain', 'ns', 'ttl'),
        [('v13.gr', 'ns1.dns.example.com', datetime.timedelta(hours=1)),
         ('v13.gr', 'ns2.dns.example.com', datetime.timedelta(hours=1)),
         ('sub.v13.gr', 'ns1.sub.v13.gr', ttl(300)),  # cname glue
         ('sub.v13.gr', 'ns2.sub.v13.gr', ttl(300)),  # non-cname glue
         ('sub.v13.gr', 'ns3.example.com', ttl(300)),  # non-glue
         ('dyn.v13.gr', 'ns1.example.com', ttl(300)),
         ('dyn.v13.gr', 'ns2.example.com', ttl(300)),
         ('10.in-addr.arpa', 'ns1.dns.example.com', datetime.timedelta(days=1)),
         ])
    db.add_data_tuple(
        'mx',
        # ('domain', 'hostname', 'priority', 'mx', 'ttl'),
        [('v13.gr', '', 1, 'aspmx.l.google.com.', ttl(3600)),
         ('v13.gr', '', 5, 'alt1.aspmx.l.google.com.', ttl(3600)),
         ('v13.gr', '', 5, 'alt2.aspmx.l.google.com.', ttl(3600)),
         ])
    db.add_data_tuple(
        'dynamic',
        # ('domain', 'hostname'),
        [('dyn.v13.gr', 'host1')]
    )
