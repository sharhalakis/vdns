# pylint: disable=protected-access

import copy
import datetime
import ipaddress
import unittest.mock
import psycopg2.extensions

import vdns.db
import vdns.common

from typing import Any, Optional, Sequence, Union

DBReadResults = vdns.db.DBReadResults
DBRow = vdns.db.DBReadRow
QueryArgs = vdns.db.QueryArgs

_table_columns: dict[str, tuple[str, ...]] = {
    'cnames': ('domain', 'hostname', 'hostname0', 'ttl'),
    'domains': ('name', 'ttl', 'refresh', 'retry', 'expire', 'minimum', 'contact', 'serial', 'ns0', 'ts',
                'reverse', 'updated'),
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
        # pylint: disable=super-init-not-called
        self.db = unittest.mock.create_autospec(psycopg2.extensions.connection)

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

    def set_data(self, tbl: str, rows: DBReadResults) -> None:
        """Sets data for a table, removing the old ones."""
        assert tbl in self._tables, f'Bad table name: {tbl}'
        self._tables[tbl] = []
        for row in rows:
            self.add_data(tbl, row)

    def set_data_tuples(self, tbl: str, rows: Sequence[Sequence[Any]]) -> None:
        """Convenience method to mass-set the data using tuples instead of dictionaries for rows."""
        assert tbl in self._tables, f'Bad table name: {tbl}'
        self._tables[tbl] = []
        for row in rows:
            self.add_data_tuple(tbl, row)

    def add_data_tuple(self, tbl: str, row: Sequence[Any]) -> None:
        colnames = _table_columns[tbl]
        drow: DBRow = dict(zip(colnames, row))
        self.add_data(tbl, drow)

    def add_data(self, tbl: str, row: DBRow) -> None:
        """Adds a row to a table while taking care of some standard type conversions."""
        assert tbl in self._tables, f'Bad table name: {tbl}'
        dt: DBRow = {}
        for k, v in row.items():
            if v is None:
                dt[k] = None
                continue

            if k in ('ttl', 'refresh', 'retry', 'expire', 'minimum'):
                if isinstance(v, datetime.timedelta):
                    dt[k] = v
                elif isinstance(v, int):
                    dt[k] = datetime.timedelta(seconds=v)
            elif k == 'ip':
                if isinstance(v, str):
                    dt[k] = ipaddress.ip_address(v)
                elif isinstance(v, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    dt[k] = v
            elif k == 'network':
                if isinstance(v, str):
                    dt[k] = ipaddress.ip_network(v)
                elif isinstance(v, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                    dt[k] = v
            elif k in ('ts', 'updated'):
                if isinstance(v, datetime.datetime):
                    dt[k] = v
                elif isinstance(v, (int, float)):
                    dt[k] = datetime.datetime.fromtimestamp(v)
            else:
                dt[k] = v

            # Fail if we failed to set the value
            if dt.get(k) is None:
                raise Exception(f'Bad type {type(v)} for column "{k}"')

        self._tables[tbl].append(dt)

    def add_host(self, ip: Union[str, vdns.common.IPAddress], domain: str, hostname: str, reverse: bool = False,
                 ttl: Optional[int] = None) -> None:
        """Convenience function for adding a host entry."""
        dt = {'ip': ip, 'domain': domain, 'hostname': hostname, 'reverse': reverse, 'ttl': ttl}
        self.add_data('hosts', dt)

    def close(self) -> None:
        pass

    def _read_table_raw(self, query: str, kwargs: Optional[QueryArgs] = None) -> DBReadResults:
        raise Exception('Should not have been called')

    def read_table_raw(self, query: str, kwargs: Optional[QueryArgs] = None) -> DBReadResults:
        raise Exception('Should not have been called')

    def read_table(self, tbl: str, where: Optional[QueryArgs] = None) -> DBReadResults:
        if tbl not in self._tables:
            raise Exception(f'No such table: {tbl}')

        ret: DBReadResults = []
        data = self._tables[tbl]
        if not where:
            return data

        for row in data:
            skip = False
            for k, v in where.items():
                # If a key is not found in a row then something is wrong
                if k not in row:
                    raise Exception(f'Key "{k}" not found in row {row}')
                if v != row.get(k):
                    skip = True
                    break
            if skip:
                continue
            ret.append(row)

        return ret

    def store_serial(self, domain: str, newserial: int) -> None:
        dt = self.read_table_one('domains', {'name': domain})
        if not dt:
            raise Exception(f'Unknown domain:{domain}')
        dt['serial'] = newserial

    def is_dynamic(self, domain: str) -> bool:
        dt = self.read_table_one('dynamic', {'domain': domain})
        return bool(dt)

    def get_domain_related_data(self, tbl: str, domain: str, order: Optional[str] = None) -> DBReadResults:
        dt = self.read_table(tbl, {'domain': domain})
        if not dt:
            return dt

        def _key(a: DBRow) -> tuple[Any, ...]:
            assert order is not None
            ret = a[order]
            if isinstance(ret, ipaddress.IPv4Address):
                ret = ipaddress.IPv6Address(f'::{ret.compressed}')
            return ret

        if order:
            dt.sort(key=_key)

        return dt

    def get_subdomains(self, domain: str) -> DBReadResults:
        ret: DBReadResults = []
        for row in self._tables['domains']:
            if not row['name'].endswith(f'.{domain}'):
                continue
            ret.append(row)
        # This fails if there is dom.com, sub.dom.com and sub2.sub.dom.com, in which case it will return
        # both sub.dom.com and sub2.sub.dom.com as subdomains of dom.com
        return ret

    def get_net_hosts(self, net: vdns.common.IPNetwork) -> DBReadResults:
        ret = []
        for row in self._tables['hosts']:
            if row['ip'] in net:
                r = copy.copy(row)
                r['ip'] = self.fixip(r['ip'])
                r['ip_str'] = r['ip'].compressed
                ret.append(r)
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
    def subd(domain: str, serial: int, ns0: str, reverse: bool, ts: Optional[int]
             ) -> tuple[str, int, int, int, int, int, str, int, str, int, bool, Optional[int]]:
        """Helper to return a domain tuple."""
        return (domain, 86400, 86400, 3600, 30 * 86400, 60, f'dns.{domain}', serial, ns0, 1654363945, reverse, ts)

    db = get_db()
    db.set_data_tuples(
        'domains',
        # ('name', 'ttl', 'refresh', 'retry', 'expire', 'minimum', 'contact', 'serial', 'ns0', 'ts', 'reverse', 'updated'),
        [subd('v13.gr', 2022060400, 'ns1.dns.example.com', False, None),
         subd('dyn.v13.gr', 2022060420, 'ns1.example.com', False, None),
         subd('sub.v13.gr', 2022060400, 'ns1.example.com', False, None),
         subd('10.in-addr.arpa', 2022060400, 'ns1.dns.example.com', True, None),
         subd('8.b.d.0.1.0.0.2.ip6.arpa', 2022060400, 'ns1.dns.example.com', True, None),
         ])
    db.set_data_tuples(
        'networks',
        # ('domain', 'network'),
        [('10.in-addr.arpa', '10.0.0.0/8'),
         ('8.b.d.0.1.0.0.2.ip6.arpa', '2001:db8::/32'),
         ])
    db.set_data_tuples(
        'cnames',
        # ('domain', 'hostname', 'hostname0', 'ttl'),
        [('v13.gr', 'apps', 'ghs.google.com.', None),
         ('v13.gr', 'www', 'host1', None),
         ('v13.gr', 'ldap', 'host2.v13.gr.', datetime.timedelta(days=30)),
         ('sub.v13.gr', 'ns1', 'host1', None),
         ])
    db.set_data_tuples(
        'hosts',
        # ('ip', 'domain', 'hostname', 'reverse', 'ttl'),
        [('192.168.1.1', 'v13.gr', '', False, 3600),
         ('192.168.1.2', 'v13.gr', '', False, 3600),
         ('10.0.0.1', 'v13.gr', '', True, None),
         ('2001:db8:1::1', 'v13.gr', '', True, None),
         ('10.1.1.1', 'v13.gr', 'host1', True, None),
         ('10.1.1.2', 'v13.gr', 'host2', True, 3600),
         ('10.1.1.3', 'v13.gr', 'host3', True, 900),
         ('2001:db8:2c1:3212::1', 'v13.gr', 'host3', True, 900),
         ('2001:db8:2c1:12::1', 'v13.gr', 'host3', True, None),
         ('2001:db8:2c1:13::1', 'v13.gr', 'host4', False, None),  # Two hostnames with the same IP
         ('2001:db8:2c1:13::1', 'v13.gr', 'host5', True, None),
         ('10.1.2.1', 'sub.v13.gr', 'host1', True, None),
         ('10.1.2.2', 'sub.v13.gr', 'ns2', True, None),
         ])
    db.set_data_tuples(
        'sshfp',
        # ('domain', 'hostname', 'keytype', 'hashtype', 'fingerprint', 'ttl'),
        [('v13.gr', 'host3', 1, 1, '1234567890abcdef1234567890abcdef12345678', None),
         ('v13.gr', 'host3', 2, 1, '01234567890abcdef1234567890abcdef1234567', None),
         ('v13.gr', 'host100', 1, 1, '234567890abcdef1234567890abcdef123456789', None),  # Non-existent host
         ])
    db.set_data_tuples(
        'txt',
        # ('domain', 'hostname', 'txt', 'ttl'),
        [('v13.gr', '', 'v=spf1 include:_spf.google.com ~all', None),
         ('v13.gr', 'host3', 'v=spf1 include:_spf.google.com ~all', None),
         ('v13.gr', 'host100', 'v=spf1 include:_spf.google.com ~all', None),
         ])
    db.set_data_tuples(
        'ns',
        # ('domain', 'ns', 'ttl'),
        [('v13.gr', 'ns1.dns.example.com', datetime.timedelta(hours=1)),
         ('v13.gr', 'ns2.dns.example.com', datetime.timedelta(hours=1)),
         ('sub.v13.gr', 'ns1.sub.v13.gr', 300),  # cname glue
         ('sub.v13.gr', 'ns2.sub.v13.gr', 300),  # non-cname glue
         ('sub.v13.gr', 'ns3.example.com', 300),  # non-glue
         ('dyn.v13.gr', 'ns1.example.com', 300),
         ('dyn.v13.gr', 'ns2.example.com', 300),
         ('10.in-addr.arpa', 'ns1.dns.example.com', datetime.timedelta(days=1)),
         ])
    db.set_data_tuples(
        'mx',
        # ('domain', 'hostname', 'priority', 'mx', 'ttl'),
        [('v13.gr', '', 1, 'aspmx.l.google.com.', 3600),
         ('v13.gr', '', 5, 'alt1.aspmx.l.google.com.', 3600),
         ('v13.gr', '', 5, 'alt2.aspmx.l.google.com.', 3600),
         ])
    db.set_data_tuples(
        'dynamic',
        # ('domain', 'hostname'),
        [('dyn.v13.gr', 'host1')]
    )
