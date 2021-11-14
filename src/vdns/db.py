#!/usr/bin/env python
# coding=UTF-8
#

import logging
import psycopg2
import psycopg2.extras

import vdns.common

_db = None


class NoDatabaseConnectionError(Exception):
    def __init__(self):
        Exception.__init__(self, 'No database connection')


class DB:
    def __init__(self, dbname, dbuser=None, dbpass=None,
                 dbhost=None, dbport=None):

        psycopg2.extras.register_ipaddress()

        db = psycopg2.connect(
            database=dbname,
            user=dbuser,
            password=dbpass,
            host=dbhost,
            port=dbport
        )

        if db is None:
            vdns.common.abort('Failed to connect to db')

        logging.debug('Connected to db')

        self.db = db

    def close(self):
        self.db.close()
        self.db = None

    def _read_table_raw(self, query, kwargs=None):
        """
        No logging version
        """
        cur = self.db.cursor()
        cur.execute(query, kwargs)

        ret = []
        for x in cur:
            dt = {}
            for idx in range(len(cur.description)):
                dt[cur.description[idx].name] = x[idx]
            ret.append(dt)

        return ret

    def read_table_raw(self, query, kwargs=None):
        logging.debug('Executing query: %s', query)

        res = self._read_table_raw(query, kwargs)

        return res

    def read_table(self, tbl, where=None):
        if where is None:
            where = {}
        # Construct the WHERE part
        where2 = []
        args = {}
        for k, v in where.items():
            if v is None:
                st = '%s IS NULL' % (k,)
            else:
                keyname = 'k_' + k
                st = '%s=%%(%s)s' % (k, keyname)
                args[keyname] = v
            where2.append(st)

        if where2:
            st_where = ' AND '.join(where2)
            st_where = ' WHERE ' + st_where
        else:
            st_where = ''

        query = 'SELECT * FROM %s%s' % (tbl, st_where)
        res = self._read_table_raw(query, args)

        return res

    def read_table_one(self, tbl, where):
        r = self.read_table(tbl, where)

        if len(r) > 1:
            raise Exception('Got multiple results')

        if r:
            ret = r[0]
        else:
            ret = None

        return ret

    def store_serial(self, domain, newserial):
        """
        Store a new serial number for a domain and update ts
        """
        query = 'UPDATE domains SET serial=%(newserial)s, ts=updated WHERE name=%(domain)s'
        args = {'domain': domain, 'newserial': newserial}

        cur = self.db.cursor()
        cur.execute(query, args)
        self.db.commit()

    def is_dynamic(self, domain):
        """
        Is this a domain with dynamic entries?

        @return True when a domain has at least one dynamic entry
        """
        query = 'SELECT * FROM dynamic WHERE domain=%(domain)s LIMIT 1'
        args = {'domain': domain}

        res = self._read_table_raw(query, args)

        return len(res) > 0

    def get_domain_related_data(self, tbl, domain, order=None):
        """
        Return all data from table tbl that are related to domain
        Table should have a column named domain
        """
        query = 'SELECT * FROM ' + tbl + ' WHERE domain=%(domain)s'
        if order is not None:
            query += ' ORDER BY ' + order
        args = {'domain': domain}

        res = self.read_table_raw(query, args)

        for i in res:
            if 'hostname' not in i:
                i['hostname'] = ''
            if 'ip' in i:
                i['ip_str'] = i['ip'].ip.compressed

        return res

    def get_subdomains(self, domain):
        """
        Return the direct subdomain records of a domain
        """
        query = """SELECT * FROM domains d1 WHERE name LIKE %(st)s
            AND NOT EXISTS (
                SELECT name FROM domains d2 WHERE name LIKE %(st)s
                    AND d1.name LIKE '%%.' || d2.name )"""
        args = {'st': '%.' + domain}

        res = self._read_table_raw(query, args)

        return res

    def get_domains(self):
        """!
        @return all domains
        """
        ret = self.read_table('domains')

        return ret

    def get_networks(self):
        """!
        @return all networks
        """
        ret = self.read_table('networks')

        return ret

    def get_net_hosts(self, net: vdns.common.IPNetwork):
        """
        Return all host entries that belong to that network
        """
        query = 'SELECT *, family(ip) AS family FROM hosts WHERE ip << %(net)s'
        args = {'net': net}

        res = self.read_table_raw(query, args)
        for x in res:
            x['ip_str'] = x['ip'].ip.compressed

        return res
# End of class DB


def init_db(**kwargs):
    global _db

    if _db is not None:
        _db.close()

    _db = DB(**kwargs)

    return _db


def get_db():
    global _db

    if _db is None:
        raise NoDatabaseConnectionError()

    return _db


if __name__ == '__main__':
    pass

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
