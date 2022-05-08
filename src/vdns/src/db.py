#!/usr/bin/env python3
# coding=UTF-8
#
import time
import logging
import datetime
import dataclasses as dc

import vdns.db
import vdns.rr
import vdns.common
import vdns.src.src0


@dc.dataclass
class DBDNSSEC(vdns.rr.DNSSEC):
    id: int     # Internal id, not exported


@dc.dataclass
class DBDomain(vdns.rr.Domain):
    reverse: bool = False
    ts: int = 0
    updated: int = 0
    # ts: datetime.datetime = datetime.datetime.fromtimestamp(0)
    # updated: datetime.datetime = datetime.date.fromtimestamp(0)


class DB(vdns.src.src0.Source):
    def __init__(self, domain):
        vdns.src.src0.Source.__init__(self, domain)
        self.db = vdns.db.get_db()

    def _get_hosts(self):
        """
        Return the host entries taking care of dynamic entries

        Dynamic entries that exist in the hosts table will not be included.
        Dynamic entries will get their values from the zone file
        """
        # Get hosts
        hosts = self.db.get_domain_related_data('hosts', self.domain, 'ip')

        return hosts

    def get_data(self):
        return self.get_data_test()

    # Testing for vdns.rr
    def get_data_test(self):
        dom = self.domain

        logging.debug('Reading data for: %s', dom)

        # Get zone data
        domain = self.db.read_table_one('domains', {'name': dom})
        network = self.db.read_table_one('networks', {'domain': dom})

        if network:
            logging.debug('This is a network zone')

        def _mk(rrtype, data):
            return [vdns.rr.make_rr(rrtype, x) for x in data]

        tablemap = {'cnames': vdns.rr.CNAME,
                    'ns': vdns.rr.NS,
                    'mx': vdns.rr.MX,
                    'dnssec': DBDNSSEC,
                    'txt': vdns.rr.TXT,
                    'sshfp': vdns.rr.SSHFP,
                    'dkim': vdns.rr.DKIM,
                    'srv': vdns.rr.SRV,
                    }

        domain['cnames'] = self.db.get_domain_related_data('cnames', dom)
        domain['ns'] = self.db.get_domain_related_data('ns', dom)
        domain['mx'] = self.db.get_domain_related_data('mx', dom)
        domain['dnssec'] = self.db.get_domain_related_data('dnssec', dom)
        domain['txt'] = self.db.get_domain_related_data('txt', dom)
        domain['sshfp'] = self.db.get_domain_related_data('sshfp', dom)
        domain['dkim'] = self.db.get_domain_related_data('dkim', dom)
        domain['srv'] = self.db.get_domain_related_data('srv', dom)

        def convert_datetime(v):
            """psycopg2 returns datetime objects. Convert them to seconds (epoch or deltas)."""
            if isinstance(v, datetime.datetime):
                ret = int(v.timestamp())
            elif isinstance(v, datetime.timedelta):
                ret = int(v.total_seconds())
            else:
                ret = v
            return ret

        def convert_datetime_dict(dt):
            return {k: convert_datetime(v) for k, v in dt.items()}

        soa = vdns.rr.make_rr(vdns.rr.SOA, convert_datetime_dict(domain))
        domain2 = {'soa': soa}
        for rrname, data in domain.items():
            if rrname not in tablemap:
                continue
            rrclass = tablemap[rrname]
            domain2[rrname] = [vdns.rr.make_rr(rrclass, convert_datetime_dict(v)) for v in data]
        # print(domain2)

        # print()
        # print('domain2:', domain2)

        if domain['reverse']:
            net = network['network']
            domain['_domain'] = vdns.common.reverse_name(net)
            domain['hosts'] = self.db.get_net_hosts(net)
            domain['network'] = net
        else:
            domain['_domain'] = dom
            domain['hosts'] = self._get_hosts()
            domain['network'] = None

        # Also store subdomains
        subs = self.db.get_subdomains(dom)
        domain['subs'] = subs

        ret = domain

        return ret

    def get_data_orig(self):
        dom = self.domain

        logging.debug('Reading data for: %s', dom)

        # Get zone data
        domain = self.db.read_table_one('domains', {'name': dom})
        network = self.db.read_table_one('networks', {'domain': dom})

        if network:
            logging.debug('This is a network zone')

        domain['cnames'] = self.db.get_domain_related_data('cnames', dom)
        domain['ns'] = self.db.get_domain_related_data('ns', dom)
        domain['mx'] = self.db.get_domain_related_data('mx', dom)
        domain['dnssec'] = self.db.get_domain_related_data('dnssec', dom)
        domain['txt'] = self.db.get_domain_related_data('txt', dom)
        domain['sshfp'] = self.db.get_domain_related_data('sshfp', dom)
        domain['dkim'] = self.db.get_domain_related_data('dkim', dom)
        domain['srv'] = self.db.get_domain_related_data('srv', dom)

        if domain['reverse']:
            net = network['network']
            domain['_domain'] = vdns.common.reverse_name(net)
            domain['hosts'] = self._get_net_hosts(net)
            domain['network'] = net
        else:
            domain['_domain'] = dom
            domain['hosts'] = self._get_hosts()
            domain['network'] = None

        # Also store subdomains
        subs = self.db.get_subdomains(dom)
        domain['subs'] = subs

        ret = domain

        return ret

    def has_changed(self):
        domain = self.domain

        dt = self.db.read_table_one('domains', {'name': domain})

        # old=dt['serial']

        ts0 = dt['ts']
        updated0 = dt['updated']

        if ts0 is None:
            ts = 0
        else:
            ts = int(time.mktime(ts0.timetuple()))

        if updated0 is None:
            updated = 0
        else:
            updated = int(time.mktime(updated0.timetuple()))

        if updated <= ts:
            ret = False
        else:
            ret = True

        return ret

    def incserial(self, oldserial):
        """! Increment the serial number if needed.

        @param oldserial    Old serial (ignored)
        @return the current (new) serial number
        """
        ret = self.incserial_date(oldserial)

        return ret

    def set_serial(self, serial):
        domain = self.domain

        logging.debug('Storing serial number for %s: %s', domain, serial)

        self.db.store_serial(domain, serial)

# End of class DB

# if __name__=="__main__":
#     vdns.db.init_db(
#         dbname  = 'dns',
#         dbuser  = 'v13',
#         dbhost  = 'my.db.host'
#     )
#
#     import pprint
#
# #    db=DB('10.in-addr.arpa')
#     db=DB('example.com')
#     dt=db.get_data()
#
# #    pprint.pprint(dt)

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
