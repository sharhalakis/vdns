#!/usr/bin/env python3
# coding=UTF-8
#
import time
import logging
import vdns.db
import vdns.rr
import vdns.common
import vdns.src.src0

from typing import Any, Optional, Type, TypeVar, Union


# Maps DB tables to RR records for get_domain_related_data
RR_TABLEMAP: dict[str, Type[vdns.rr.RR]] = {
    'cnames': vdns.rr.CNAME,
    'dkim': vdns.rr.DKIM,
    'dnssec': vdns.rr.DNSSEC,
    # 'domain': vdns.rr.SOA,
    'hosts': vdns.rr.Host,
    'mx': vdns.rr.MX,
    'ns': vdns.rr.NS,
    'srv': vdns.rr.SRV,
    'sshfp': vdns.rr.SSHFP,
    'txt': vdns.rr.TXT,
}


# @dc.dataclass
# class DBDNSSEC(vdns.rr.DNSSEC):
#     id: int     # Internal id, not exported


# @dc.dataclass
# class DBDomainData(vdns.src.src0.DomainData):
#     # reverse: bool = False
#     ts: int = 0
#     updated: int = 0
#     # ts: datetime.datetime = datetime.datetime.fromtimestamp(0)
#     # updated: datetime.datetime = datetime.date.fromtimestamp(0)

T_RR_SOA = TypeVar('T_RR_SOA', bound=Union[vdns.rr.RR, vdns.rr.SOA])


class DB(vdns.src.src0.Source):
    db: vdns.db.DB

    def __init__(self, domain: str):
        vdns.src.src0.Source.__init__(self, domain)
        self.db = vdns.db.get_db()

    def _mkrr(self, data: vdns.db.DBReadResults, rrtype: Type[vdns.rr.T_RR_SOA]) -> list[vdns.rr.T_RR_SOA]:
        """Converts a list of results to RR records, converting datetime entries first."""
        return [vdns.rr.make_rr(rrtype, x) for x in data]

    # TODO: Figure out how to return a non-Any
    def _get_domain_related_data(self, tbl: str, domain: str, order: Optional[str] = None) -> Any:
        """Gets db data and returns RR records."""
        if tbl not in RR_TABLEMAP:
            raise Exception(f'Unknown table {tbl}')
        data = self.db.get_domain_related_data(tbl, domain, order)
        return self._mkrr(data, RR_TABLEMAP[tbl])

    def _get_hosts(self) -> vdns.db.DBReadResults:
        """Returns the host entries taking care of dynamic entries

        Dynamic entries that exist in the hosts table will not be included.
        Dynamic entries will get their values from the zone file
        """
        # Get hosts
        hosts = self.db.get_domain_related_data('hosts', self.domain, 'ip')

        return hosts

    def get_data(self) -> Optional[vdns.src.src0.DomainData]:
        dom = self.domain

        logging.debug('Reading data for: %s', dom)

        # Get zone data
        domain = self.db.read_table_one('domains', {'name': dom})
        network = self.db.read_table_one('networks', {'domain': dom})

        if domain is None:
            logging.debug('No domain data for %s', dom)
            return None

        if network:
            logging.debug('This is a network zone')

        ret = vdns.src.src0.DomainData(serial=domain['serial'])

        if domain['reverse']:
            if network is None:
                raise Exception(f'Reverse domain "{dom} without a network entry')
            ret.name = vdns.common.reverse_name(network['network'])
            ret.network = network['network']
            hosts = self.db.get_net_hosts(network['network'])
        else:
            ret.name = dom
            hosts = self._get_hosts()

        ret.hosts = self._mkrr(hosts, vdns.rr.Host)
        ret.soa = vdns.rr.make_rr(vdns.rr.SOA, domain)
        ret.cnames = self._get_domain_related_data('cnames', dom)
        ret.ns = self._get_domain_related_data('ns', dom)
        ret.mx = self._get_domain_related_data('mx', dom)
        ret.dnssec = self._get_domain_related_data('dnssec', dom)
        ret.txt = self._get_domain_related_data('txt', dom)
        ret.sshfp = self._get_domain_related_data('sshfp', dom)
        ret.dkim = self._get_domain_related_data('dkim', dom)
        ret.srv = self._get_domain_related_data('srv', dom)

        # Also store subdomains
        subs = self.db.get_subdomains(dom)
        ret.subdomains = self._mkrr(subs, vdns.rr.SOA)

        return ret

    def has_changed(self) -> bool:
        domain = self.domain

        dt = self.db.read_table_one('domains', {'name': domain})
        assert dt is not None

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

    def incserial(self, oldserial: int) -> int:
        """! Increment the serial number if needed.

        @param oldserial    Old serial (ignored)
        @return the current (new) serial number
        """
        ret = self.incserial_date(oldserial)

        return ret

    def set_serial(self, serial: int) -> None:
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
