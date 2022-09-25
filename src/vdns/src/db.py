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

import time
import logging
import vdns.db
import vdns.rr
import vdns.src.src0
import vdns.vdb
import vdns.common
import vdns.db_tables

from typing import Optional, Type


class DB(vdns.src.src0.Source):
    """Implements the db-based datasource."""
    db: vdns.db.DB

    def __init__(self, domain: str):
        vdns.src.src0.Source.__init__(self, domain)
        db = vdns.db.get_db()
        self.db = db

    def _get_domain_related_data(self, rr: Type[vdns.rr.T_RR_SOA], source: vdns.vdb.Table,
                                 domain: str) -> list[vdns.rr.T_RR_SOA]:
        dt = source.read_flat({'domain': domain})
        return [rr.from_db_record(x) for x in dt]  # type: ignore

    def _get_hosts(self) -> list[vdns.db.db_tables.Host]:
        """Returns the host entries taking care of dynamic entries

        Dynamic entries that exist in the hosts table will not be included.
        Dynamic entries will get their values from the zone file
        """
        return self.db.hosts.read_flat({'domain': self.domain}, sort=['ip'])

    def get_data(self) -> Optional[vdns.src.src0.DomainData]:
        dom = self.domain

        logging.debug('Reading data for: %s', dom)

        # Get zone data
        domain = self.db.domains.read_one({'name': dom})
        network = self.db.networks.read_one({'domain': dom})

        if domain is None:
            logging.debug('No domain data for %s', dom)
            return None

        if network:
            logging.debug('This is a network zone')

        serial = domain.serial or 1
        ret = vdns.src.src0.DomainData(serial=serial)

        if domain.reverse:
            if network is None:
                raise Exception(f'Reverse domain "{dom} without a network entry')
            ret.name = vdns.common.reverse_name(network.network.compressed)
            ret.network = network.network
            hosts = self.db.get_net_hosts(network.network)
        else:
            ret.name = dom
            hosts = self._get_hosts()

        ret.hosts = [vdns.rr.Host.from_db_record(x) for x in hosts]
        ret.soa = vdns.rr.SOA.from_db_record(domain)
        ret.cnames = self._get_domain_related_data(vdns.rr.CNAME, self.db.cnames, dom)
        ret.ns = self._get_domain_related_data(vdns.rr.NS, self.db.ns, dom)
        ret.mx = self._get_domain_related_data(vdns.rr.MX, self.db.mx, dom)
        ret.dnssec = self._get_domain_related_data(vdns.rr.DNSSEC, self.db.dnssec, dom)
        ret.txt = self._get_domain_related_data(vdns.rr.TXT, self.db.txt, dom)
        ret.sshfp = self._get_domain_related_data(vdns.rr.SSHFP, self.db.sshfp, dom)
        ret.dkim = self._get_domain_related_data(vdns.rr.DKIM, self.db.dkim, dom)
        ret.srv = self._get_domain_related_data(vdns.rr.SRV, self.db.srv, dom)

        # Also store subdomains
        subs = self.db.get_subdomains(dom)
        ret.subdomains = [x.name for x in subs]

        return ret

    def has_changed(self) -> bool:
        domain = self.domain

        dt = self.db.domains.read_one({'name': domain})
        assert dt is not None

        # old=dt['serial']

        if dt.ts is None:
            ts = 0
        else:
            ts = int(time.mktime(dt.ts.timetuple()))

        if dt.updated is None:
            updated = 0
        else:
            updated = int(time.mktime(dt.updated.timetuple()))

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

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
