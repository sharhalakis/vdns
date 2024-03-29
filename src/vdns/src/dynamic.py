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

import os
import errno
import logging

import vdns.db
import vdns.rr
import vdns.common
import vdns.src.src0
import vdns.db_tables
import vdns.zoneparser

from typing import Optional


class NoSuchZoneFileError(OSError):
    def __init__(self, fn: str) -> None:
        err = errno.ENOENT
        st = os.strerror(err)
        OSError.__init__(self, err, st, fn)


class Dynamic(vdns.src.src0.Source):
    """! Dynamic zone handling """

    db: vdns.db.DB
    zonedir: str
    zonefile: str

    def __init__(self, domain: str, zonedir: str, zonefile: str) -> None:
        """!
        @param domain   The domain name
        @param zonedir  The directory that holds the zone files
        @param zonefile The existing zone file to read for dynamic entries.
                        This is relative to the zonedir. Defaults to the
                        domain name
        """
        vdns.src.src0.Source.__init__(self, domain)
        self.db = vdns.db.get_db()
        self.zonedir = zonedir
        self.zonefile = zonefile

    def get_dynamic(self) -> list[vdns.db_tables.Dynamic]:
        """
        Return the dynamic entries of a domain
        """
        # res = self.db.get_domain_related_data('dynamic', self.domain)
        res = self.db.dynamic.read_flat({'domain': self.domain})

        return res

    def read_zone_file(self) -> vdns.src.src0.DomainData:
        """
        Read the contents of a zone file and return them in a processed
        form as returned by ZoneInfo.data()

        @return The data or None if the file failed to open / doesn't exist
        """
        fn = self.zonedir + '/' + self.zonefile

        if not os.path.exists(fn):
            raise NoSuchZoneFileError(fn)

        z = vdns.zoneparser.ZoneParser(fn, self.domain)
        ret = z.data()

        return ret

    def read_dynamic(self) -> dict[str, dict[str, list[vdns.rr.Host]]]:
        """
        Read dynamic IP addresses from existing files

        Returns a dictionary where key is the hostname. Each entry is
        a dictionary as follows
        {'a': [list of A records], 'aaaa': [list of AAAA records]}

        Record format is the same as the hosts table
        """

        # Get database entries
        dyns = self.get_dynamic()

        # If this domain doesn't have anything dynamic then be cool
        if len(dyns) == 0:
            return {}

        logging.debug('Domain %s has %d dynamic entries', self.domain, len(dyns))

        # Ensure a record for each dynamic entry
        ret: dict[str, dict[str, list[vdns.rr.Host]]] = {}
        for dyn in dyns:
            hn = dyn.hostname
            if hn is None:
                hn = ''
            ret[hn] = {'a': [], 'aaaa': []}

        zoneinfo = self.read_zone_file()
        # If we cannot open the old file then we risk losing information
        if zoneinfo is None:
            vdns.common.abort(f'Could not open file for dynamic hosts for {self.domain}')

        # Add information from the file
        for host in zoneinfo.hosts:
            if host.hostname is None:
                hn = ''
            else:
                hn = host.hostname

            # Only handle file entries that exist in the dynamic table
            if hn not in ret:
                continue

            # TODO: Get rid of a/aaaa and just return a list of all host entries
            if host.ip.version == 4:
                rrtype = 'a'
            else:
                rrtype = 'aaaa'

            assert host.domain == self.domain
            assert host.hostname == hn
            ret[hn][rrtype].append(host)

        return ret

    def get_hosts(self) -> Optional[list[vdns.rr.Host]]:
        """
        Return the host entries taking care of dynamic entries

        Dynamic entries that exist in the hosts table will not be included.
        Dynamic entries will get their values from the zone file
        """
        # Get dynamic entries
        dynamic = self.read_dynamic()

        # Simplest case
        if len(dynamic) == 0:
            return None

        hosts = []

        # Add the dynamic entries
        for host, entries in dynamic.items():
            for i in ('a', 'aaaa'):
                for entry in entries[i]:
                    logging.debug('Adding dynamic entry %s %s %s', host, i, entry.ip.compressed)
                    hosts.append(entry)

        return hosts

    def determine_dynamic_serial(self, serial: int) -> int:
        """
        Determine the serial number of a dynamic zone

        Dynamic zones will most probably have serial numbers in their
        zone file that are bigger than the database one.

        The returned serial number is the current serial number. It will
        have to be incremented one way or another.

        @param domain   The domain name
        @param serial   The database serial
        @return An appropriate serial number
        """
        zoneinfo = self.read_zone_file()

        fserial = int(zoneinfo.soa.serial)

        ret = max(serial, fserial)

        return ret

    def get_data(self) -> Optional[vdns.src.src0.DomainData]:
        dom = self.domain

        if not self.db.is_dynamic(dom):
            return None

        domain = self.db.domains.read_one({'name': dom})
        network = self.db.networks.read_one({'domain': dom})

        if not domain:
            return None

        ret = vdns.src.src0.DomainData(dom)

        if network:
            ret.name = vdns.common.reverse_name(network.network.compressed)
            ret.network = network.network
        else:
            ret.name = dom

        hosts = self.get_hosts()
        # TODO: Convert timestamps (?)

        if not hosts:
            return None

        assert domain.serial is not None
        ret.serial = self.determine_dynamic_serial(domain.serial)
        ret.hosts = hosts

        return ret

    def has_changed(self) -> bool:
        # Dynamic zones never trigger a zone regeneration by themselves
        return False

    def incserial(self, oldserial: int) -> int:
        """!
        Increment the serial number

        @param oldserial    The old serial number
        @return The incremented serial number
        """

        ret = oldserial + 1

        return ret

    def set_serial(self, serial: int) -> None:
        # We don't store serial numbers
        pass

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
