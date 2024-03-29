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

from typing import Optional

import copy
import logging
import dataclasses as dc

import vdns.rr
import vdns.zone
import vdns.zone0
import vdns.common
import vdns.zonerev
import vdns.src.src0
import vdns.src.db
import vdns.src.dynamic


SourceList = list[vdns.src.src0.Source]


@dc.dataclass
class ZoneOutput:
    # The contents of the zone file
    zone: str = ''
    # A list of keys where each entry is a tuple of (key_file_name, data)
    keys: list[tuple[str, str]] = dc.field(default_factory=list)


class ZoneMaker:
    domain: str
    zonedir: Optional[str]
    sources: Optional[SourceList]

    def __init__(self, domain: str, zonedir: Optional[str] = None):
        """!
        @param domain   The domain to create config for
        @param zonedir  The directory that stores old zone data, or None
                        if no dynamic data should be read
        """
        self.domain = domain
        self.zonedir = zonedir
        self.sources = None

    def _mksources(self) -> SourceList:
        """!
        Construct a list of sources for a certain domain

        Needed config options:
            - zonedir   Directory that stores the zone files

        @param domain   The domain to make the sources for
        @param cfg      Config options used for constructing the sources
                        objects. If an option is missing then it's an error.
                        If a needed option for a certain type is missing
                        then that type is not created
        @return a list of source objects
        """
        domain = self.domain
        zonedir = self.zonedir

        ret: SourceList = []

        source: vdns.src.src0.Source

        source = vdns.src.db.DB(domain)
        ret.append(source)

        if zonedir is not None:
            source = vdns.src.dynamic.Dynamic(domain, zonedir, domain)
            ret.append(source)

        return ret

    def _zonemaker_factory(self, domain: str) -> 'ZoneMaker':
        return ZoneMaker(domain, zonedir=self.zonedir)

    def get_sources(self) -> SourceList:
        if self.sources is None:
            self.sources = self._mksources()

        return self.sources

    def get_main_source(self) -> vdns.src.src0.Source:
        sources = self.get_sources()

        ret = sources[0]

        return ret

    def get_zone_data(self, incserial: bool = False) -> Optional[vdns.zone0.ZoneData]:
        """
        @param incserial    If True then increment the serial number
        @return the combined zone data or None
        """
        sources = self.get_sources()
        domain = self.domain

        if not sources:
            return None

        ret = vdns.zone0.ZoneData()
        ret.sources = sources

        # Cache the data of each source. The order/index needs to be the same as in sources.
        sourcedata: list[Optional[vdns.src.src0.DomainData]] = []
        for source in sources:
            sourcedata.append(source.get_data())

        # Get the main source
        main = sourcedata[0]
        assert main is not None

        # invoked domain name
        ret.domain = domain
        # soa
        ret.soa = main.soa

        # Figure out the old serial
        # Serial has to be the max
        max_idx = -1
        serial = -1
        for idx, t_data in enumerate(sourcedata):
            if not t_data:
                continue
            if t_data.serial > serial:
                max_idx = idx
                serial = t_data.serial
        oldserial = serial
        logging.debug('Old serial: %d', oldserial)

        # Figure out if things have changed
        changed = False
        for source in sources:
            if source.has_changed():
                logging.debug('Detected changed')
                changed = True
                break

        # If yes, then increment the serial and store it
        if incserial and changed:
            t_source = sources[max_idx]
            serial = t_source.incserial(serial)
            logging.debug('New serial: %s', serial)

            for source in sources:
                source.set_serial(serial)

        ret.data.name = domain
        ret.data.soa = main.soa
        ret.data.network = main.network

        # Combine data
        for srcdt in sourcedata:
            if not srcdt:
                continue
            ret.data += srcdt

        # Get subdomain data
        for subdomain in main.subdomains:
            ldom = len(domain)
            if not subdomain.endswith(f'.{domain}'):
                logging.error('WTF? Bad subdomain: %s - %s', domain, subdomain)
                raise Exception('Something went bad')

            subz = self._zonemaker_factory(subdomain)
            dt = subz.get_zone_data()
            if dt is None:
                continue

            # subdata = vdns.zone0.ZoneData.SubdomainData(soa=subsoa)
            subdata = vdns.zone0.ZoneData.SubdomainData(name=subdomain)
            ret.subs[subdomain] = subdata

            # This will give us the 'host' part
            # For subdomain of hell.gr named test1.test2.hell.gr, this
            # will contain test1.test2
            h = subdomain[:-(ldom + 1)]

            # Get DS info for all KSK DNSSEC entries of that domain
            for dnssec in dt.data.dnssec:
                if dnssec.ksk:
                    ds = vdns.rr.DS.from_dnssec(dnssec)
                    ds.hostname = h
                    subdata.ds.append(ds)

            # Get NS entries for that domain as well
            for ns in dt.data.ns:
                ns.hostname = h
                subdata.ns.append(ns)

                # Get the glue records - if any
                if not ns.ns.endswith(f'.{ns.domain}'):
                    continue

                # Iterate over hosts to find appropriate records
                for host in dt.data.hosts:
                    host2 = f'{host.hostname}.{host.domain}'
                    if ns.ns != host2:
                        continue
                    # Figure out the hostname part by removing the current
                    # domain from the host's FQDN
                    ns2 = host2[:-(ldom + 1)]

                    # Create another record with appropriate
                    # domain and hostname entries
                    rec = copy.deepcopy(host)
                    rec.domain = domain
                    rec.hostname = ns2
                    subdata.glue.append(rec)

        return ret

    # def incserial(self) -> None:
    #     """! Increase the serial number of the main source """
    #     logging.debug('Incrementing serial number of %s', self.domain)
    #     main = self.get_main_source()
    #     main.incserial()

    def doit(self, keys: bool = False, incserial: bool = False) -> ZoneOutput:
        """!
        Generate zone files

        Returns a dictionary of:
        - zone      The contents of the zone file
        - keys      A list of keys where each entry is a tuple of
                    (key_file_name, data)

        @param keys         If True then also generate the key files
        @param incserial    If True then increment the serial number
        @return a dictionary as specified above
        """
        data = self.get_zone_data(incserial=incserial)

        if not data:
            raise Exception('Failed to get data')

        z: vdns.zone0.Zone0

        if data.reverse:
            z = vdns.zonerev.ZoneRev(data)
        else:
            z = vdns.zone.Zone(data)

        ret = ZoneOutput()
        ret.zone = z.make()
        if keys:
            zone_keys = z.make_keys()
            ret.keys = []
            for key in zone_keys:
                ret.keys.append((key.fn, key.st_key))

        return ret

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
