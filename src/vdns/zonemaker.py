#!/usr/bin/env python
# coding=UTF-8
#

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

        # metadata
        ret.meta = vdns.zone0.ZoneData.Meta(
            domain=domain,
            subsoas=main.subdomains,
            network=main.network,
        )
        # soa
        ret.soa = main.soa

        # Figure out the old serial
        # Serial has to be the max
        max_idx = -1
        serial = -1
#        for idx, _ in enumerate(sources):
#            t_data = sourcedata[idx]
#            if not t_data:
#                continue
#            if t_data['serial'] > serial:
#                max_idx = idx
#                serial = t_data['serial']
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

        # data to be combined
        # _data3 = {
        #     'cnames': [],
        #     'dkim': [],
        #     'dnssec': [],
        #     'hosts': [],
        #     'mx': [],
        #     'ns': [],
        #     'srv': [],
        #     'sshfp': [],
        #     'txt': [],
        # }

        # dom = vdns.src.src0.DomainData(domain, soa=soa)
        ret.data.name = domain
        ret.data.soa = main.soa

        # Combine data
        for srcdt in sourcedata:
            if not srcdt:
                continue
            ret.data += srcdt

        # Get subdomain data
        for subsoa in ret.meta.subsoas:
            subname = subsoa.name
            ldom = len(domain)
            if not subname.endswith(f'.{domain}'):
                logging.error('WTF? Bad subdomain: %s - %s', domain, subname)
                raise Exception('Something went bad')

            subz = ZoneMaker(subname, zonedir=self.zonedir)
            dt = subz.get_zone_data()
            if dt is None:
                continue

            subdata = vdns.zone0.ZoneData.SubdomainData()
            ret.subs[subname] = subdata

            # This will give us the 'host' part
            # For subdomain of hell.gr named test1.test2.hell.gr, this
            # will contain test1.test2
            h = subname[:-(ldom + 1)]

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

# if __name__=='__main__':
#     import vdns.db
#     import pprint
#
#     logging.basicConfig(level=logging.DEBUG)
#
#     vdns.db.init_db(
#         dbname = 'dns',
#         dbuser = 'v13',
#         dbhost = 'db.host'
#     )
#
#     domain='example.com'
#     domain='10.in-addr.arpa'
#
#     zm=ZoneMaker(domain, zonedir='/etc/bind/db')
#
#     pprint.pprint(zm.doit())
#
# #    init()
# #    doit()
# #    end()

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
