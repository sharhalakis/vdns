#!/usr/bin/env python
# coding=UTF-8
#

import copy
import logging

import vdns.zone
import vdns.zonerev
import vdns.src.db
import vdns.src.dynamic


class ZoneMaker:
    def __init__(self, domain, zonedir=None):
        """!
        @param domain   The domain to create config for
        @param zonedir  The directory that stores old zone data, or None
                        if no dynamic data should be read
        """
        self.domain = domain
        self.zonedir = zonedir
        self.sources = None

    def _mksources(self):
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

        ret = []

        source = vdns.src.db.DB(domain)
        ret.append(source)

        if zonedir is not None:
            source = vdns.src.dynamic.Dynamic(domain, zonedir, domain)
            ret.append(source)

        return ret

    def get_sources(self):
        if not self.sources:
            self.sources = self._mksources()

        return self.sources

    def get_main_source(self):
        sources = self.get_sources()

        ret = sources[0]

        return ret

    def get_zone_data(self, incserial=False):
        """!
        returns a dictionary of:
            - sources   The source objects
            - main      The main source object (useful for updating the serial)
            - meta      Metadata of the zone:
                - _domain   The domain name
                - reverse   True if this is a reverse zone
                - subs      Subdomains (the db domain records)
                - network   The IP network in case of reverse, or None
            - zone      SOA data
            - data      The actual records
            - sub       Subdomain data. Each entry is a dict of:
                - ns    NS records
                - ds    DS records
                - glue  glue records

        @param incserial    If True then increment the serial number
        @return the combined zone data or None
        """
        sources = self.get_sources()
        domain = self.domain

        if not sources:
            return None

        # Cache the data of each source
        sourcedata = []
        for source in sources:
            dt = source.get_data()
            #            if not dt:
            #                continue
            sourcedata.append(dt)

        # Get the main source
        main = sourcedata[0]

        # metadata
        data1 = {
            '_domain': domain,
            'reverse': main['reverse'],
            'subs': main['subs'],
            'network': main['network'],
            #            'ts':       main['ts'],
            #            'updated':  main['updated'],
        }

        # Figure out the old serial
        # Serial has to be the max
        max_idx = -1
        serial = -1
        for idx, _ in enumerate(sources):
            t_source = sources[idx]
            t_data = sourcedata[idx]
            if not t_data:
                continue
            if t_data['serial'] > serial:
                max_idx = idx
                serial = t_data['serial']
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

        # zonedata - common for all sources. Get them from the main source
        data2 = {
            'contact': main['contact'],
            'expire': main['expire'],
            'minimum': main['minimum'],
            'name': main['name'],
            'ns0': main['ns0'],
            'refresh': main['refresh'],
            'retry': main['retry'],
            'serial': serial,
            'ttl': main['ttl'],
        }

        # data to be combined
        data3 = {
            'cnames': [],
            'dkim': [],
            'dnssec': [],
            'hosts': [],
            'mx': [],
            'ns': [],
            'srv': [],
            'sshfp': [],
            'txt': [],
        }

        # Combine data
        for dt in sourcedata:
            if not dt:
                continue
            for k in data3:
                if k not in dt:
                    continue
                data3[k] += dt[k]

        # Get subdomain data
        subs = {}

        for sub in data1['subs']:
            subname = sub['name']
            ldom = len(domain)
            if subname[-ldom:] != domain:
                logging.error('WTF? Bad subdomain: %s - %s', domain, subname)
                raise Exception('Something went bad')

            subz = ZoneMaker(subname, zonedir=self.zonedir)
            dt = subz.get_zone_data()
            if dt is None:
                continue
            dt = dt['data']

            subdata = {
                'ns': [],
                'ds': [],
                'glue': [],
            }

            # This will give us the 'host' part
            # For subdomain of hell.gr named test1.test2.hell.gr, this
            # will contain test1.test2
            h = subname[:-(ldom + 1)]

            # Get DS info for all KSK DNSSEC entries of that domain
            for ds in dt['dnssec']:
                if ds['ksk']:
                    ds['hostname'] = h
                    subdata['ds'].append(ds)

            # Get NS entries for that domain as well
            for ns in dt['ns']:
                ns['hostname'] = h
                subdata['ns'].append(ns)

                # Get the glue records - if any
                if not ns['ns'].endswith('.' + ns['domain']):
                    continue

                # Iterate over hosts to find appropriate records
                for host in dt['hosts']:
                    host2 = host['hostname'] + '.' + host['domain']
                    if ns['ns'] != host2:
                        continue
                    # Figure out the hostname part by removing the current
                    # domain from the host's FQDN
                    ns2 = host2[:-(ldom + 1)]

                    # Create another record with appropriate
                    # domain and hostname entries
                    rec = copy.deepcopy(host)
                    rec['domain'] = domain
                    rec['hostname'] = ns2
                    subdata['glue'].append(rec)

            subs[h] = subdata

        ret = {
            'sources': sources,
            'main': main,
            'meta': data1,
            'zone': data2,
            'data': data3,
            'subs': subs,
        }

        return ret

    def incserial(self):
        """! Increase the serial number of the main source """
        logging.debug('Incrementing serial number of %s', self.domain)
        main = self.get_main_source()
        main.incserial()

    def doit(self, keys=False, incserial=False):
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
        data0 = self.get_zone_data(incserial=incserial)

        # print sorted(data0[0].keys())

        # The Zone classes require all data in one dictionary.
        # Combine them
        data = {}
        data.update(data0['meta'])
        data.update(data0['zone'])
        data.update(data0['data'])
        data['subs'] = data0['subs']

        if data['reverse']:
            z = vdns.zonerev.ZoneRev(data)
        else:
            z = vdns.zone.Zone(data)

        st = z.make()

        ret = {
            'zone': st,
        }

        if keys:
            t = z.make_keys()
            ret['keys'] = t

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
