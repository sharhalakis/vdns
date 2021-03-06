#!/usr/bin/env python
# coding=UTF-8
#

import logging
import os
import copy
import errno
import datetime
import psycopg2
import psycopg2.extras

import vdns.db
import vdns.common
import vdns.src.src0
import vdns.zoneparser

class NoSuchZoneFileError(OSError):
    def __init__(self, fn):
        err=errno.ENOENT
        st=os.strerror(err)
        OSError.__init__(self, err, st, fn)

class Dynamic(vdns.src.src0.Source):
    """! Dynamic zone handling """
    def __init__(self, domain, zonedir, zonefile):
        """!
        @param domain   The domain name
        @param zonedir  The directory tha holds the zone files
        @param zonefile The existing zone file to read for dynamic entries.
                        This is relative to the zonedir. Defaults to the
                        domain name
        """
        vdns.src.src0.Source.__init__(self, domain)
        self.db=vdns.db.get_db()
        self.zonedir=zonedir
        self.zonefile=zonefile

    def get_dynamic(self):
        """
        Return the dynamic entries of a domain
        """
        query="""SELECT * FROM dynamic WHERE domain=%(domain)s"""
        args={'domain': self.domain}

        res=self.db.read_table_raw(query, args)

        return(res)

    def read_zone_file(self):
        """
        Read the contents of a zone file and return them in a processed
        form as returned by ZoneInfo.data()

        @return The data or None if the file failed to open / doesn't exist
        """
        fn=self.zonedir + '/' + self.zonefile

        if not os.path.exists(fn):
            raise NoSuchZoneFileError(fn)

        z=vdns.zoneparser.ZoneParser(fn, self.domain)
        ret=z.data()

        return(ret)

    def read_dynamic(self):
        """
        Read dynamic IP addresses from existing files

        Returns a dictionary where key is the hostname. Each entry is
        a dictionary as follows
        {'a': [list of A records], 'aaaa': [list of AAAA records]}

        Record format is the same as the hosts table
        """

        # Get database entries
        dyns=self.get_dynamic()

        # If this domain doesn't have anything dynamic then be cool
        if len(dyns)==0:
            return({})

        logging.debug('Domain %s has %d dynamic entries' % \
            (self.domain, len(dyns)))

        # Ensure a record for each dynamic entry
        ret={}
        for dyn in dyns:
            hn=dyn['hostname']
            if hn==None:
                hn=''
            ret[hn]={'a': [], 'aaaa': []}

        zoneinfo=self.read_zone_file()
        # If we cannot open the old file then we risk loosing information
        if zoneinfo==None:
            vdns.common.abort('Could not open file for dynamic hosts for %s' % \
                (self.domain, ))

        # Add information from the file
        for x in ('a', 'aaaa'):
            for i in zoneinfo[x]:
                if i[0]==None:
                    hn=''
                else:
                    hn=i[0]

                # Only handle file entries that exist in the dynamic table
                if not hn in ret:
                    continue

                if i[2]:
                    ttl=datetime.timedelta(0, i[2])
                else:
                    ttl=None

                ret[hn][x].append({
                    'domain':   self.domain,
                    'hostname': hn,
                    'ip':       i[1],
                    'ip_str':   str(i[1]),
                    'ttl':      ttl,
                })

#        pprint(zoneinfo)
#        pprint(ret)
        return(ret)

    def get_hosts(self):
        """
        Return the host entries taking care of dynamic entries

        Dynamic entries that exist in the hosts table will not be included.
        Dynamic entries will get their values from the zone file
        """
        # Get dynamic entries
        dynamic=self.read_dynamic()

        # Simplest case
        if len(dynamic)==0:
            return(None)

        hosts=[]

        # Add the dynamic entries
        for host in dynamic:
            for i in ('a', 'aaaa'):
                for entry in dynamic[host][i]:
                    logging.debug('Adding dynamic entry %s %s %s' %
                            (host, i, entry['ip_str']))
                    hosts.append(entry)

        return(hosts)

    def determine_dynamic_serial(self, serial):
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
        zoneinfo=self.read_zone_file()

        fserial=int(zoneinfo['soa']['serial'])

        ret=max(serial, fserial)

        return(ret)

    def get_data(self):
        dom=self.domain

        if not self.db.is_dynamic(dom):
            return(None)

        domain=self.db.read_table_one('domains', {'name': dom})
        network=self.db.read_table_one('networks', {'domain': dom})

        if network:
            dom2=vdns.common.reverse_name(network['network'])
        else:
            dom2=dom

        hosts=self.get_hosts()

        if hosts:
            serial=self.determine_dynamic_serial(domain['serial'])
            ret={
                '_domain':  dom2,
                'hosts':    hosts,
                'serial':   serial,
            }
        else:
            ret=None

        return(ret)

    def has_changed(self):
        # Dynamic zones never trigger a zone regeneration by themselves
        return(False)

    def incserial(self, oldserial):
        """!
        Increment the serial number

        @param oldserial    The old serial number
        @return The incremented serial number
        """

        ret=oldserial+1

        return(ret)

    def set_serial(self, serial):
        # We don't store serial numbers
        pass

# End of class Dynamic

if __name__=="__main__":
    vdns.db.init_db(
        dbname  = 'dns',
        dbuser  = 'v13',
        dbhost  = 'my.db.host'
    )

    import pprint

    zone='dyn.example.com'
    dyn=Dynamic(zone, '/etc/bind/db', zone)
    dt=dyn.get_data()

    pprint.pprint(dt)

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:

