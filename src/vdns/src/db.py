#!/usr/bin/env python
# coding=UTF-8
#

import time
import logging

import vdns.db
import vdns.common
import vdns.src.src0

#from pprint import pprint

class DB(vdns.src.src0.Source):
    def __init__(self, domain):
        vdns.src.src0.Source.__init__(self, domain)
        self.db=vdns.db.get_db()

    def get_net_hosts(self, net):
        """
        Return all host entries that belong to that network
        """
        query='SELECT *, family(ip) AS family FROM hosts WHERE ip << %(net)s'
        args={'net': net}

        res=self.db.read_table_raw(query, args)
        for x in res:
            x['ip_str']=str(x['ip'])

        return(res)

    def get_hosts(self):
        """
        Return the host entries taking care of dynamic entries

        Dynamic entries that exist in the hosts table will not be included.
        Dynamic entries will get their values from the zone file
        """
        # Get hosts
        hosts=self.db.get_domain_related_data('hosts', self.domain, 'ip')

        return(hosts)

    def get_data(self):
        dom=self.domain

        logging.debug('Reading data for: %s' % (dom,))

        # Get zone data
        domain=self.db.read_table_one('domains', {'name': dom})
        network=self.db.read_table_one('networks', {'domain': dom})

        if network:
            logging.debug('This is a network zone')

        domain['cnames']=self.db.get_domain_related_data('cnames', dom)
        domain['ns']=self.db.get_domain_related_data('ns', dom)
        domain['mx']=self.db.get_domain_related_data('mx', dom)
        domain['dnssec']=self.db.get_domain_related_data('dnssec', dom)
        domain['txt']=self.db.get_domain_related_data('txt', dom)
        domain['sshfp']=self.db.get_domain_related_data('sshfp', dom)
        domain['dkim']=self.db.get_domain_related_data('dkim', dom)
        domain['srv']=self.db.get_domain_related_data('srv', dom)

        if domain['reverse']:
            net=network['network']
            domain['_domain']=vdns.common.reverse_name(net)
            domain['hosts']=self.get_net_hosts(net)
            domain['network']=net
        else:
            domain['_domain']=dom
            domain['hosts']=self.get_hosts()
            domain['network']=None

        # Also store subdomains
        subs=self.db.get_subdomains(dom)
        domain['subs']=subs

        ret=domain

        return(ret)

    def has_changed(self):
        domain=self.domain

        dt=self.db.read_table_one('domains', {'name': domain})

        old=dt['serial']

        ts0=dt['ts']
        updated0=dt['updated']

        if ts0==None:
            ts=0
        else:
            ts=int(time.mktime(ts0.timetuple()))

        if updated0==None:
            updated=0
        else:
            updated=int(time.mktime(updated0.timetuple()))

        if updated<=ts:
            ret=False
        else:
            ret=True

        return(ret)

    def incserial(self, oldserial):
        """! Increment the serial number if needed.

        @param oldserial    Old serial (ignored)
        @return the current (new) serial number
        """
        ret=self.incserial_date(oldserial)

        return(ret)

    def set_serial(self, serial):
        domain=self.domain

        logging.debug('Storing serial number for %s: %s', domain, serial)

        self.db.store_serial(domain, serial)

# End of class DB

if __name__=="__main__":
    vdns.db.init_db(
        dbname  = 'dns',
        dbuser  = 'v13',
        dbhost  = 'my.db.host'
    )

    import pprint

#    db=DB('10.in-addr.arpa')
    db=DB('example.com')
    dt=db.get_data()

#    pprint.pprint(dt)

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:

