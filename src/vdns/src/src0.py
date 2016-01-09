#!/usr/bin/env python
# coding=UTF-8
#

import time
import datetime

class Source(object):
    def __init__(self, domain):
        self.domain=domain

    def incserial_date(self, oldserial):
        """!
        Increment a serial number, handling date cases

        @param oldserial    The old serial number
        @return the new serial number
        """
        old=oldserial

        # If our convention is not the date then just increment by one
        if old > 1000000000:
            ts=datetime.date.fromtimestamp(time.time())
            ser0="%04d%02d%02d" % (ts.year, ts.month, ts.day)

            if str(old)[:len(ser0)]==ser0:
                # Same day
                idx=old%100
                ser=ser0 + '%02d' % (idx+1, )
            elif old < (int(ser0)*100):
                # Normal increament
                ser=ser0 + '00'
            else:
                # Fail!
                raise Exception('Old serial (%d) for %s is in the future' % \
                    (old, domain))
        else:
            ser=old+1

        return(ser)

    # -------------------------------------------------------------------
    # Things to implement in derived classes

    def get_data(self):
        """!
        Return the data as:
        ret={
            '_domain':  The domain name
            contact, ns0, ttl, refresh, retry, expire, minimum:
                        The SOA data

            'reverse':  True of this is a reverse zone

            # All bellow have hostname and ttl
            'mx':       [ { priority, mx } ]
            'ns':       [ { ns } ]
            'hosts':    [ { domain, ip, ip_str } ]
            'cnames':   [ { hostname0 } ]
            'txt':      [ { txt } ]
            'dnssec':   [ { ksk, algorithm, key_pub,
                            domain, keyid, st_key_pub, st_key_priv,
                            digest_sha1, digest_sha256 } ]
            'sshfp':    [ { keytype, hashtype, fingerprint } ]
            'dkim':     [ { selector, k, key_pub, g, t, ttl,
                            h, subdomains } ]
            'srv':      [ { service, protocol, priority,
                            weight, port, target } ]

            # TODO: Lose this - replace with just a domain list
            'subs': {
                subdomain_name: {   # host part. not the FQDN
                    'ns':   [ NS records ]
                    'ds':   [ { keyid, algorithm, digest_sha1,
                                digest_sha256 } ]
                    'glue': [ Glue records for NS ]
                    }
                }
            }

        """
        raise NotImplemented()

    def has_changed(self):
        """!
        Check whether data for this source have changed. If yes then
        a new serial will be allocated later

        @return True/False
        """
        raise NotImplemented()

    def incserial(self, oldserial):
        """!
        Given the old serial number, provide the next serial number.

        E.g. if this source uses dates for serial representation it may
        return the next serial to use (which may not be old+1). Otherwise
        it may return just the oldeserial+1, etc...

        @return The next serial number to use
        """
        raise NotImplemented()

    def set_serial(self, serial):
        """!
        Store this serial number to the database (if applicable)

        Once the next serial number is determined, all sources will be called
        to store the serial number.
        """
        raise NotImplemented()

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:

