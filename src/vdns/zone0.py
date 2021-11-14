#!/usr/bin/env python
# coding=UTF-8
#

import copy
import logging
import datetime
import dataclasses as dc

import vdns.common
import vdns.rr

from typing import List, Optional, Tuple


@dc.dataclass
class Domain:
    soa: vdns.rr.SOA
    mx: List[vdns.rr.MX] = dc.field(default_factory=list)
    ns: List[vdns.rr.NS] = dc.field(default_factory=list)
    hosts: List[vdns.rr.Host] = dc.field(default_factory=list)
    cnames: List[vdns.rr.CNAME] = dc.field(default_factory=list)
    txt: List[vdns.rr.TXT] = dc.field(default_factory=list)
    dnssec: List[vdns.rr.DNSSEC] = dc.field(default_factory=list)
    sshfp: List[vdns.rr.SSHFP] = dc.field(default_factory=list)
    dkim: List[vdns.rr.DKIM] = dc.field(default_factory=list)
    srv: List[vdns.rr.SRV] = dc.field(default_factory=list)


@dc.dataclass
class Zone0:
    """
    Base class for producing zone files
    """
    dt: datetime.timedelta

    def __init__(self, dt: datetime.timedelta):
        self.dt = dt

    def fmttd(self, td: datetime.timedelta) -> Tuple[str, str]:
        """
        Format a timedelta value to something that's appropriate for
        zones
        """

        lst = ((1, '', 'second', 'seconds'),
               (60, 'M', 'minute', 'minutes'),
               (3600, 'H', 'hour', 'hours'),
               (86400, 'D', 'day', 'days'),
               (86400 * 7, 'W', 'week', 'weeks'))

        ts = int(td.total_seconds())

        if ts == 0:
            raise ValueError("Timedelta can't be 0")

        # Find the first value that doesn't give an exact result
        ent = lst[0]
        for i in lst:
            if (ts % i[0]) != 0:
                break
            ent = i

        ret1 = '%d%s' % (int(ts / ent[0]), ent[1])

        # Now form the human readable string
        rem = ts
        ret2 = []
        for i in reversed(lst):
            t, rem = divmod(rem, i[0])

            if t == 0:
                continue

            if t == 1:
                unit = i[2]
            else:
                unit = i[3]

            st = '%s %s' % (t, unit)

            ret2.append(st)

            # Speadup
            if rem == 0:
                break

        ret2st = ', '.join(ret2)
        ret = (ret1, ret2st)

        return ret

    def make_ptr_name(self, rec):
        """
        Format the name of a PTR record (i.e. reverse IPv4 or IPv6)
        """
        if rec['family'] == 4:
            rev = rec['ip_str'].split('.')
            rev.reverse()
            rev = '.'.join(rev)
            ret = rev + '.in-addr.arpa'
        elif rec['family'] == 6:
            ip2 = rec['ip_str'] + '/128'
            ret = vdns.common.reverse_name(ip2)
        #            logging.error('Unhandled address family: %s', rec['family'])
        #            ret=''
        else:
            logging.error('Unknown address family: %s', rec['family'])
            ret = ''

        # Get rid of the suffix if we can
        domain = self.dt['_domain']
        if ret[-len(domain):] == domain:
            ret = ret[:-len(domain) - 1]

        return ret

    #    def make_soa(self, incserial):
    def make_soa(self):
        """!
NO        @param incserial    If True then increment the serial number
        """
        dt = self.dt

        dt2 = {
            #            'serial':       self.mkserial(dt, incserial),
            'serial': dt['serial'],
            'domain': dt['_domain'],
            'contact': dt['contact'],
            'ns0': dt['ns0'],
        }

        times = ('ttl', 'refresh', 'retry', 'expire', 'minimum')
        for i in times:
            t = self.fmttd(dt[i])
            dt2[i] = t[0]
            dt2[i + '2'] = t[1]

        st = '''\
$ORIGIN		%(domain)s.
$TTL		%(ttl)s	; %(ttl2)s
@		%(ttl)s	IN	SOA	%(ns0)s. %(contact)s. (
                                %(serial)-15s ; serial
                                %(refresh)-15s ; refresh (%(refresh2)s)
                                %(retry)-15s ; retry (%(retry2)s)
                                %(expire)-15s ; expire (%(expire2)s)
                                %(minimum)-15s ; minimum (%(minimum2)s)
                                )

''' % dt2

        return st

    def fmtrecord(self, name: str, ttl: Optional[datetime.timedelta], rr: str, data: str):
        """
        Format a record

        This is a dump function that concatenates data, translating ttl

        Use mkrecord instead

        @param name     The hostname
        @param ttl      The TTL in seconds
        @param rr       The type of the record
        @param data     A freeform string
        @return The formed entry
        """

        if ttl is None:
            ttl2 = ''
        else:
            t = self.fmttd(ttl)
            ttl2 = ' ' + t[0]

        ret = '%-16s%s	IN	%s	%s' % \
              (name, ttl2, rr, data)

        return ret

    def split_txt(self, data):
        """
        Split TXT data to chunks of max 255 bytes to comply with bind

        @param data     An unquoted string of arbitrary length
        @return A quoted string to be used as TXT record
        """
        limit = 255

        items = []
        data2 = copy.deepcopy(data)
        while len(data2) > limit:
            items.append(data2[:limit])
            data2 = data2[limit:]
        items.append(data2)

        ret = '"' + '" "'.join(items) + '"'

        return ret

    def mkrecord(self, rr, rec):
        """
        Create a record based on RR (the type)

        @param rr   The record type. One of: ns, mx, ds
        @return The formed entry
        """

        # If this is true then we will make sure that there is a dot
        # at the end of the name
        needsdot = False

        # Allow this to be changed by a type (i.e. PTR)
        hostname = None

        if rr == 'mx':
            rrname = 'MX'
            data = '%-4d %s' % (rec['priority'], rec['mx'])
            if rec['mx'].count('.') >= 2:
                needsdot = True
        elif rr == 'ns':
            rrname = 'NS'
            data = rec['ns']
            if rec['ns'].count('.') >= 2:
                needsdot = True
        elif rr == 'ds':
            rrname = 'DS'
            data = []
            data.append('%d %d %d %s' % (rec['keyid'], rec['algorithm'],
                                         1, rec['digest_sha1']))
            data.append('%d %d %d %s' % (rec['keyid'], rec['algorithm'],
                                         2, rec['digest_sha256']))
        elif rr == 'a':
            rrname = 'A'
            data = rec['ip_str'].split('/')[0]
        elif rr == 'aaaa':
            rrname = 'AAAA'
            data = rec['ip_str'].split('/')[0]
        elif rr == 'ptr':
            # TODO: This is broken. We need to inverse the ip
            # and take care of ipv6 as well
            rrname = 'PTR'
            data = '%s.%s.' % (rec['hostname'], rec['domain'])
            hostname = self.make_ptr_name(rec)
            needsdot = True
        elif rr in ('cname', 'cnames'):
            rrname = 'CNAME'
            data = rec['hostname0']
            if rec['hostname0'].count('.') >= 2:
                needsdot = True
        elif rr == 'txt':
            rrname = 'TXT'
            data = '"%s"' % (rec['txt'],)
        elif rr == 'dnssec':
            rrname = 'DNSKEY'
            if rec['ksk']:
                flags = 257
            else:
                flags = 256
            #            rec['hostname']=rec['domain']
            data = '%s 3 %s %s' % (flags, rec['algorithm'], rec['key_pub'])
        elif rr == 'sshfp':
            rrname = 'SSHFP'
            data = '%(keytype)d %(hashtype)d %(fingerprint)s' % rec
        elif rr == 'dkim':
            rrname = 'TXT'
            hostname = '%(selector)s._domainkey' % rec
            if 'hostname' in rec and rec['hostname']:
                hostname += '.' + rec['hostname']
            data0 = []
            data0.append('v=DKIM1')
            if rec['g'] is not None:
                data0.append('g=' + rec['g'])
            data0.append('k=' + rec['k'])
            data0.append('s=email')
            if rec['t'] or not rec['subdomains']:
                if rec['t']:
                    if rec['subdomains']:
                        t = 'y'
                    else:
                        t = 's:y'
                else:
                    t = 's'
                data0.append('t=' + t)
            if rec['h'] is not None:
                data0.append('h=' + rec['h'])
            data0.append('p=' + rec['key_pub'])

            data = self.split_txt('; '.join(data0))
        elif rr == 'srv':
            rrname = 'SRV'
            hostname = '_%(service)s._%(protocol)s' % rec
            if rec['name'] != '':
                hostname += '.' + rec['name']
            data = '%(priority)s %(weight)s %(port)s %(target)s' % rec
            if rec['target'].count('.') >= 1:
                needsdot = True
        else:
            vdns.common.abort('Unhandled RR type %s: %s' % (rr, rec))

        if not isinstance(data, list):
            data = [data]

        if needsdot:
            for i, _ in enumerate(data):
                if data[i][-1] != '.':
                    data[i] += '.'

        if hostname is None:
            if 'hostname' in rec:
                hostname = rec['hostname']
            else:
                hostname = ''

        if hostname == '.':
            hostname = ''

        ttl = rec['ttl']
        # ret=self.fmtrecord(hostname, self.dt['ttl'], rrname, data)
        ret = ''
        for d in data:
            ret += self.fmtrecord(hostname, ttl, rrname, d)
            ret += '\n'

        return ret

    def mkrecord_a_aaaa(self, rec):
        """!
        Auto-determine A or AAAA and call mkrecord

        @record rec     The record. Must be either A or AAAA
        @return The result of mkrecord()
        """
        if rec['ip'].ip.version == 4:
            ret = self.mkrecord('a', rec)
        else:
            ret = self.mkrecord('aaaa', rec)

        return ret

    def make_toplevel(self):
        """
        Create the top-level entries.
        These are the entries with empty hostname or hostname=='.'
        """

        lst = ['ns', 'mx', 'dnssec', 'txt']

        ret = ''

        for typ in lst:
            if typ not in self.dt:
                continue

            recs = self.dt[typ]

            for rec in recs:
                if 'hostname' in rec and \
                        not (rec['hostname'] == '' or rec['hostname'] == '.'):
                    continue

                ret += self.mkrecord(typ, rec)

        if 'hosts' in self.dt:
            for rec in self.dt['hosts']:
                if rec['hostname'] != '':
                    continue

                ret += self.mkrecord_a_aaaa(rec)

        # Add DKIM and SRV here (last) since they have a host part
        for x in ('dkim', 'srv'):
            if x in self.dt:
                for rec in self.dt[x]:
                    if rec['hostname'] != '':
                        continue
                    ret += self.mkrecord(x, rec)

        return ret

    def make_subzones(self):
        """
        Create entries that are considered subdomains
        For now these are entries that have NS
        """

        lst = ['ns', 'ds']

        ret = ''
        glue = ''

        for sub in sorted(self.dt['subs']):
            ret += '\n'
            for typ in lst:
                recs = self.dt['subs'][sub][typ]

                for rec in recs:
                    ret += self.mkrecord(typ, rec)

            recs = self.dt['subs'][sub]['glue']
            for rec in recs:
                glue += self.mkrecord_a_aaaa(rec)

        if glue != '':
            ret += '\n; Glue records\n'
            ret += glue

        return ret

    def make_hosts(self):
        """
        Make the host entries

        Host entries are accompanied with relevant records like CNAMEs,
        TXTs, etc...
        """
        done = []  # List of entries already handled
        ret = ''
        subdomaintypes = ['ns']
        lst = ['txt', 'sshfp']

        # Determine entries to be excluded
        # - since we added them previously
        for typ in subdomaintypes:
            if typ not in self.dt:
                continue

            recs = self.dt[typ]

            for rec in recs:
                t = rec['hostname']
                if t not in done:
                    done.append(t)

        # Examine all hosts
        #        hosts2=dict([(h['ip'], h) for h in self.dt['hosts']])
        #        ips=hosts2.keys()
        #        ips.sort()
        for rec in self.dt['hosts']:
            #        for ip in ips:
            #            rec=hosts2[ip]
            hostname = rec['hostname']
            if hostname == '':
                continue

            # ip=rec['ip']
            ret += self.mkrecord_a_aaaa(rec)

            if hostname in done:
                continue

            done.append(hostname)

            # Add additional info here
            for typ in lst:
                if typ not in self.dt:
                    continue

                recs2 = self.dt[typ]
                for rec2 in recs2:
                    if rec2['hostname'] != hostname:
                        continue

                    rec3 = copy.deepcopy(rec2)
                    rec3['hostname'] = ''
                    ret += self.mkrecord(typ, rec3)

            # CNAMEs are special. We look for cnames that are
            # pointing to this host
            if 'cnames' in self.dt:
                recs2 = self.dt['cnames']
                for rec2 in recs2:
                    if rec2['hostname0'] != hostname:
                        continue

                    ret += self.mkrecord('cnames', rec2)

                    done.append(rec2['hostname'])

            # Add DKIM here (last) as it has a hostname part
            for rec2 in self.dt['dkim']:
                if rec2['hostname'] != hostname:
                    continue

                ret += self.mkrecord('dkim', rec2)

        # Now do the rest cnames
        rests = ['cnames', 'txt']
        for rr in rests:
            if rr in self.dt:
                ret += '\n'
                for rec in self.dt[rr]:
                    if rec['hostname'] == '':
                        continue
                    if not rec['hostname'] in done:
                        ret += self.mkrecord(rr, rec)

        return ret

    def make_reverse(self):
        """
        Make the reverse entries
        """
        ret = ''

        # Create a dict and sort the keys. We list IPv4 before IPv6.
        # Keys are: X-Y where X is 4 or 6 depending on the family and
        # Y is the numerical representation of the address as returned by
        # inet_pton. All of this to be able to sort based on numerical
        # value instead of string representation
        hosts = {}
        for x in self.dt['hosts']:
            # Skip entries that are not designated as reverse
            if not x['reverse']:
                continue

            ip = x['ip'].ip
            k = b'%d-%s' % (ip.version, ip.packed)
            hosts[k] = x

        for x in sorted(hosts):
            rec = hosts[x]
            ret += self.mkrecord('ptr', rec)

        return ret

    def make_keys(self):
        """
        Make the key files

        Returns a list of entries. Each entry is a tuple of:
        (type, fn, contents)
        Where type is 'key' or 'private'
        """

        ret = []

        for x in self.dt['dnssec']:
            fn0 = 'K%s.+%03d+%d' % (x['domain'], x['algorithm'], x['keyid'])

            fn = fn0 + '.key'
            rec = ('key', fn, x['st_key_pub'])
            ret.append(rec)

            fn = fn0 + '.private'
            rec = ('private', fn, x['st_key_priv'])
            ret.append(rec)

        return ret


if __name__ == '__main__':
    pass

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
