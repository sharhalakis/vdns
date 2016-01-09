#!/usr/bin/env python
# coding=UTF-8
#

import sys
import struct
import base64
import hashlib
import logging

from argparse import ArgumentParser
from pprint import pprint

__all__=["ZoneParser"]

db=None

# List if known RRs. We only need to list those that we handle.
rrs=['A', 'AAAA', 'NS', 'CNAME', 'MX', 'TXT', 'SOA', 'DNSKEY', 'PTR']

def is_ttl(st):
    if st[0] in ('1', '2', '3', '4', '5', '6', '7', '8' ,'9', '0') \
        and st[-1]!='.' and 'arpa' not in st:
        ret=True
    else:
        ret=False

    return(ret)

def cleanup_line(line0):
    ''' Clean a line by removing comments and starting/trailing space '''
    line=line0.strip()
    if line.find(';')>=0:
        line=line[:line.find(';')]

    return(line)

def parse_line(line0):
    global rrs

    line=cleanup_line(line0)

    if len(line)==0 or line[0]==';':
        return(None)

    items=line.split()

    addr1=None
    ttl=None
    rr=None
    addr2=None

    add=0

    rridx=None

    # Nothing to do for these
    if items[0] in ('RRSIG', 'NSEC'):
        return(None)

    # Find the type
    for i in range(len(items)):
        if items[i] in rrs:
            rridx=i
            add=i+1
            break

    if rridx==None:
        return(None)

    rr=items[rridx]
    addr2=' '.join(items[add:])

    for i in range(rridx):
        if items[i]=='IN':
            continue

        if ttl==None and is_ttl(items[i]):
            ttl=items[i]
        elif addr1==None:
            addr1=items[i]
        else:
            logging.warning('Could not parse line: ' + line)
            return(None)

    ret=(addr1, ttl, 'IN', rr, addr2)

    return(ret)

def sinn(val, char):
    # Strip if not None
    if val==None:
        ret=None
    else:
        ret=val.strip(char)

    return(ret)

def ein(val):
    # Return empty if it's null
    if val==None:
        return('')
    return(val)

def esinn(val, char):
    return(ein(sinn(val, char)))

def error(st):
    logging.error(st)
    sys.exit(1)

def insert(tbl, fields, values):

    values2=[]
    for v in values:
        if v==None:
            values2.append('NULL')
        elif type(v)==str and len(v)>0 and v[0]=='\x00':
            values2.append(v[1:])
        else:
            values2.append("'%s'" % v)

    st="INSERT INTO %s(%s) VALUES(%s);" % \
        (tbl, ', '.join(fields), ', '.join(values2))

    return(st)

def ins_soa(name, reverse, ttl, refresh, retry, expire, minimum, contact,
            serial, ns0):
    name2=esinn(name, '.')
    contact2=esinn(contact, '.')
    ns02=ns0.strip('.')

    ret=insert('domains',
        ('name', 'reverse', 'ttl', 'refresh', 'retry', 'expire', 'minimum',
            'contact', 'serial', 'ns0'),
        (name2, reverse, ttl, refresh, retry, expire, minimum, contact2,
         serial, ns02))

    return(ret)

def ins_a(domain, host, ip, ttl):
    host2=esinn(host, '.')
    domain2=domain.strip('.')

    ret=insert('hosts', ('ip', 'domain', 'hostname', 'ttl'),
        (ip, domain2, host2, ttl))

    return(ret)

def ins_cname(domain, host, host0, ttl):
    host2=esinn(host, '.')
    host02=host0.strip('.')
    domain2=domain.strip('.')

    ret=insert('cnames', ('domain', 'hostname', 'hostname0', 'ttl'),
        (domain2, host2, host02, ttl))

    return(ret)

def ins_txt(domain, host, txt, ttl):
    host2=esinn(host, '.')
    domain2=domain.strip('.')
    txt2=txt.strip('"')

    ret=insert('txt', ('domain', 'hostname', 'txt', 'ttl'),
        (domain2, host2, txt2, ttl))

    return(ret)

def ins_ns(domain, ns, ttl):
    domain2=domain.strip('.')
    ns2=ns.strip('.')

    ret=insert('ns', ('domain', 'ns', 'ttl'),
        (domain2, ns2, ttl))

    return(ret)

def ins_mx(domain, hostname, priority, mx, ttl):
    domain2=domain.strip('.')
    hostname2=esinn(hostname, '.')
    mx2=mx.strip('.')

    ret=insert('mx', ('domain', 'hostname', 'priority', 'mx', 'ttl'),
        (domain2, hostname2, priority, mx2, ttl))

    return(ret)

def calc_dnssec_keyid(flags, protocol, algorithm, st):
    """
    Calculate the keyid based on the key string
    """

    st0=st.replace(' ', '')
    st2=struct.pack('!HBB', int(flags), int(protocol), int(algorithm))
    st2+=base64.b64decode(st0)

    cnt=0
    for idx in range(len(st2)):
        s=struct.unpack('B', st2[idx])[0]
        if (idx % 2) == 0:
            cnt+=s<<8
        else:
            cnt+=s

    ret=((cnt & 0xFFFF) + (cnt>>16)) & 0xFFFF

    return(ret)

def calc_ds_sigs(owner, flags, protocol, algorithm, st):
    """
    Calculate the DS signatures

    Return a dictionary where key is the algorithm and value is the value
    """

    st0=st.replace(' ', '')
    st2=struct.pack('!HBB', int(flags), int(protocol), int(algorithm))
    st2+=base64.b64decode(st0)

    # Transform owner from A.B.C to <legth of A>A<length of B>B<length of C>C0

    if owner[-1]=='.':
        owner2=owner
    else:
        owner2=owner+'.'

    owner3=''
    for i in owner2.split('.'):
        owner3+=struct.pack('B', len(i))+i

    st3=owner3+st2

    ret={
        'sha1':     hashlib.sha1(st3).hexdigest().upper(),
        'sha256':   hashlib.sha256(st3).hexdigest().upper(),
    }

    return(ret)

def ins_dnssec_no(domain, hostname, flags, protocol, algorithm, key_pub):
    domain2=domain.strip('.')
    hostname2=esinn(hostname, '.')

    keyid=calc_dnssec_keyid(flags, protocol, algorithm, key_pub)

    print('keyid', keyid)

    insert('dnssec',
        ('domain', 'hostname', 'keyid', 'algorithm', 'key_pub'),
        (domain2, hostname2, keyid, algorithm, key_pub))

def handle_entry(domain, r):
    addr1=r[0]
    addr2=r[4]
    ttl=r[1]
    rr=r[3]

    if rr=='PTR':
        logging.info("Ignoring PTR: " + repr(r))
    elif rr=='A' or rr=='AAAA':
        ins_a(domain, addr1, addr2, ttl)
    elif rr=='CNAME':
        ins_cname(domain, addr1, addr2, ttl)
    elif rr=='NS':
        # Don't do NS records for a zone here (i.e. when addr1!='')
        # We will collect them from the zone itself (i.e when addr1=='')
        if addr1!=None and addr1!='':
            logging.info('Skipping NS record for %s.%s' % (addr1, domain))
        else:
            ins_ns(domain, addr2, ttl)
    elif rr=='TXT':
        ins_txt(domain, addr1, addr2, ttl)
    elif rr=='MX':
        t=addr2.split(None, 1)
        ins_mx(domain, addr1, int(t[0]), t[1], ttl)
#    elif rr=='DS':
#        t=addr2.split(None, 3)
#        if (t[2]!='1'):
#            msg('Unrecognized DS record: %s' % addr2)
#        else:
#            ins_ds(domain, addr1, t[0], t[1], t[2], t[3])
#    elif rr=='DNSKEY':
#        t=addr2.split(None, 3)
##        if (t[2]!='1'):
##            msg('Unrecognized DNSKEY record: %s' % addr2)
##        else:
#        ins_dnssec(domain, addr1, t[0], t[1], t[2], t[3])
    else:
        logging.info("Unhandled %s:" % (rr,) + repr(r))

def parse_ttl(st):
    """
    Parse ttl and return the duration in seconds
    """
    deltas={
        'M':    60,
        'H':    3600,
        'D':    86400,
        'W':    86400*7,
    }

    # If this is already a number
    if type(st)==int:
        ret=st
    elif st[-1].isdigit():
        ret=int(st)
    else:
        ret=int(st[:-1])
        w=st[-1].upper()
        ret*=deltas[w]

    return(ret)

class ZoneParser(object):
    """
    A class to read and parse a zone file
    """

    def __init__(self, fn=None, zone=None, is_reverse=False):
        self.zero()
        self.is_reverse=is_reverse

        if fn!=None:
            self.read(fn, zone)

    def zero(self):
        self.dt={
            'domain':       None,
            'soa':          None,
            'a':            [],
            'aaaa':         [],
            'ptr':          [],
            'cname':        [],
            'ns':           [],
            'txt':          [],
            'mx':           []
        }

    def add_entry(self, r):
        addr1=r[0]
        addr2=r[4]
        ttl=r[1]
        rr=r[3]

        if rr=='PTR':
            logging.info("Ignoring PTR: " + repr(r))
        elif rr=='A' or rr=='AAAA':
            dt=[addr1, addr2, ttl]
            if rr=='A':
                self.dt['a'].append(dt)
            else:
                self.dt['aaaa'].append(dt)
        elif rr=='CNAME':
            dt=[addr1, addr2, ttl]
            self.dt['cname'].append(dt)
        elif rr=='NS':
            # Don't do NS records for a zone here (i.e. when addr1!='')
            # We will collect them from the zone itself (i.e when addr1=='')
            if addr1!=None and addr1!='':
                logging.info('Skipping NS record for %s' % (addr1,))
            else:
                dt=[addr2, ttl]
                self.dt['ns'].append(dt)
        elif rr=='TXT':
            dt=[addr1, addr2, ttl]
            self.dt['txt'].append(dt)
        elif rr=='MX':
            t=addr2.split(None, 1)
            dt=[addr1, int(t[0]), t[1], ttl]
            self.dt['mx'].append(dt)
        else:
            logging.info("Unhandled %s:" % (rr,) + repr(r))

    def read(self, fn, zone=None):
        """
        @param zone     Optional zone name. If None then the SOA name is used.
        """

        lastname=None
        domain=None
        insoa=False

        soa={
            'name':     None,
            'defttl':   None,
            'refresh':  None,
            'retry':    None,
            'expire':   None,
            'minimum':  None,
            'contact':  None,
            'serial':   None,
            'ns0':      None,
            }
        soastr='';

        if zone!=None:
            domain=zone.strip('.')
            soa['name']=domain

        self.dt['domain']=domain;

        defttl=-1;

        soattl=None

        try:
            f=open(fn)
        except:
            logging.error('Failed to open file: %s' % (fn,))
            return(None)

        for line0 in f:
            # Remove comments etc...
            line=cleanup_line(line0)

            # Handle special entries
            if line[:4]=='$TTL':
                t=line.split()
                defttl=parse_ttl(t[1])
                self.dt['defttl']=defttl
                continue

            # If we are in SOA then concatenate the lines until we find a )
            # Then parse the resulting line
            #
            # Don't attempt to parse intermediate SOA lines. Remember that
            # the first line is already parsed.
            #
            # This logic fails if the whole SOA is on one line and there is
            # no empty/comment line after that.
            if insoa:
                soastr+=' '
                soastr+=line

                # The end
                if ')' in soastr:
                    insoa=False

                    r=parse_line(soastr)
                    # msg(repr(r))

                    if r[1]==None:
                        ttl=None
                    else:
                        ttl=parse_ttl(r[1])

                    # Sample r[4]:
                    #  hell.gr. root.hell.gr. ( 2012062203 24H 1H 1W 1H )
                    # After removal if ( and ):
                    #  hell.gr. root.hell.gr. 2012062203 24H 1H 1W 1H
                    # Fields:
                    #  0: ns0
                    #  1: contact
                    #  2: serial
                    #  3: refresh
                    #  4: retry
                    #  5: expire
                    #  6: minimum

                    t=r[4].replace('(','').replace(')','').split()

#                    if domain.strip('.')!=t[0].strip('.'):
#                        error("Domain doesn't match! (%s - %s)" % \
#                            (domain, t[0]))

                    if ttl==None:
                        ttl=defttl

                    soattl=ttl

                    self.dt['soa']={
                        'name':         domain,
                        'contact':      t[1],
                        'serial':       t[2],
                        'ttl':          ttl,
                        'refresh':      parse_ttl(t[3]),
                        'retry':        parse_ttl(t[4]),
                        'expire':       parse_ttl(t[5]),
                        'minimum':      parse_ttl(t[6]),
                        'ns0':          t[0],
                        'reverse':      False
                    }
#                    ins_soa(name=domain, contact=t[1], serial=t[2], ttl=ttl,
#                        refresh=t[3], retry=t[4], expire=t[5], minimum=t[6],
#                        ns0=t[0], reverse=False)

                continue

            r=parse_line(line)

            if r==None:
                continue

            if r[3]=='SOA':
                # domain=r[4].split()[0]
                if r[0]!='@':
                    if r[0]!=domain:
                        error("Domain doesn't match! (%s - %s)" % \
                            (domain, r[0]))

                domain=zone
                lastname=None

                logging.debug("Domain: " + domain)

                insoa=True
                soastr=line

                continue

            if lastname==None and (r[0]==None or r[0]=='@'):
                # msg("Zone entry: " + repr(r))
                lastname=None
            elif r[0]!=None:
                lastname=r[0]

            # For reverse we only need the soa
            if self.is_reverse:
                continue

            r2=[lastname] + list(r[1:])

            # Set TTL:
            #   If TTL if not specified:
            #       If current ttl (based on $TTL) is same as SOAs then
            #       leave TTL==None
            #       If current ttl<>SOA's ttl then set ttl as the current ttl
            #   If TTL is specified:
            #       If it is same as SOAs then set it to NULL
            #       Else use the specified TTL
            #
            # TTL is r2[1]
            if r2[1]==None:
                if soattl!=defttl:
                    r2[1]=defttl

            # Don't convert this to 'else'. This way it will catch cases
            # where r2[1]==None (initially) and soattl!=defttl. In that case
            # r2[1] will become non-null and will be rexamined in case it
            # matches the soattl
            if r2[1]!=None:
                r2[1]=parse_ttl(r2[1])
                if r2[1]==soattl:
                    r2[1]=None

            self.add_entry(r2)
#            handle_entry(domain, r2)

    def show(self):
        """
        Show the data
        """
        pprint(self.dt)

    def make_sql(self):
        """
        Return a list of SQL commands
        """

        dt=self.dt
        d=dt['domain']

        ret=[]

        for x in dt['a']:           ret.append(ins_a(d, *x))
        for x in dt['aaaa']:        ret.append(ins_a(d, *x))
        for x in dt['cname']:       ret.append(ins_cname(d, *x))
        for x in dt['ns']:          ret.append(ins_ns(d, *x))
        for x in dt['txt']:         ret.append(ins_txt(d, *x))
        for x in dt['mx']:          ret.append(ins_mx(d, *x))

        print('\n'.join(ret))

    def data(self):
        """
        Return the data dictionary
        """

        return(self.dt)

if __name__=='__main__':
    init()

    z=ZoneParser(Config.fn, Config.zone)

    if Config.output=='sql':
        z.make_sql()
    elif Config.output=='dump':
        z.show()
#    z.show()
#    z.make_sql()
#    doit()

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:

