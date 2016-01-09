#!/usr/bin/env python
# coding=UTF-8
#

import sys
import socket
import logging

def python3():
    """!
    @return True if we are running python3
    """
    if sys.version_info < (3,0):
        ret=False
    else:
        ret=True

    return(ret)

def addr_family(addr):
    """
    Return the address family
    
    @param addr     The IP address
    """
    if type(addr)!=str:
        addr2=addr.addr
    else:
        addr2=addr

    if ':' in addr2:
        ret=6
    else:
        ret=4

    return(ret)

def ip_to_octets(ip):
    """
    Get an IP address and return an array of "octets".

    In case of IPv4:
        '10.1.1.0' => [10, 1, 1, 0]
    In case of IPv6:
        '2a01:348:180::2' => [2,a,0,1,0,3,4,8,0,1,8,0,0,0,....,2]

    @param ip       The IP address as a string
    @return A list of octets (for a certain definition of octets)
    """

    family=addr_family(ip)

    if family==4:
        octets=[]
        for x in ip.split('.'):
            octets.append(int(x))
    elif family==6:
        octets=[]
        addr=socket.inet_pton(socket.AF_INET6, ip)
        # Get each byte
        for x in addr:
            # Handle each 4 bits

            # Python3 doesn't need ord
            if python3():
                x2=x
            else:
                x2=ord(x)

            octets.append(x2>>4)
            octets.append(x2&0x0F)
    else:
        logging.error('Bad address family: %s' % (addr_family(ip)))
        abort('I cannot work like this')

    return(octets)

def reverse_name(net):
    """
    Form the domain name of an IP network/address
    
    @param net      Is in the form 10.0.0.0/8
    """

    (ip, mask)=net.split('/', 1)

    if int(mask)%8 != 0:
        logging.error('Mask must be multiple of 8')
        abort("I don't know what to do")

    num=int(int(mask)/8)
    octets=ip_to_octets(ip)

    family=addr_family(ip)
    if family==4:
        octets=octets[:num]
        octets.reverse()
        octets2=['%d' % (x,) for x in octets]
        st='.'.join(octets2)
        st+='.in-addr.arpa'
    elif family==6:
        octets=octets[:num*2]
        octets.reverse()
        octets2=['%01x' % (x,) for x in octets]
        st='.'.join(octets2)
        st+='.ip6.arpa'
    else:
        logging.error('Bad address family: %s' % (family,))
        abort('I cannot handle this address type')

    return(st)

    if addr_family(ip)==4:
        if not int(mask) in (8,16,24,32):
            logging.error('Cannot handle mask %s for "%s"', mask, net)
            abort("I don't know what to do")

        num=int(mask)/8

        octets=ip.split('.')[:num]
        octets.reverse()

        st='.'.join(octets[:num])
        st+='.in-addr.arpa'
    elif addr_family(ip)==6:
        if int(mask) % 8!=0:
            abort('IPv6 prefix must be a multiple of 8')
        num=int(mask)/8
        octets=[]
        addr=socket.inet_pton(socket.AF_INET6, ip)
        # Get each byte
        for x in addr:
            # Handle each 4 bits
            x2=ord(x)
            octets.append('%01x' % (x2>>4,))
            octets.append('%01x' % (x2&0x0F,))

        octets=octets[:num*2]
        octets.reverse()
        st='.'.join(octets)
        st+='.ip6.arpa'
    else:
        logging.error('Bad address family: %s' % (addr_family(ip)))
        abort('I cannot handle this address type')

    return(st)


def abort(reason):
    logging.error('%s' % reason)
    sys.exit(1)

if __name__=="__main__":
    pass

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:

