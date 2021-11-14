#!/usr/bin/env python
# coding=UTF-8
#

# import sys
# import socket
import logging
import ipaddress

from typing import Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPInterface = Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class AbortError(Exception):
    def __init__(self, *args, excode=1, **kwargs):
        """Indicates a program abort with exit code."""
        self.excode = excode
        super().__init__(*args, **kwargs)


def reverse_name(net: str) -> str:
    """
    Form the domain name of an IP network/address

    @param net      Is in the form 10.0.0.0/8
    """

    network: IPNetwork = ipaddress.ip_network(net)
    ip: IPAddress = network.network_address

    if network.version == 4:
        octet_size = 8
        octet_number = 4
    elif network.version == 6:
        octet_size = 4
        octet_number = 32
    else:
        logging.error('Bad address family: %s', network.version)
        abort('I cannot handle this address type')

    if network.prefixlen % octet_size != 0:
        logging.error('Mask must be multiple of %d for IPv%d', octet_size, network.version)
        abort("I don't know what to do")

    num = network.prefixlen // octet_size
    octets = ip.reverse_pointer.split('.')
    st = '.'.join(octets[(octet_number - num):])

    return st


def abort(reason):
    logging.error('%s', reason)
    raise AbortError(reason, excode=1)


if __name__ == '__main__':
    pass

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
