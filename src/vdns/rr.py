#!/usr/bin/env python3
#

import dataclasses as dc
import datetime

import vdns.common

from typing import Any, Dict, List, Type


@dc.dataclass
class RR:

    @property
    def rrname(self) -> str:
        return type(self).__qualname__

    @property
    def rrfields(self) -> List[str]:
        return [x.name for x in dc.fields(self)]


@dc.dataclass
class BaseRecord(RR):
    domain: str
    hostname: str
    ttl: int


@dc.dataclass
class MX(BaseRecord):
    priority: int
    mx: str


@dc.dataclass
class NS(BaseRecord):
    ns: str


@dc.dataclass
class Host(BaseRecord):
    ip: vdns.common.IPAddress


@dc.dataclass
class CNAME(BaseRecord):
    hostname0: str


@dc.dataclass
class TXT(BaseRecord):
    txt: str


@dc.dataclass
class DNSSEC(BaseRecord):
    id: int     # Internal id, not exported
    keyid: str
    ksk: str
    algorithm: str
    digest_sha1: str
    digest_sha256: str
    key_pub: str
    st_key_pub: str
    st_key_priv: str
    ts_created: datetime.datetime
    ts_activate: datetime.datetime
    ts_publish: datetime.datetime


@dc.dataclass
class SSHFP(BaseRecord):
    keytype: str
    hashtype: str
    fingerprint: str


@dc.dataclass
class DKIM(BaseRecord):
    selector: str
    k: str
    key_pub: str
    g: str
    t: str
    h: str
    subdomains: str


@dc.dataclass
class SRV(BaseRecord):
    name: str
    protocol: str
    service: str
    priority: int
    weight: int
    port: int
    target: str


@dc.dataclass
class SOA(RR):
    contact: str = ''
    ns0: str = ''
    ttl: int = 86400
    refresh: int = 86400
    retry: int = 3600
    expire: int = 86400 * 30 * 3
    minimum: int = 60
    serial: int = 1


@dc.dataclass
class Domain:
    name: str
    reverse: bool = False
    soa: SOA = dc.field(default_factory=SOA)
    mx: List[MX] = dc.field(default_factory=list)
    ns: List[NS] = dc.field(default_factory=list)
    hosts: List[Host] = dc.field(default_factory=list)
    cnames: List[CNAME] = dc.field(default_factory=list)
    txt: List[TXT] = dc.field(default_factory=list)
    dnssec: List[DNSSEC] = dc.field(default_factory=list)
    sshfp: List[SSHFP] = dc.field(default_factory=list)
    dkim: List[DKIM] = dc.field(default_factory=list)
    srv: List[SRV] = dc.field(default_factory=list)


def make_rr(rrtype: Type[RR], data: Dict[Any, Any]) -> RR:
    """Constructs an RR from a dictionary, ignoring extra entries in the dict."""
    fields = [x.name for x in dc.fields(rrtype)]
    data2 = {k: v for k, v in data.items() if k in fields}
    return rrtype(**data2)


if __name__ == '__main__':
    s = {'name': 'asdf', 'contact': 'v13@v13.gr', 'ttl': 3600, 'nothing': 'something'}
    soa = rr(SOA, s)
    print(f'{soa.rrname}: {soa.rrfields}')
    print(soa)

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
