#!/usr/bin/env python3
#

import enum
import logging
import datetime
import dataclasses as dc

import vdns.common

from typing import Any, Dict, Optional, Sequence, Type, Union


class BadRecordError(Exception):
    def __init__(self, msg: str, record: 'RR'):
        super().__init__(f'{msg}: {record}')


class _StringRecord:
    st: str
    # Override the hostname
    hostname: Optional[str]
    # Override the rrname
    rrname: Optional[str]
    autodot: int
    _needsdot: Optional[bool]

    def __init__(self, st: str, /, hostname: Optional[str] = None, rrname: Optional[str] = None,
                 needsdot: Optional[bool] = None, autodot: int = 0):
        self.st = st
        self.hostname = hostname
        self.rrname = rrname
        self._needsdot = needsdot
        self.autodot = autodot

    @property
    def needsdot(self) -> bool:
        if self._needsdot is not None:
            return self._needsdot

        return self.autodot > 0 and self.st.count('.') >= self.autodot

    @needsdot.setter
    def needsdot(self, value: bool) -> None:
        if not isinstance(value, property):
            self._needsdot = value


@dc.dataclass(kw_only=True)
class RR:
    domain: str
    hostname: Optional[str] = None
    ttl: Optional[datetime.timedelta] = None

    # To be reusable after overriding the rrname property
    def _rrname(self) -> str:
        return type(self).__qualname__

    @property
    def rrname(self) -> str:
        return self._rrname()

    @property
    def rrfields(self) -> list[str]:
        return [x.name for x in dc.fields(self)]

    def make_string(self, records: Sequence[_StringRecord]) -> str:
        ret = ''

        assert isinstance(records, Sequence)
        assert all(isinstance(x, _StringRecord) for x in records)

        for rec in records:
            if not rec.st:
                raise BadRecordError('Record is missing the data', self)

            if rec.needsdot and rec.st[-1] != '.':
                rec.st += '.'

            if rec.hostname is None:
                hostname = self.hostname
            else:
                hostname = rec.hostname

            if hostname == '.' or hostname is None:
                hostname = ''

            rrname = rec.rrname if rec.rrname else self.rrname

            ret += vdns.common.fmtrecord(hostname, self.ttl, rrname, rec.st)
            ret += '\n'

        ret = vdns.common.spaces2tabs(ret)

        return ret

    def _records(self) -> Union[_StringRecord, list[_StringRecord]]:
        raise NotImplementedError()

    def record(self) -> str:
        records = self._records()
        if not isinstance(records, Sequence):
            records = [records]

        return self.make_string(records)


@dc.dataclass
class MX(RR):
    priority: int
    mx: str

    def _records(self) -> _StringRecord:
        ret = _StringRecord(f'{self.priority:<4} {self.mx}')
        if self.mx.count('.') >= 2:
            ret.needsdot = True
        return ret


@dc.dataclass
class NS(RR):
    ns: str

    def _records(self) -> _StringRecord:
        ret = _StringRecord(self.ns)
        if self.ns.count('.') >= 2:
            ret.needsdot = True
        return ret


@dc.dataclass
class Host(RR):
    ip: vdns.common.IPAddress
    reverse: bool

    @property
    def rrname(self):
        if self.ip.version == 4:
            return 'A'
        elif self.ip.version == 6:
            return 'AAAA'
        else:
            raise BadRecordError('Unsupported IP version', self)

    def _records(self) -> _StringRecord:
        return _StringRecord(self.ip.compressed)


@dc.dataclass
class PTR(Host):
    net_domain: str

    @property
    def rrname(self):
        return self._rrname()

    def _records(self) -> _StringRecord:
        data = f'{self.hostname}.{self.domain}'

        if not self.reverse:
            raise BadRecordError("PTR attempted for non-reverse", self)
        if self.ip.version not in (4, 6):
            raise BadRecordError("Bad IP version", self)

        rev = self.ip.reverse_pointer

        # sanity check
        assert rev.endswith(f'.{self.net_domain}'), f"'{rev}' doesn't end with '{self.net_domain}'"
        hostname = rev.removesuffix(f'.{self.net_domain}')

        return _StringRecord(data, hostname=hostname, needsdot=True)


@dc.dataclass
class CNAME(RR):
    hostname0: str

    def _records(self) -> _StringRecord:
        return _StringRecord(self.hostname0, autodot=2)


@dc.dataclass
class TXT(RR):
    txt: str

    def _records(self) -> _StringRecord:
        data = f'"{self.txt}"'
        return _StringRecord(data)


@dc.dataclass
class DNSSEC(RR):
    keyid: int
    ksk: bool
    algorithm: int
    digest_sha1: str
    digest_sha256: str
    key_pub: str
    st_key_pub: str
    st_key_priv: str
    ts_created: datetime.datetime
    ts_activate: datetime.datetime
    ts_publish: datetime.datetime
    # ts_created: datetime.datetime
    # ts_activate: datetime.datetime
    # ts_publish: datetime.datetime


@dc.dataclass
class DNSKEY(DNSSEC):
    def _records(self) -> _StringRecord:
        if self.ksk:
            flags = 257
        else:
            flags = 256

        data = f'{flags} 3 {self.algorithm} {self.key_pub}'

        return _StringRecord(data)


@dc.dataclass
class DS(DNSSEC):
    def _records(self) -> list[_StringRecord]:
        ret = []
        ret.append(_StringRecord(f'{self.keyid} {self.algorithm} 1 {self.digest_sha1}'))
        ret.append(_StringRecord(f'{self.keyid} {self.algorithm} 2 {self.digest_sha256}'))
        return ret


@dc.dataclass
class SSHFP(RR):
    keytype: int
    hashtype: int
    fingerprint: str

    def _records(self) -> _StringRecord:
        data = f'{self.keytype} {self.hashtype} {self.fingerprint}'
        return _StringRecord(data)


@dc.dataclass(kw_only=True)
class DKIM(RR):
    selector: str
    k: str
    key_pub: str
    g: Optional[str] = None
    t: bool
    h: Optional[str] = None
    subdomains: bool

    def _records(self) -> _StringRecord:
        hostname = f'{self.selector}._domainkey'
        if self.hostname:
            hostname += f'.{self.hostname}'
        data0 = []
        data0.append('v=DKIM1')
        if self.g is not None:
            data0.append(f'g={self.g}')
        data0.append(f'k={self.k}')
        data0.append('s=email')
        if self.t or not self.subdomains:
            if self.t:
                if self.subdomains:
                    t = 'y'
                else:
                    t = 's:y'
            else:
                t = 's'
            data0.append(f't={t}')
        if self.h is not None:
            data0.append(f'h={self.h}')
        data0.append(f'p={self.key_pub}')

        data = vdns.common.split_txt('; '.join(data0))
        return _StringRecord(data, hostname=hostname, rrname='TXT')


@dc.dataclass(kw_only=True)
class SRV(RR):
    class Protocol(enum.Enum):
        tcp = 1
        udp = 2
        sctp = 3
        dccp = 4

    name: Optional[str] = None
    protocol: str
    service: str
    priority: int
    weight: int
    port: int
    target: str

    def _records(self) -> _StringRecord:
        hostname = f'_{self.service}._{self.protocol}'
        if self.name:
            hostname += f'.{self.name}'
        data = f'{self.priority} {self.weight} {self.port} {self.target}'
        needsdot = self.target.count('.') >= 1
        return _StringRecord(data, hostname=hostname, needsdot=needsdot)


@dc.dataclass
class SOA:
    name: str
    ttl: datetime.timedelta
    refresh: datetime.timedelta
    retry: datetime.timedelta
    expire: datetime.timedelta
    minimum: datetime.timedelta
    contact: str
    serial: int
    ns0: str
#    ts: datetime.datetime
#    reverse: bool
#    updated: Optional[datetime.datetime] = None

    def record(self) -> str:
        ttl = vdns.common.zone_fmttd(self.ttl)
        refresh = vdns.common.zone_fmttd(self.refresh)
        retry = vdns.common.zone_fmttd(self.retry)
        expire = vdns.common.zone_fmttd(self.expire)
        minimum = vdns.common.zone_fmttd(self.minimum)

        ret = f'''\
$ORIGIN		{self.name}.
$TTL		{ttl.value}	; {ttl.human_readable}
@		{ttl.value}	IN	SOA	{self.ns0}. {self.contact}. (
                                {self.serial:<15} ; serial
                                {refresh.value:<15} ; refresh ({refresh.human_readable})
                                {retry.value:<15} ; retry ({retry.human_readable})
                                {expire.value:<15} ; expire ({expire.human_readable})
                                {minimum.value:<15} ; minimum ({minimum.human_readable})
                                )

'''
        return vdns.common.spaces2tabs(ret)


@dc.dataclass
class Domain:
    name: str
    # reverse: bool = False
    soa: SOA
    mx: list[MX] = dc.field(default_factory=list)
    ns: list[NS] = dc.field(default_factory=list)
    hosts: list[Host] = dc.field(default_factory=list)
    cnames: list[CNAME] = dc.field(default_factory=list)
    txt: list[TXT] = dc.field(default_factory=list)
    dnssec: list[DNSKEY] = dc.field(default_factory=list)
    sshfp: list[SSHFP] = dc.field(default_factory=list)
    dkim: list[DKIM] = dc.field(default_factory=list)
    srv: list[SRV] = dc.field(default_factory=list)


def make_rr(rrtype: Union[Type[RR], Type[SOA]], data: Dict[Any, Any], eat=True) -> RR:
    """Constructs an RR from a dictionary, ignoring extra entries in the dict."""
    fields = [x.name for x in dc.fields(rrtype)]
    data2 = {k: v for k, v in data.items() if not eat or k in fields}
    return rrtype(**data2)  # type: ignore


if __name__ == '__main__':
    def td(i: int) -> datetime.timedelta:
        return datetime.timedelta(seconds=i)

    s = {'domain': 'v13.gr', 'contact': 'v13@v13.gr', 'ttl': td(3600),
         'refresh': td(3600), 'retry': td(600), 'expire': td(86400), 'minimum': td(60),
         'serial': 100, 'ns0': 'ns1.v13.gr', 'ts': datetime.datetime.now(), 'reverse': False,
         'nothing': 'something'}
    soa = make_rr(SOA, s)

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
