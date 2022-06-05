import enum
import datetime
import dataclasses as dc
import ipaddress

import vdns.common

from typing import Any, Dict, Optional, Sequence, Type, TypeVar, Union


class BadRecordError(Exception):
    def __init__(self, msg: str, record: 'RR'):
        super().__init__(f'{msg}: {record}')


class _StringRecord:
    """Holds the resulting RR string, plus a few related information. Used as a return type for make_string()."""
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

    def validate(self) -> None:
        vdns.common.validate_dataclass(self)

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

        return ret

    def _records(self) -> Union[_StringRecord, list[_StringRecord]]:
        raise NotImplementedError()

    def record(self) -> str:
        self.validate()
        records = self._records()
        if not isinstance(records, Sequence):
            records = [records]

        return self.make_string(records)

    @property
    def sort_key(self) -> Any:
        return self.hostname

    def __lt__(self, other: 'RR') -> bool:
        if self.hostname is None:
            return True
        if other.hostname is None:
            return False
        return self.hostname < other.hostname


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
    reverse: Optional[bool]

    @property
    def rrname(self) -> str:
        if self.ip.version == 4:
            return 'A'
        if self.ip.version == 6:
            return 'AAAA'
        raise BadRecordError('Unsupported IP version', self)

    def _records(self) -> _StringRecord:
        return _StringRecord(self.ip.compressed)

    @property
    def as_ipv6(self) -> ipaddress.IPv6Address:
        if self.ip.version == 6:
            return self.ip
        return ipaddress.IPv6Address(f'::{self.ip.compressed}')

    @property
    def sort_key(self) -> Any:
        return self.as_ipv6


@dc.dataclass
class PTR(Host):
    net_domain: str

    @property
    def rrname(self) -> str:
        return self._rrname()

    def _records(self) -> _StringRecord:
        if self.hostname:
            data = f'{self.hostname}.{self.domain}'
        else:
            data = self.domain

        if not self.reverse:
            raise BadRecordError('PTR attempted for non-reverse', self)
        if self.ip.version not in (4, 6):
            raise BadRecordError('Bad IP version', self)

        rev = self.ip.reverse_pointer

        # sanity check
        assert rev.endswith(f'.{self.net_domain}'), f"'{rev}' doesn't end with '{self.net_domain}'"
        hostname = rev.removesuffix(f'.{self.net_domain}')

        return _StringRecord(data, hostname=hostname, needsdot=True)

    @classmethod
    def from_host(cls, host: Host, net_domain: str) -> 'PTR':
        return cls(net_domain=net_domain, **dc.asdict(host))

    def __lt__(self, other: 'RR') -> bool:
        assert isinstance(other, PTR)
        # IPv4 before IPv6, then normal order based on the packed version
        s1 = b'%d-%b' % (self.ip.version, self.ip.packed)
        s2 = b'%d-%b' % (other.ip.version, other.ip.packed)
        return s1 < s2


@dc.dataclass
class CNAME(RR):
    hostname0: str

    def _records(self) -> _StringRecord:
        return _StringRecord(self.hostname0, autodot=2)

    @property
    def sort_key(self) -> Any:
        if self.hostname.endswith('_domainkey'):
            return f'zzzz_{self.hostname}'
        return self.hostname


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

    def _records(self) -> Union[_StringRecord, list[_StringRecord]]:
        raise NotImplementedError


@dc.dataclass
class DNSKEY(DNSSEC):
    def _records(self) -> _StringRecord:
        if self.ksk:
            flags = 257
        else:
            flags = 256

        data = f'{flags} 3 {self.algorithm} {self.key_pub}'

        return _StringRecord(data)

    @classmethod
    def from_dnssec(cls, dnssec: DNSSEC) -> 'DNSKEY':
        """Constructs a DNSKEY class from a DNSSEC class."""
        return DNSKEY(**dc.asdict(dnssec))


@dc.dataclass
class DS(DNSSEC):
    def _records(self) -> list[_StringRecord]:
        ret = []
        ret.append(_StringRecord(f'{self.keyid} {self.algorithm} 1 {self.digest_sha1}'))
        ret.append(_StringRecord(f'{self.keyid} {self.algorithm} 2 {self.digest_sha256}'))
        return ret

    @classmethod
    def from_dnssec(cls, dnssec: DNSSEC) -> 'DS':
        """Constructs a DS class from a DNSSEC class."""
        return DS(**dc.asdict(dnssec))


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
    name: str = ''
    ttl: datetime.timedelta = datetime.timedelta(days=1)
    refresh: datetime.timedelta = datetime.timedelta(hours=24)
    retry: datetime.timedelta = datetime.timedelta(hours=1)
    expire: datetime.timedelta = datetime.timedelta(days=90)
    minimum: datetime.timedelta = datetime.timedelta(minutes=1)
    contact: str = ''
    serial: int = 1
    ns0: str = ''
#    ts: datetime.datetime
#    reverse: bool
#    updated: Optional[datetime.datetime] = None

    def record(self) -> str:
        ttl = vdns.common.zone_fmttd(self.ttl)
        refresh = vdns.common.zone_fmttd(self.refresh)
        retry = vdns.common.zone_fmttd(self.retry)
        expire = vdns.common.zone_fmttd(self.expire)
        minimum = vdns.common.zone_fmttd(self.minimum)

        ttl2 = vdns.common.tabify(ttl.value, 8)
        serial2 = vdns.common.tabify(str(self.serial), 16)
        refresh2 = vdns.common.tabify(refresh.value, 16)
        retry2 = vdns.common.tabify(retry.value, 16)
        expire2 = vdns.common.tabify(expire.value, 16)
        minimum2 = vdns.common.tabify(minimum.value, 16)

        ret = f'''\
$ORIGIN\t\t\t{self.name}.
$TTL\t\t\t{ttl2}; {ttl.human_readable}
@\t\t\t{ttl2}IN	SOA	{self.ns0}. {self.contact}. (
\t\t\t\t\t{serial2} ; serial
\t\t\t\t\t{refresh2} ; refresh ({refresh.human_readable})
\t\t\t\t\t{retry2} ; retry ({retry.human_readable})
\t\t\t\t\t{expire2} ; expire ({expire.human_readable})
\t\t\t\t\t{minimum2} ; minimum ({minimum.human_readable})
\t\t\t\t\t)

'''
        return ret

    def __lt__(self, other: 'SOA') -> bool:
        return self.name < other.name


T_RR_SOA = TypeVar('T_RR_SOA', bound=Union[RR, SOA])


def make_rr(rrtype: Union[Type[T_RR_SOA]], data: Dict[Any, Any], eat: bool = True) -> T_RR_SOA:
    """Constructs an RR from a dictionary, ignoring extra entries in the dict."""
    fields = [x.name for x in dc.fields(rrtype)]
    data2 = {k: v for k, v in data.items() if not eat or k in fields}
    return rrtype(**data2)  # type: ignore

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
