# Copyright (c) 2014-2016 Stefanos Harhalakis <v13@v13.gr>
# Copyright (c) 2016-2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import enum
import datetime
import dataclasses as dc
import ipaddress

import vdns.db
import vdns.common
import vdns.parsing

from typing import Any, Dict, Optional, Protocol, Sequence, Type, TypeVar, Union


T = TypeVar('T', bound='RR')


class BadRecordError(Exception):
    def __init__(self, msg: str, record: 'RR'):
        super().__init__(f'{msg}: {record}')


class ParseLineInput(Protocol):
    addr1: Optional[str]
    ttl: Optional[datetime.timedelta]
    addr2: str


class ParseError(Exception):
    def __init__(self, msg: str, r: ParseLineInput) -> None:
        super().__init__(f'{msg}. addr1="{r.addr1}, addr2={r.addr2}')


class _StringRecord:
    """Holds the resulting RR string, plus a few related information. Used as a return type for make_string()."""
    st: str
    multiline_st: Sequence[str]
    comment: str
    # Override the hostname
    hostname: Optional[str]
    # Override the rrname
    rrname: Optional[str]
    autodot: int
    _needsdot: Optional[bool]

    def __init__(self, st: str, *, multiline_st: Sequence[str] = (), comment: str = '', hostname: Optional[str] = None,
                 rrname: Optional[str] = None, needsdot: Optional[bool] = None, autodot: int = 0):
        self.st = st
        self.multiline_st = multiline_st
        self.comment = comment
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
    """
    There are three hostnames:
    - hostname: The actual hostname record
    - associated_hostname: A hostname that this record is associated with.
                           For example for DKIM records (selector._domainkey.hostname)
    - coocked_hostname: The hostname that will be added to the records.
                        For example for SRV records (_xmpp-client._tcp)
    """
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
            if not rec.st and not rec.multiline_st:
                raise BadRecordError('Record is missing the data', self)

            if rec.multiline_st and rec.needsdot:
                raise BadRecordError('Cannot use needsdot with multiline strings', self)

            if rec.needsdot and rec.st[-1] != '.':
                rec.st += '.'

            if rec.hostname is None:
                hostname = self.cooked_hostname
            else:
                hostname = rec.hostname

            if hostname == '.' or hostname is None:
                hostname = ''

            rrname = rec.rrname if rec.rrname else self.rrname

            ret += vdns.common.fmtrecord(hostname, self.ttl, rrname, rec.st, rec.multiline_st, rec.comment)
            ret += '\n'

        return ret

    def _records(self) -> Union[_StringRecord, list[_StringRecord]]:
        raise NotImplementedError

    def record(self) -> str:
        self.validate()
        records = self._records()
        if not isinstance(records, Sequence):
            records = [records]

        return self.make_string(records)

    @classmethod
    def parse_line(cls: Type[T], domain: str, r: ParseLineInput) -> T:
        raise NotImplementedError

    @property
    def sort_key(self) -> Any:
        return self.cooked_hostname

    def __lt__(self, other: 'RR') -> bool:
        if self.sort_key is None:
            return True
        if other.sort_key is None:
            return False
        return self.sort_key < other.sort_key

    def __gt__(self, other: 'RR') -> bool:
        if self.sort_key is None:
            return False
        if other.sort_key is None:
            return True
        return self.sort_key > other.sort_key

    @property
    def associated_hostname(self) -> Optional[str]:
        """Returns the hostname that this record should be associated with.
        For cases like CNAMEs where they are associated with the target hostname and should be listed close to that.
        """
        # self.hostname and not self.cooked_hostname
        return self.hostname

    @property
    def cooked_hostname(self) -> Optional[str]:
        """The hostname to be added to the zone file. In cases like DKIM, the listed hostname has extra parts."""
        return self.hostname

    @property
    def dbfields(self) -> tuple[str, ...]:
        """Returns the names of the database fields for this RR."""
        return 'domain', 'hostname', 'ttl'

    def dbvalues(self) -> vdns.db.QueryArgs:
        """Returns a dict suitable for an insert to the database."""
        dt = dc.asdict(self)
        ret: vdns.db.QueryArgs = {x: dt[x] for x in self.dbfields}
        return ret


@dc.dataclass(kw_only=True)
class MX(RR):
    priority: int
    mx: str

    def _records(self) -> _StringRecord:
        ret = _StringRecord(f'{self.priority:<4} {self.mx}')
        if self.mx.count('.') >= 2:
            ret.needsdot = True
        return ret

    @classmethod
    def parse_line(cls, domain: str, r: ParseLineInput) -> 'MX':
        dt = r.addr2.split(None, 1)
        # pylint: disable=unexpected-keyword-arg
        return MX(domain=domain, hostname=r.addr1, priority=int(dt[0]), mx=dt[1], ttl=r.ttl)
        # pylint: enable=unexpected-keyword-arg


@dc.dataclass(kw_only=True)
class NS(RR):
    ns: str

    def _records(self) -> _StringRecord:
        ret = _StringRecord(self.ns)
        if self.ns.count('.') >= 2:
            ret.needsdot = True
        return ret

    @classmethod
    def parse_line(cls, domain: str, r: ParseLineInput) -> 'NS':
        # pylint: disable=unexpected-keyword-arg
        return NS(domain=domain, hostname=r.addr1, ns=r.addr2, ttl=r.ttl)
        # pylint: enable=unexpected-keyword-arg


@dc.dataclass(kw_only=True)
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

    @classmethod
    def parse_line(cls, domain: str, r: ParseLineInput) -> 'Host':
        # pylint: disable=unexpected-keyword-arg
        return Host(domain=domain, hostname=r.addr1, ip=ipaddress.ip_address(r.addr2), ttl=r.ttl, reverse=False)
        # pylint: enable=unexpected-keyword-arg


@dc.dataclass(kw_only=True)
class PTR(Host):
    net_domain: str

    @property
    def rrname(self) -> str:
        return self._rrname()

    @property
    def cooked_hostname(self) -> Optional[str]:
        rev = self.ip.reverse_pointer
        # sanity check
        assert rev.endswith(f'.{self.net_domain}'), f"'{rev}' doesn't end with '{self.net_domain}'"
        hostname = rev.removesuffix(f'.{self.net_domain}')
        return hostname

    def _records(self) -> _StringRecord:
        if self.hostname:
            data = f'{self.hostname}.{self.domain}'
        else:
            data = self.domain

        if not self.reverse:
            raise BadRecordError('PTR attempted for non-reverse', self)
        if self.ip.version not in (4, 6):
            raise BadRecordError('Bad IP version', self)

        return _StringRecord(data, needsdot=True)

    @classmethod
    def from_host(cls, host: Host, net_domain: str) -> 'PTR':
        return cls(net_domain=net_domain, **dc.asdict(host))

    @property
    def sort_key(self) -> Any:
        return b'%d-%b' % (self.ip.version, self.ip.packed)

    @classmethod
    def parse_line(cls: Type['PTR'], domain: str, r: ParseLineInput) -> 'PTR':
        # pylint: disable=unexpected-keyword-arg
        raise NotImplementedError
        # pylint: enable=unexpected-keyword-arg


@dc.dataclass(kw_only=True)
class CNAME(RR):
    hostname0: str

    def _records(self) -> _StringRecord:
        return _StringRecord(self.hostname0, autodot=2)

    @property
    def sort_key(self) -> Any:
        if self.hostname and self.hostname.endswith('_domainkey'):
            return f'zzzz_{self.hostname}'
        return self.hostname

    @property
    def associated_hostname(self) -> Optional[str]:
        return self.hostname0

    @classmethod
    def parse_line(cls, domain: str, r: ParseLineInput) -> 'CNAME':
        # pylint: disable=unexpected-keyword-arg
        return CNAME(domain=domain, hostname=r.addr1, hostname0=r.addr2, ttl=r.ttl)
        # pylint: enable=unexpected-keyword-arg


@dc.dataclass(kw_only=True)
class TXT(RR):
    txt: str

    def _records(self) -> _StringRecord:
        data = f'"{self.txt}"'
        return _StringRecord(data)

    # TODO: Use this and introduce a associated_hostname() property, which should be used for
    # looking up the hostname to associate entries with. This way the _spf records for hosts will be
    # associated with the hosts themselves
    @property
    def sort_key(self) -> Any:
        if self.hostname and self.hostname.startswith('_spf.'):
            return self.hostname.removeprefix('_spf.') + '_zzzz'
        return self.hostname

    @property
    def associated_hostname(self) -> Optional[str]:
        if self.hostname and self.hostname.startswith('_spf.'):
            return self.hostname.removeprefix('_spf.')
        return self.hostname

    @classmethod
    def parse_line(cls, domain: str, r: ParseLineInput) -> 'TXT':
        txt = r.addr2
        if txt[0] == '"' and txt[-1] == '"':
            txt = txt[1:-1]

        # pylint: disable=unexpected-keyword-arg
        return TXT(domain=domain, hostname=r.addr1, txt=txt, ttl=r.ttl)
        # pylint: enable=unexpected-keyword-arg


@dc.dataclass(kw_only=True)
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

    # https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    class Algos(enum.Enum):
        RSASHA1 = 5
        NSEC3RSASHA1 = 7
        RSASHA256 = 8
        RSASHA512 = 9
        ECDSAP256SHA256 = 13
        ECDSAP384SHA384 = 14
        ED25519 = 15
        ED448 = 16

    def _records(self) -> Union[_StringRecord, list[_StringRecord]]:
        raise NotImplementedError

    @property
    def dbfields(self) -> tuple[str, ...]:
        return ('domain', 'ttl', 'keyid', 'ksk', 'algorithm', 'digest_sha1', 'digest_sha256', 'key_pub',
                'st_key_pub', 'st_key_priv', 'ts_created', 'ts_activate', 'ts_publish')


@dc.dataclass(kw_only=True)
class DNSKEY(DNSSEC):
    def _records(self) -> _StringRecord:
        if self.ksk:
            flags = 257
            key_st = 'KSK'
        else:
            flags = 256
            key_st = 'ZSK'

        data = f'{flags} 3 {self.algorithm}'
        multiline_data = self.key_pub.split()
        algo = self.Algos(self.algorithm)
        comment = f'{key_st} ; alg = {algo.name} ; key id = {self.keyid}'

        return _StringRecord(data, multiline_st=multiline_data, comment=comment)

    @classmethod
    def from_dnssec(cls, dnssec: DNSSEC) -> 'DNSKEY':
        """Constructs a DNSKEY class from a DNSSEC class."""
        return DNSKEY(**dc.asdict(dnssec))

    @classmethod
    def _parse_dnskey(cls, addr: str) -> 'DNSKEY':
        now = datetime.datetime.fromtimestamp(0)

        pl = vdns.parsing.ParsedLine(
            addr1='something',
            addr2=addr,
            rr='DNSKEY',
        )
        r = vdns.parsing.parse_pub_key_line(pl)

        # Caller must set domain, hostname and ttl.
        # pylint: disable=unexpected-keyword-arg
        dnssec = vdns.rr.DNSSEC(
            domain='',
            hostname='',
            ttl=None,
            keyid=r.keyid,
            ksk=r.ksk,
            algorithm=r.algorithm,
            digest_sha1=r.sha1,
            digest_sha256=r.sha256,
            key_pub=r.key_pub,
            st_key_pub='',
            st_key_priv='',
            ts_created=now,
            ts_activate=now,
            ts_publish=now
        )
        # pylint: enable=unexpected-keyword-arg
        return cls.from_dnssec(dnssec)

    @classmethod
    def parse_line(cls: Type['DNSKEY'], domain: str, r: ParseLineInput) -> 'DNSKEY':
        if r.addr1:
            raise ParseError('DNSKEY record with non-empty hostname', r)
        ret = cls._parse_dnskey(r.addr2)
        ret.hostname = r.addr1
        ret.domain = domain
        ret.ttl = r.ttl
        return ret


@dc.dataclass(kw_only=True)
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

    @classmethod
    def parse_line(cls, domain: str, r: ParseLineInput) -> 'DS':
        if not r.addr1:
            raise ParseError('DS record without a hostname', r)

        now = datetime.datetime.fromtimestamp(0)

        ds_split = r.addr2.split(None, 3)
        if len(ds_split) != 4:
            vdns.common.abort(f'Bad DS line: {r.addr2}')

        # pylint: disable=unexpected-keyword-arg
        dnssec = DNSSEC(domain=domain, hostname=r.addr1, keyid=int(ds_split[0]), ksk=True, algorithm=8,
                        digest_sha1='', digest_sha256='', key_pub='', st_key_pub='', st_key_priv='',
                        ts_created=now, ts_activate=now, ts_publish=now)
        # pylint: enable=unexpected-keyword-arg
        ds = cls.from_dnssec(dnssec)

        if ds_split[1] != '8':
            raise ParseError(f'Cannot handle protocol "{ds_split[1]}"', r)

        if ds_split[2] == '1':
            ds.digest_sha1 = ds_split[3]
        elif ds_split[2] == '2':
            ds.digest_sha256 = ds_split[3]
        else:
            raise ParseError(f'Cannot handle digest type "{ds_split[2]}"', r)

        return ds


@dc.dataclass(kw_only=True)
class SSHFP(RR):
    keytype: int
    hashtype: int
    fingerprint: str

    def _records(self) -> _StringRecord:
        data = f'{self.keytype} {self.hashtype} {self.fingerprint}'
        return _StringRecord(data)

    @classmethod
    def parse_line(cls: Type['SSHFP'], domain: str, r: ParseLineInput) -> 'SSHFP':
        dt = r.addr2.split(None, 2)
        # pylint: disable=unexpected-keyword-arg
        return SSHFP(domain=domain, hostname=r.addr1, keytype=int(dt[0]), hashtype=int(dt[1]), fingerprint=dt[2],
                     ttl=r.ttl)
        # pylint: enable=unexpected-keyword-arg


@dc.dataclass(kw_only=True)
class DKIM(RR):
    selector: str
    k: str
    key_pub: str
    g: Optional[str] = None
    t: bool
    h: Optional[str] = None
    subdomains: bool

    @property
    def cooked_hostname(self) -> Optional[str]:
        hostname = f'{self.selector}._domainkey'
        if self.hostname:
            hostname += f'.{self.hostname}'
        return hostname

    def _records(self) -> _StringRecord:
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
        lines = vdns.common.split_txt_multiline('; '.join(data0))

        return _StringRecord(st='', multiline_st=lines, rrname='TXT')

    @classmethod
    def _parse_dkim(cls, addr1: str, addr2: str) -> 'DKIM':
        addr1_split = addr1.split('.', 2)
        assert addr1_split[1] == '_domainkey'

        if len(addr1_split) > 2:
            hostname = addr1_split[2]
        else:
            hostname = None

        selector = addr1_split[0]
        k: str = ''
        key_pub: str = ''
        g: Optional[str] = None
        t: bool = False
        h: Optional[str] = None
        subdomains: bool = False

        if addr2[0] == '"' and addr2[-1] == '"':
            addr2 = addr2[1:-1]

        for entry in addr2.split(';'):
            entry = entry.strip()
            key, value = entry.split('=', 1)
            if key == 'v':
                assert value == 'DKIM1', f'Only DKIM1 is supported. Found: {value}'
            elif key == 'g':
                g = value
            elif key == 'p':
                key_pub = value
            elif key == 'k':
                k = value
            elif key == 's':
                pass
            elif key == 't':
                if value == 'y':
                    subdomains = True
                    t = True
                elif value == 's:y':
                    subdomains = False
                    t = True
                elif value == 's':
                    t = False
                elif value == '':
                    pass
                else:
                    vdns.common.abort(f'Unhandled t value for DKIM record: "{addr2}"')
            elif key == 'h':
                h = value

        assert k != ''
        assert key_pub != ''

        # Caller must set domain and ttl
        # pylint: disable=unexpected-keyword-arg
        return vdns.rr.DKIM(domain='', hostname=hostname, ttl=None,
                            selector=selector, k=k, key_pub=key_pub, g=g, t=t, h=h, subdomains=subdomains)
        # pylint: enable=unexpected-keyword-arg

    @classmethod
    def parse_line(cls, domain: str, r: ParseLineInput) -> 'DKIM':
        # pylint: disable=unexpected-keyword-arg
        if not r.addr1 or not (r.addr1.endswith('._domainkey') or '._domainkey.' in r.addr1):
            raise ParseError('Not a DKIM host', r)

        dkim = cls._parse_dkim(r.addr1, r.addr2)
        dkim.domain = domain
        dkim.ttl = r.ttl
        return dkim
        # pylint: enable=unexpected-keyword-arg


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

    @property
    def cooked_hostname(self) -> Optional[str]:
        hostname = f'_{self.service}._{self.protocol}'
        if self.name:
            hostname += f'.{self.name}'
        return hostname

    def _records(self) -> _StringRecord:
        data = f'{self.priority} {self.weight} {self.port} {self.target}'
        needsdot = self.target.count('.') >= 1
        return _StringRecord(data, needsdot=needsdot)

    @classmethod
    def parse_line(cls, domain: str, r: ParseLineInput) -> 'SRV':
        if not r.addr1 or len(t := r.addr1.split('.', 2)) <= 1 or not t[0].startswith('_') or not t[1].startswith('_'):
            vdns.common.abort(f'Bad SRV hostname: {r.addr1}')

        hostname = t[2] if len(t) == 3 else ''
        service = t[0][1:]
        protocol = t[1][1:]

        if not r.addr2 or not len(t := r.addr2.split(None, 3)) == 4:
            vdns.common.abort(f'Bad SRV record: {r.addr2}')

        priority = int(t[0])
        weight = int(t[1])
        port = int(t[2])
        target = t[3]

        # pylint: disable=unexpected-keyword-arg
        return SRV(
            name=hostname,
            hostname=None,
            ttl=r.ttl,
            service=service,
            protocol=protocol,
            domain=domain,
            priority=priority,
            weight=weight,
            port=port,
            target=target
        )
        # pylint: enable=unexpected-keyword-arg


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

    def __gt__(self, other: 'SOA') -> bool:
        return self.name > other.name


T_RR_SOA = TypeVar('T_RR_SOA', bound=Union[RR, SOA])


def make_rr(rrtype: Union[Type[T_RR_SOA]], data: Dict[Any, Any], eat: bool = True) -> T_RR_SOA:
    """Constructs an RR from a dictionary, ignoring extra entries in the dict."""
    fields = [x.name for x in dc.fields(rrtype)]
    data2 = {k: v for k, v in data.items() if not eat or k in fields}
    return rrtype(**data2)  # type: ignore

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
