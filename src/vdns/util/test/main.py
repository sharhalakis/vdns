import copy
import difflib

import vdns.rr
import vdns.src.src0
import vdns.util.config
import vdns.zone
import vdns.zone0
import vdns.common
import vdns.zonemaker
import vdns.zoneparser

from typing import Optional, TypeVar

T = TypeVar('T', bound=vdns.rr.RR)


class TestSource(vdns.src.src0.Source):

    _dt: vdns.zoneparser.ParsedDomainData

    def __init__(self, domain: str, data: vdns.zoneparser.ParsedDomainData):
        self._dt = data
        super().__init__(domain)

    def get_data(self) -> Optional[vdns.src.src0.DomainData]:
        def flt(entries: list[T]) -> list[T]:
            return [x for x in entries if x.domain == self.domain]

        def flt_sub(entries: list[T]) -> list[T]:
            ret: list[T] = []
            for entry in entries:
                fqdn = f'{entry.hostname}.{entry.domain}'
                if not fqdn.endswith(self.domain):
                    continue
                if fqdn == self.domain:
                    hostname = ''
                else:
                    hostname = fqdn.removesuffix(f'.{self.domain}')

                entry2 = copy.deepcopy(entry)
                entry2.hostname = hostname
                entry2.domain = self.domain
                ret.append(entry2)
            return ret

        def mk_dnssec_from_ds(entries: list[vdns.rr.DS]) -> list[vdns.rr.DNSSEC]:
            ret: list[vdns.rr.DNSSEC] = []
            for entry in entries:
                fqdn = f'{entry.hostname}.{entry.domain}'
                if fqdn != self.domain:
                    continue
                t = copy.deepcopy(entry)
                t.domain = self.domain
                t.hostname = ''
                ret.append(t)
            return ret

        def get_subdomains(entries: list[T]) -> set[str]:
            ret: set[str] = set()
            for entry in entries:
                if not entry.hostname or entry.domain != self.domain:
                    continue
                fqdn = f'{entry.hostname}.{entry.domain}'
                ret.add(fqdn)
            return ret

        dt: vdns.zoneparser.ParsedDomainData = self._dt

        soa = copy.deepcopy(dt.soa)
        soa.name = self.domain

        # Determine subdomains
        subs: set[str] = get_subdomains(dt.ns) | get_subdomains(dt.ds)

        ret = vdns.src.src0.DomainData(
            name=self.domain,
            serial=dt.serial,
            soa=soa,
            mx=flt(dt.mx),
            ns=flt(dt.ns) + flt_sub(dt.ns),
            hosts=flt(dt.hosts),
            cnames=flt(dt.cnames),
            txt=flt(dt.txt),
            dnssec=flt(dt.dnssec) + mk_dnssec_from_ds(dt.ds),
            sshfp=flt(dt.sshfp),
            dkim=flt(dt.dkim),
            srv=flt(dt.srv),
            subdomains=list(subs),
        )

        return ret

    def has_changed(self) -> bool:
        return False

    def incserial(self, oldserial: int) -> int:
        raise NotImplementedError

    def set_serial(self, serial: int) -> None:
        raise NotImplementedError


class TestZoneMaker(vdns.zonemaker.ZoneMaker):

    _dt: vdns.zoneparser.ParsedDomainData

    def __init__(self, domain: str, data: vdns.zoneparser.ParsedDomainData) -> None:
        self._dt = data
        super().__init__(domain)

    def _mksources(self) -> vdns.zonemaker.SourceList:
        return [TestSource(self.domain, self._dt)]

    def _zonemaker_factory(self, domain: str) -> vdns.zonemaker.ZoneMaker:
        return TestZoneMaker(domain, self._dt)


def doit() -> int:
    config = vdns.util.config.get_config()

    def check_diff(a: str, b: str, msg: str) -> bool:
        delta = difflib.unified_diff(a.splitlines(), b.splitlines())
        diff = list(delta)
        if config.diff and diff:
            print(f'{msg}:')
            print('\n'.join(diff))
            return True
        return False

    with open(config.file, 'rt', encoding='ASCII') as f:
        orig = f.read()

    zp = vdns.zoneparser.ZoneParser()
    zp.parse(orig.splitlines())
    zp_data = zp.data()
    zm = TestZoneMaker(zp_data.soa.name, zp_data)
    zm_out = zm.doit()

    if check_diff(orig, zm_out.zone, 'diff between orig & 2'):
        return 1

    zp2 = vdns.zoneparser.ZoneParser()
    zp2.parse(zm_out.zone.splitlines())
    zp2_data = zp2.data()
    zm2 = TestZoneMaker(zp2_data.soa.name, zp2_data)
    zm2_out = zm2.doit()

    if check_diff(zm_out.zone, zm2_out.zone, 'diff between 2 & 3'):
        return 1

    if check_diff(orig, zm2_out.zone, 'diff between orig & 3'):
        return 1

    return 0

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
