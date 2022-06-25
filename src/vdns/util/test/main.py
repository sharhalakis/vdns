import difflib

import vdns.src.src0
import vdns.util.config
import vdns.zone
import vdns.common
import vdns.zonemaker
import vdns.zoneparser

from typing import Optional


class TestSource(vdns.src.src0.Source):

    _dt: vdns.src.src0.DomainData

    def __init__(self, data: vdns.src.src0.DomainData):
        self._dt = data
        super().__init__(self._dt.name)

    def get_data(self) -> Optional[vdns.src.src0.DomainData]:
        # print(f"{self.domain}:", self._dt.dnssec)
        return self._dt

    def has_changed(self) -> bool:
        return False

    def incserial(self, oldserial: int) -> int:
        raise NotImplementedError

    def set_serial(self, serial: int) -> None:
        raise NotImplementedError


class TestZoneMaker(vdns.zonemaker.ZoneMaker):

    _dt: vdns.src.src0.DomainData

    def __init__(self, data: vdns.src.src0.DomainData) -> None:
        self._dt = data
        super().__init__(data.soa.name)

    def _mksources(self) -> vdns.zonemaker.SourceList:
        return [TestSource(self._dt)]

    def _zonemaker_factory(self, domain: str) -> vdns.zonemaker.ZoneMaker:
        # Construct a fake SOA for subdomains
        data = vdns.src.src0.DomainData(name=domain, soa=vdns.rr.SOA(name=domain))
        subname = domain.removesuffix(f'.{self._dt.soa.name}')

        # Add NS records for matching subdomains
        data.ns.extend([ns for ns in self._dt.ns if ns.hostname == subname])

        # Add DS records for matching subdomains
        data.dnssec.extend([ds for ds in self._dt.dnssec if ds.hostname == subname])

        return TestZoneMaker(data)


def doit() -> int:
    config = vdns.util.config.get_config()

    def check_diff(a: str, b: str, msg: str) -> bool:
        delta = difflib.unified_diff(a.splitlines(), b.splitlines())
        diff = list(delta)
        if diff:
            print(f'{msg}:')
            print('\n'.join(diff))
            return True
        return False

    with open(config.file, 'rt', encoding='ASCII') as f:
        orig = f.read()

    zp = vdns.zoneparser.ZoneParser()
    zp.parse(orig.splitlines())
    zp_data = zp.data()
    dt = zp_data.to_zonedata()
    zm = TestZoneMaker(dt.data)
    zm_out = zm.doit()

    if check_diff(orig, zm_out.zone, 'diff between orig & 2'):
        return 1

    zp2 = vdns.zoneparser.ZoneParser()
    zp2.parse(zm_out.zone.splitlines())
    zp2_data = zp2.data()
    dt2 = zp2_data.to_zonedata()
    zm2 = TestZoneMaker(dt2.data)
    zm2_out = zm2.doit()

    if check_diff(zm_out.zone, zm2_out.zone, 'diff between 2 & 3'):
        return 1

    if check_diff(orig, zm2_out.zone, 'diff between orig & 3'):
        return 1

    return 0

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
