#!/usr/bin/env python3
# coding=UTF-8
#
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

import time
import datetime
import dataclasses as dc

import vdns.rr
import vdns.common

from typing import Optional, Sequence

RRTypeList = Sequence[Sequence[vdns.rr.RR]]


@dc.dataclass
class DomainData:
    name: str = ''
    serial: int = 1
    network: Optional[vdns.common.IPNetwork] = None
    soa: vdns.rr.SOA = dc.field(default_factory=vdns.rr.SOA)
    mx: list[vdns.rr.MX] = dc.field(default_factory=list)
    ns: list[vdns.rr.NS] = dc.field(default_factory=list)
    hosts: list[vdns.rr.Host] = dc.field(default_factory=list)
    cnames: list[vdns.rr.CNAME] = dc.field(default_factory=list)
    txt: list[vdns.rr.TXT] = dc.field(default_factory=list)
    dnssec: list[vdns.rr.DNSSEC] = dc.field(default_factory=list)
    sshfp: list[vdns.rr.SSHFP] = dc.field(default_factory=list)
    dkim: list[vdns.rr.DKIM] = dc.field(default_factory=list)
    srv: list[vdns.rr.SRV] = dc.field(default_factory=list)
    subdomains: list[str] = dc.field(default_factory=list)

    def __iadd__(self, other: 'DomainData') -> 'DomainData':
        self.mx += other.mx
        self.ns += other.ns
        self.hosts += other.hosts
        self.cnames += other.cnames
        self.txt += other.txt
        self.dnssec += other.dnssec
        self.sshfp += other.sshfp
        self.dkim += other.dkim
        self.srv += other.srv
        self.subdomains += other.subdomains

        return self

    @property
    def reverse(self) -> bool:
        """Returns true if this is a reverse zone."""
        return self.network is not None

    @property
    def host_reclist(self) -> RRTypeList:
        """Non-A/AAAA reclist for hosts. These are the RRs that accompany a host (A/AAAA)."""
        return [self.mx, self.cnames, self.txt, self.dkim, self.srv, self.sshfp]

    @property
    def toplevel_reclist(self) -> RRTypeList:
        """Non-A/AAAA reclist for domains. These are the RRs that are added at the top level."""
        return [self.ns, self.mx, self.dnssec, self.txt, self.dkim, self.sshfp, self.srv]


class Source:
    domain: str

    def __init__(self, domain: str):
        self.domain = domain

    def incserial_date(self, oldserial: int) -> int:
        """!
        Increment a serial number, handling date cases

        @param oldserial    The old serial number
        @return the new serial number
        """
        old = oldserial

        # If our convention is not the date then just increment by one
        if old > 1000000000:
            ts = datetime.date.fromtimestamp(time.time())
            # ser0 = '%04d%02d%02d' % (ts.year, ts.month, ts.day)
            ser0 = f'{ts.year:04}{ts.month:02}{ts.day:02}'

            if str(old)[:len(ser0)] == ser0:
                # Same day
                idx = old % 100
                # ser = int(ser0 + '%02d' % (idx + 1,))
                ser = int(f'{ser0}{(idx+1):02}')
            elif old < (int(ser0) * 100):
                # Normal increament
                # ser = int(ser0 + '00')
                ser = int(f'{ser0}00')
            else:
                # Fail!
                raise Exception(f'Old serial ({old}) for {self.domain} is in the future')
        else:
            ser = old + 1

        return ser

    # -------------------------------------------------------------------
    # Things to implement in derived classes

    def get_data(self) -> Optional[DomainData]:
        """Returns the data as a DomainData structure."""
        raise NotImplementedError()

    def has_changed(self) -> bool:
        """!
        Check whether data for this source have changed. If yes then
        a new serial will be allocated later

        @return True/False
        """
        raise NotImplementedError()

    def incserial(self, oldserial: int) -> int:
        """!
        Given the old serial number, provide the next serial number.

        E.g. if this source uses dates for serial representation it may
        return the next serial to use (which may not be old+1). Otherwise
        it may return just the oldeserial+1, etc...

        @return The next serial number to use
        """
        raise NotImplementedError()

    def set_serial(self, serial: int) -> None:
        """!
        Store this serial number to the database (if applicable)

        Once the next serial number is determined, all sources will be called
        to store the serial number.
        """
        raise NotImplementedError()

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
