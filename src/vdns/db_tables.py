# Copyright (c) 2022 Google LLC
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

from typing import Optional, Union

import vdns.vdb

import copy
import datetime
import ipaddress
import dataclasses as dc

Schema = vdns.vdb.Schema
Interval = datetime.timedelta
Inet = Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface]
Cidr = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
Timpestamp = datetime.datetime


@dc.dataclass
class CName(Schema):
    domain: str
    hostname: str
    hostname0: str
    ttl: Optional[Interval]


@dc.dataclass
class DKIM(Schema):
    domain: str
    hostname: str
    selector: str
    k: str
    key_pub: str
    h: Optional[str]
    g: str
    t: bool
    subdomains: bool
    ttl: Optional[Interval]


@dc.dataclass
class DNSSEC(Schema):
    id: Optional[int]
    domain: str
    keyid: int
    ksk: Optional[bool]
    algorithm: int
    digest_sha1: Optional[str]
    digest_sha256: Optional[str]
    key_pub: Optional[str]
    st_key_pub: Optional[str]
    st_key_priv: Optional[str]
    ts_created: Optional[Timpestamp]
    ts_activate: Optional[Timpestamp]
    ts_publish: Optional[Timpestamp]
    ttl: Optional[Interval]

    @classmethod
    def transform_data_inverse(cls, data: dict[str, object]) -> vdns.vdb.ParamDict:
        ret = copy.copy(data)
        #  id comes form a sequence so don't try to store it if it is set to None
        if ret['id'] is None:
            ret.pop('id')
        return ret  # type: ignore


@dc.dataclass
class Domain(Schema):
    name: str
    reverse: Optional[bool]
    ttl: Optional[Interval]
    refresh: Optional[Interval]
    retry: Optional[Interval]
    expire: Optional[Interval]
    minimum: Optional[Interval]
    contact: Optional[str]
    serial: Optional[int]
    ns0: Optional[str]
    ts: Optional[datetime.datetime]
    updated: Optional[datetime.datetime]


@dc.dataclass
class Dynamic(Schema):
    domain: str
    hostname: str


@dc.dataclass
class Host(Schema):
    ip: Inet
    domain: str
    hostname: str
    reverse: Optional[bool]
    ttl: Optional[Interval]


@dc.dataclass
class MX(Schema):
    domain: str
    hostname: str
    priority: Optional[int]
    mx: str
    ttl: Optional[Interval]


@dc.dataclass
class Network(Schema):
    domain: str
    network: Cidr


@dc.dataclass
class NS(Schema):
    domain: str
    ns: str
    ttl: Optional[Interval]


@dc.dataclass
class SRV(Schema):
    domain: str
    name: str
    protocol: str
    service: str
    priority: int
    weight: int
    port: int
    target: str
    ttl: Optional[Interval]


@dc.dataclass
class SSHFP(Schema):
    domain: str
    hostname: str
    keytype: int
    hashtype: int
    fingerprint: str
    ttl: Optional[Interval]


@dc.dataclass
class TXT(Schema):
    domain: str
    hostname: str
    txt: str
    ttl: Optional[Interval]
