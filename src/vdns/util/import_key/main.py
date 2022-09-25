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

import vdns.db
import vdns.util.config
import vdns.common
import vdns.db_tables
import vdns.keyparser

import datetime


def parse_one(keyfile: str, domain: str, ttl: datetime.timedelta) -> None:
    data = vdns.keyparser.parse(keyfile, domain)
    data.ttl = ttl

    db = vdns.db.get_db()

    res = db.dnssec.read_flat({'digest_sha1': data.digest_sha1})
    if not res:
        res = db.dnssec.read_flat({'digest_sha256': data.digest_sha256})

    if res:
        vdns.common.abort('The key already exists in the database')

    db.dnssec.insert(data.to_db_record(vdns.db_tables.DNSSEC))


def doit() -> int:
    config = vdns.util.config.get_config()
    parse_one(config.keyfile, config.domain, config.ttl)
    return 0

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
