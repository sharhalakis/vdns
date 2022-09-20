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

import datetime
import argparse
import dataclasses as dc

import vdns.db
import vdns.util.config
import vdns.parsing

from typing import Optional


@dc.dataclass
class _Config:
    # The keyfile, as passed by the user
    domain: str = ''
    keyfile: str = ''
    ttl: Optional[datetime.timedelta] = None


def add_args(parser: argparse.ArgumentParser) -> None:
    vdns.db.add_args(parser)

    config = _Config()
    vdns.util.config.set_module_config('import_key', config)

    parser.add_argument('--domain', default=config.domain,
                        help='The domain name to import the key to. Used if the keyfile has no domain and as '
                             'a sanity check (optional)')
    parser.add_argument('--ttl', default=config.ttl, help='The ttl to use (optional)')
    parser.add_argument('keyfile', help='The file to import the key from')


def handle_args(args: argparse.Namespace) -> None:
    config = vdns.util.config.get_config()
    config.domain = args.domain
    config.keyfile = args.keyfile
    if args.ttl:
        config.ttl = vdns.parsing.parse_ttl(args.ttl.upper())

    vdns.db.handle_args(args)


def init() -> None:
    # TODO: Maybe don't try to connect if we won't use the database
    vdns.db.init_db()

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
