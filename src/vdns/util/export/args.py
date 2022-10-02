#!/usr/bin/env python
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

import sys
import logging
import argparse
import vdns.db
import vdns.util.config
import vdns.util.export.config


def add_args(parser: argparse.ArgumentParser) -> None:
    vdns.db.add_args(parser)

    config = vdns.util.export.config.Config()

    # Set this as the module config
    vdns.util.config.set_module_config('export', config)

    parser.add_argument('--keys', action='store_true', default=False,
                        help='Export keys')

    parser.add_argument('--outdir', default=config.outdir,
                        help='Output directory for zones (def: %(default)s)')
    parser.add_argument('--keydir', default=config.keydir,
                        help='Output directory for keys (def: %(default)s)')
    parser.add_argument('--olddir', default=config.olddir,
                        help='Old configuration directory (i.e. bind zones) (def: %(default)s)')

    what = parser.add_mutually_exclusive_group(required=True)
    what.add_argument('--domains', nargs=argparse.REMAINDER, default=[],
                      help='A series of domains to export')
    what.add_argument('--networks', nargs=argparse.REMAINDER, default=[],
                      help='A series of networks to export')
    what.add_argument('--all', action='store_true', default=False,
                      help='Do all domains and networks')


def handle_args(args: argparse.Namespace) -> None:
    config = vdns.util.config.get_config()

    config.domains = args.domains
    config.networks = args.networks
    config.doall = args.all
    config.dokeys = args.keys

    config.olddir = args.olddir
    config.outdir = args.outdir
    config.keydir = args.keydir

    if len(config.domains) == 0 and len(config.networks) == 0 and not config.doall:
        logging.error('No domains specified and not --all used. Nothing to do')
        sys.exit(1)

    vdns.db.handle_args(args)


def init() -> None:
    vdns.db.init_db()


# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
