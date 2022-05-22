#!/usr/bin/env python
# coding=UTF-8
#
# Copyright (c) 2014-2015 Stefanos Harhalakis <v13@v13.gr>
#
# This file is part of vdns
#
# vdns is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# vdns is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# $Id$
#

import sys
import logging
import argparse
import vdns.db
import vdns.util.config
import vdns.util.export.config


def add_args(parser: argparse.ArgumentParser) -> None:
    config = vdns.util.export.config.Config()

    # Set this as the module config
    vdns.util.config.set_module_config(config)

    parser.add_argument('--keys', action='store_true', default=False,
                        help='Export keys')

    parser.add_argument('--outdir', default=config.outdir,
                        help='Output directory for zones (def: %(default)s)')
    parser.add_argument('--keydir', default=config.keydir,
                        help='Output directory for keys (def: %(default)s)')
    parser.add_argument('--olddir', default=config.olddir,
                        help='Old configuration directory (i.e. bind zones) (def: %(default)s)')

    parser.add_argument('--dbname', default=config.dbname,
                        help='Database name (def: %(default)s)')
    parser.add_argument('--dbuser', default=config.dbuser,
                        help='Database user (def: %(default)s)')
    parser.add_argument('--dbhost', default=config.dbhost,
                        help='Database host (def: %(default)s)')
    parser.add_argument('--dbport', default=config.dbport,
                        help='Database port (def: %(default)s)')

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

    config.dbname = args.dbname
    config.dbuser = args.dbuser
    config.dbhost = args.dbhost
    config.dbport = args.dbport

    if len(config.domains) == 0 and len(config.networks) == 0 and not config.doall:
        logging.error('No domains specified and not --all used. Nothing to do')
        sys.exit(1)


def _init_db() -> None:
    config = vdns.util.config.get_config()

    vdns.db.init_db(
        dbname=config.dbname,
        dbuser=config.dbuser,
        dbhost=config.dbhost,
        dbport=config.dbport,
    )


def init() -> None:
    _init_db()


if __name__ == '__main__':
    init()

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
