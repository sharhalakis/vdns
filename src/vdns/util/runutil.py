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
import collections
import vdns.util.config
import vdns.util.export

od=collections.OrderedDict

modules=od([
    ('export',      vdns.util.export)
    ])

def abort(msg, excode=1):
    sys.stderr.write(msg)
    sys.exit(excode)

def init_args():
    """!
    Parameter handling

    This works both with and without a utility name:
        - When Config.util is None, the make the utility name a parameter.
          E.g. vnds.py export ....
        - When Config.util is set, force this to be the utility name.
          E.g. vdns-export.py ....

    Also initialized logging

    Also sets Config.module, which can then be used for the rest of the stuff
    """
    config=vdns.util.config.get_config()

    parser=argparse.ArgumentParser()

    parser.add_argument('-d', '--debug', action='store_true',
        default=config.debug,
        help='Enable debugging')

    if config.util==None:
        sub=parser.add_subparsers(dest='what')

        # Add the arguments for each module
        for k,v in modules.items():
            subparser=sub.add_parser(k)
            func=getattr(v, 'add_args')
            func(subparser)

        # In this mode, this gets set later
        module=None
    elif config.util in modules:
        vdns.util.export.args.add_args(parser)
        module=modules[config.util]
    else:
        abort('Bad utility name: %s' % (config.util,))

    # Parse them
    args=parser.parse_args()

    # Handle top-level parameters
    config.debug=args.debug

    if config.util:
        config.what=config.util
    else:
        config.what=args.what

    if config.what==None:
        parser.error('Must specify a utility')

    if module==None:
        if config.what=='export':
            module=vdns.util.export
        else:
            abort('Bad action: %s' % (config.what,))

    config.module=module

    # Init log early
    init_log()

    logging.debug('Module: %s' % (config.what,))

    # Handle module params
    module.args.handle_args(args)

def init_log():
    config=vdns.util.config.get_config()

    if config.debug:
        level=logging.DEBUG
    else:
        level=logging.WARNING

    logging.basicConfig(level=level)

def init():
    config=vdns.util.config.get_config()

    init_args()
    logging.debug('Initializing module')
    config.module.init()

def doit():
    config=vdns.util.config.get_config()

    logging.debug('Doing main')
    ret=config.module.doit()

    return(ret)

def runutil(util):
    """!
    Run for a certain utility or for all of them

    @param util     A utility name, or None to provide all of them
    """
    config=vdns.util.config.get_config()

    config.util=util

    init()

    ret=doit()

    sys.exit(ret)

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:

