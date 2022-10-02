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
import collections
import vdns.common
import vdns.util.test
import vdns.util.config
import vdns.util.export
import vdns.util.import_key

from typing import Optional

modules = collections.OrderedDict([
    ('export', vdns.util.export),
    ('test', vdns.util.test),
    ('import-key', vdns.util.import_key),
])


def abort(msg: str, excode: int = 1) -> None:
    sys.stderr.write(msg)
    sys.exit(excode)


def init_args() -> None:
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
    config = vdns.util.config.get_config()

    parser = argparse.ArgumentParser()

    parser.add_argument('-d', '--debug', action='store_true',
                        default=config.debug,
                        help='Enable debugging')

    parser.add_argument('--info', action='store_true',
                        default=config.info,
                        help='Enable informational messages')

    if config.util is None:
        sub = parser.add_subparsers(dest='what')

        # Add the arguments for each module
        for k, v in modules.items():
            subparser = sub.add_parser(k)
            v.add_args(subparser)

        # In this mode, this gets set later
        module = None
    elif config.util in modules:
        vdns.util.export.args.add_args(parser)
        module = modules[config.util]
    else:
        abort(f'Bad utility name: {config.util}')

    # Parse them
    args = parser.parse_args()

    # Handle top-level parameters
    config.debug = args.debug
    config.info = args.info

    if config.util:
        config.what = config.util
    elif args.what:
        config.what = args.what
    else:
        parser.error('Must specify a utility')

    if module is None:
        module = modules.get(config.what)
        if module is None:
            abort(f'Bad action: f{config.what}')

    assert module is not None

    config.module = module

    # Init log early
    init_log()

    logging.debug('Module: %s', config.what)

    # Handle module params
    module.args.handle_args(args)


def init_log() -> None:
    config = vdns.util.config.get_config()

    if config.debug:
        level = logging.DEBUG
    elif config.info:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(level=level)


def init() -> None:
    config = vdns.util.config.get_config()

    init_args()
    logging.debug('Initializing module')
    config.module.init()


def doit() -> int:
    config = vdns.util.config.get_config()

    logging.debug('Running module')
    ret = config.module.doit()

    return ret


def runutil(util: Optional[str]) -> None:
    """!
    Run for a certain utility or for all of them

    @param util     A utility name, or None to provide all of them
    """
    config = vdns.util.config.get_config()

    config.util = util

    init()

    try:
        ret = doit()
    except vdns.common.AbortError as r:
        if not r.error_shown:
            logging.error('Execution failed: %s', r)
        ret = r.excode

    sys.exit(ret)

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
