import argparse
import dataclasses as dc

import vdns.util.config
import vdns.zoneparser

# from typing import Optional


@dc.dataclass
class _Config:
    file: str = ''
    diff: bool = False


def add_args(parser: argparse.ArgumentParser) -> None:
    config = _Config()
    vdns.util.config.set_module_config('test', config)

    parser.add_argument('--diff', default=config.diff, action='store_true', help='Whether to show a diff')
    parser.add_argument('file', help='The zone file to performs tests on')


def handle_args(args: argparse.Namespace) -> None:
    config = vdns.util.config.get_config()
    config.file = args.file
    config.diff = args.diff


def init() -> None:
    pass

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
