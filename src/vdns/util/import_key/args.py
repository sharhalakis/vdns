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
