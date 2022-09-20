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

import logging

import vdns.db
import vdns.zonemaker
import vdns.util.common
import vdns.util.config


def do_domain(domain: str) -> None:
    """
    Generate one domain

    @param domain   The domain name, used also as a file name
    """

    config = vdns.util.config.get_config()

    outdir = config.outdir
    keydir = config.keydir

    zm = vdns.zonemaker.ZoneMaker(domain, zonedir=config.olddir)

    r = zm.doit(config.dokeys, config.incserial)
    outf = outdir + '/' + domain
    vdns.util.common.write_file(outf, r.zone)

    if config.dokeys:
        for key in r.keys:
            keyf = keydir + '/' + key[0]
            vdns.util.common.write_file(keyf, key[1], 0o600)


def doit() -> int:
    config = vdns.util.config.get_config()
    ret = 0

    db = vdns.db.get_db()

    networks = db.get_networks()
    domains = db.get_domains()

    outdir = config.outdir
    keydir = config.keydir

    logging.debug('Output zone directory is %s', outdir)
    logging.debug('Output keys directory is %s', keydir)

    for net in networks:
        if not config.doall and not net['network'].compressed in config.networks:
            continue

        do_domain(net['domain'])

    for domain in domains:
        if not config.doall and not domain['name'] in config.domains:
            continue

        if domain['reverse']:
            continue

        do_domain(domain['name'])

    return ret

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
