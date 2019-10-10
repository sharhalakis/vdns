import logging

import vdns.db
import vdns.zonemaker
import vdns.util.common
import vdns.util.config

def do_domain(domain):
    """
    Generate one domain

    @param domain   The domain name, used also as a file name
    """

    ZoneMaker=vdns.zonemaker.ZoneMaker
    config=vdns.util.config.get_config()

    outdir=config.outdir
    keydir=config.keydir

    zm=ZoneMaker(domain, zonedir=config.olddir)

    r=zm.doit(config.dokeys, config.incserial)
    outf=outdir + '/' + domain
    vdns.util.common.write_file(outf, r['zone'])

    if config.dokeys:
        keys=r['keys']
        for key in keys:
            keyf=keydir + '/' + key[1]
            vdns.util.common.write_file(keyf, key[2], 0o600)

def doit():
    config=vdns.util.config.get_config()
    ret=0

    db=vdns.db.get_db()

    networks=db.get_networks()
    domains=db.get_domains()

    outdir=config.outdir
    keydir=config.keydir

    logging.debug('Output zone directory is %s' % (outdir,))
    logging.debug('Output keys directory is %s' % (keydir,))

    for net in networks:
        if not config.doall and not net['network'] in config.networks:
            continue

        do_domain(net['domain'])

    for domain in domains:
        if not config.doall and not domain['name'] in config.domains:
            continue

        if domain['reverse']:
            continue

        do_domain(domain['name'])

    return(ret)

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:

