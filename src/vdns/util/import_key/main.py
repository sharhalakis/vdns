import vdns.db
import vdns.util.config
import vdns.common
import vdns.keyparser


def doit() -> int:
    config = vdns.util.config.get_config()

    data = vdns.keyparser.parse(config.keyfile, config.domain)
    data.ttl = config.ttl

    db = vdns.db.get_db()

    res = db.read_table('dnssec', {'digest_sha1': data.digest_sha1})
    if not res:
        res = db.read_table('dnssec', {'digest_sha256': data.digest_sha256})

    if res:
        vdns.common.abort('The key already exists in the database')

    db.insert('dnssec', data.dbvalues())

    return 0

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
