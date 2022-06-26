import os.path
import re
import logging
import datetime

import vdns.rr
import vdns.common
import vdns.parsing

from typing import Optional


def parse_ts(st: str) -> datetime.datetime:
    """
    Parse a key timestamp to a time string suitable for insert
    """
    # 20101007114826
    # 2010 10 07 11 48 26
    pat = r'^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$'
    r = re.compile(pat)
    t0 = r.search(st)
    if not t0:
        vdns.common.abort(f'Failed to parse timestamp "{st}"')
    t = t0.groups()

    # st = '%s-%s-%s %s:%s:%sZ' % t.groups()

    ret = datetime.datetime(
        year=int(t[0]),
        month=int(t[1]),
        day=int(t[2]),
        hour=int(t[3]),
        minute=int(t[4]),
        second=int(t[5]),
        tzinfo=datetime.timezone.utc,
    )

    return ret


def _parse(domain: str, st_pub: str, st_priv: str) -> Optional[vdns.rr.DNSSEC]:
    """Easier to test."""
    # Parse the public key
    dt_pub: Optional[vdns.parsing.ParsedPubKeyLine] = None

    buffer: list[str] = []
    in_parentheses = False

    for line in st_pub.splitlines():
        line = vdns.parsing.cleanup_line(line)
        if not line:
            continue

        buffer.append(line)
        in_parentheses = vdns.parsing.line_ends_in_parentheses(line, in_parentheses)
        if in_parentheses:
            continue
        line2 = vdns.parsing.merge_multiline(buffer, True)

        parsed_line = vdns.parsing.parse_line(line2)
        if not parsed_line or parsed_line.rr != 'DNSKEY':
            vdns.common.abort(f'Unhandled line: {line2}')

        if dt_pub is not None:
            vdns.common.abort(f'Found second DNSKEY: {line2}')

        logging.debug('Parsing: %s', line2)
        dt_pub = vdns.parsing.parse_pub_key_line(parsed_line)
        logging.debug(dt_pub.str())

    if not dt_pub:
        return None

    # Parse the hostname
    zone = dt_pub.zone.removesuffix('.')
    if domain and zone != domain:
        vdns.common.abort(f'Found hostname "{dt_pub.zone}" which does not match domain "{domain}"')

    ts_created: Optional[datetime.datetime] = None
    ts_activate: Optional[datetime.datetime] = None
    ts_publish: Optional[datetime.datetime] = None

    # Parse the private key
    for line in st_priv.splitlines():
        t = line.split(':', 1)
        if len(t) != 2:
            continue
        v = t[1].strip()
        if t[0] == 'Created':
            ts_created = parse_ts(v)
        elif t[0] == 'Publish':
            ts_publish = parse_ts(v)
        elif t[0] == 'Activate':
            ts_activate = parse_ts(v)

    if not ts_created:
        vdns.common.abort('No Created timestamp')
    elif not ts_activate:
        vdns.common.abort('No Activate timestamp')
    elif not ts_publish:
        vdns.common.abort('No Publish timestamp')

    # pylint: disable=unexpected-keyword-arg  # https://github.com/PyCQA/pylint/issues/6550
    return vdns.rr.DNSSEC(
        domain=zone,
        hostname=None,
        ttl=None,
        keyid=dt_pub.keyid,
        ksk=dt_pub.ksk,
        algorithm=dt_pub.algorithm,
        digest_sha1=dt_pub.sha1,
        digest_sha256=dt_pub.sha256,
        key_pub=dt_pub.key_pub,
        st_key_pub=st_pub,
        st_key_priv=st_priv,
        ts_created=ts_created,
        ts_activate=ts_activate,
        ts_publish=ts_publish
    )
    # pylint: enable=unexpected-keyword-arg


def parse(filename: str, domain: str) -> vdns.rr.DNSSEC:
    logging.debug('Importing key from %s', filename)

    if filename.endswith('.key'):
        base_fn = filename.removesuffix('.key')
    elif filename.endswith('.private'):
        base_fn = filename.removesuffix('.private')
    else:
        vdns.common.abort(f'Bad filename: {filename}')

    fnpub = f'{base_fn}.key'
    fnpriv = f'{base_fn}.private'

    if not os.path.exists(fnpub):
        vdns.common.abort(f'No such file: {fnpub}')
    elif not os.path.exists(fnpriv):
        vdns.common.abort(f'No such file: {fnpriv}')

    logging.debug('Public: %s', fnpub)
    logging.debug('Private: %s', fnpriv)

    with open(fnpub, 'rt', encoding='ascii') as f:
        st_pub = f.read()
    with open(fnpriv, 'rt', encoding='ascii') as f:
        st_priv = f.read()

    ret = _parse(domain, st_pub, st_priv)
    if ret is None:
        vdns.common.abort(f'Could not find a DNSKEY in {fnpub}')
    return ret


# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
