import os.path
import re
import base64
import struct
import hashlib
import logging
import datetime
import dataclasses as dc

import vdns.rr
import vdns.common
import vdns.parsing

from typing import Optional


@dc.dataclass
class ParsedPubKeyLine:
    zone: str
    flags: int
    protocol: int
    algorithm: int
    key_pub: str

    keyid: int
    sha1: str
    sha256: str
    ksk: bool

    def str(self) -> str:
        return (f'flags: {self.flags}, protocol: {self.protocol}, algorithm: {self.algorithm} -> '
                f'keyid: {self.keyid}, ksk: {self.ksk}, sha1: {self.sha1}, sha256: {self.sha256}')


@dc.dataclass
class DSSigs:
    sha1: str
    sha256: str


def calc_dnssec_keyid(flags: int, protocol: int, algorithm: int, st: str) -> int:
    """
    Calculate the keyid based on the key string
    """

    st2: bytes

    st0 = st.replace(' ', '')
    st2 = struct.pack('!HBB', flags, protocol, algorithm)
    st2 += base64.b64decode(st0)

    cnt = 0
    for idx, ch in enumerate(st2):
        # TODO: verify this. Looks like we don't need the struct.unpack in python3
        # s = struct.unpack('B', ch)[0]
        s = ch
        if (idx % 2) == 0:
            cnt += s << 8
        else:
            cnt += s

    ret = ((cnt & 0xFFFF) + (cnt >> 16)) & 0xFFFF

    return ret


def calc_ds_sigs(owner: str, flags: int, protocol: int, algorithm: int, st: str) -> DSSigs:
    """
    Calculate the DS signatures

    Return a dictionary where key is the algorithm and value is the value
    """

    st2: bytes

    st0 = st.replace(' ', '')
    st2 = struct.pack('!HBB', flags, protocol, algorithm)
    st2 += base64.b64decode(st0)

    # Transform owner from A.B.C to <legth of A>A<length of B>B<length of C>C0

    if owner[-1] == '.':
        owner2 = owner
    else:
        owner2 = owner + '.'

    owner3 = b''
    for i in owner2.split('.'):
        owner3 += struct.pack('B', len(i)) + i.encode('ASCII')

    st3: bytes = owner3 + st2

    ret = DSSigs(
        sha1=hashlib.sha1(st3).hexdigest().upper(),
        sha256=hashlib.sha256(st3).hexdigest().upper(),
    )

    return ret


def parse_pub_key_line(dt: vdns.parsing.ParsedLine) -> ParsedPubKeyLine:
    """Further parses a DNSKEY line.

    The returned zone is the exact name that's listed in the line, including a potential dot at the end.
    """
    if dt.addr1 is None:
        vdns.common.abort(f'Entry is missing the hostname/domain: {dt}')

    zone = dt.addr1
    key0 = dt.addr2
    keydata = key0.split(None, 3)
    flags = int(keydata[0])
    protocol = int(keydata[1])
    algorithm = int(keydata[2])
    key_pub = keydata[3]

    if protocol != 3:
        vdns.common.abort(f'Cannot handle protocol: {protocol}')

    keyid = calc_dnssec_keyid(flags, protocol, algorithm, key_pub)
    sigs = calc_ds_sigs(zone, flags, protocol, algorithm, key_pub)
    ksk = ((flags & 0x03) == 0x01)

    ret = ParsedPubKeyLine(
        zone=dt.addr1,
        flags=flags,
        protocol=protocol,
        algorithm=algorithm,
        key_pub=key_pub,
        keyid=keyid,
        sha1=sigs.sha1,
        sha256=sigs.sha256,
        ksk=ksk,
    )

    return ret


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
    dt_pub: Optional[ParsedPubKeyLine] = None

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
        dt_pub = parse_pub_key_line(parsed_line)
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
