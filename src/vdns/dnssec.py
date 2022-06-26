import base64
import struct
import hashlib
import dataclasses as dc


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
