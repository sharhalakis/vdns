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

import os
import pwd
import grp
import logging

from typing import Optional


def write_file(fn: str, contents: str, perms: Optional[int] = None, owner: Optional[str] = None,
               group: Optional[str] = None) -> None:
    if perms:
        perms2 = perms
    else:
        perms2 = 0o666

    fd = os.open(fn, os.O_CREAT | os.O_RDWR | os.O_TRUNC, perms2)

    # Bypass umask
    if perms:
        os.fchmod(fd, perms)

    if owner or group:
        if owner:
            pw = pwd.getpwnam(owner)
            uid = pw.pw_uid
        else:
            uid = -1

        if group:
            gr = grp.getgrnam(group)
            gid = gr.gr_gid
        else:
            gid = -1

        os.fchown(fd, uid, gid)

    f = os.fdopen(fd, 'w')
    f.write(contents)

    f.close()

    logging.debug('Wrote %d bytes to %s', len(contents), fn)


if __name__ == '__main__':
    write_file('/tmp/test1', 'teeeeeest')

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
