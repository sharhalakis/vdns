#!/usr/bin/env python
# coding=UTF-8
#
# Copyright (c) 2014-2015 Stefanos Harhalakis <v13@v13.gr>
#
# This file is part of vdns
#
# vdns is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# vdns is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# $Id$
#

import os
import pwd
import grp

from typing import Optional


def write_file(fn: str, contents: str, perms: Optional[int] = None, owner: Optional[str] = None,
               group: Optional[str] = None) -> None:
    if perms:
        perms2 = perms
    else:
        perms2 = 0o666

    fd = os.open(fn, os.O_CREAT | os.O_RDWR, perms2)

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


if __name__ == '__main__':
    write_file('/tmp/test1', 'teeeeeest')

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
