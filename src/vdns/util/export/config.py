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

class Config:
    olddir      = '/etc/bind/db'    # Directory that stores existing config
    outdir      = 'db/'
    keydir      = 'keys/'

    dbname      = 'dns'
    dbuser      = None
    dbpass      = None
    dbhost      = None
    dbport      = 5432

    domains     = []
    networks    = []
    doall       = False     # Do all domains/networks?
    dokeys      = False     # Export keys?

    incserial   = True      # Increment serial number?

if __name__=="__main__":
    pass

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:

