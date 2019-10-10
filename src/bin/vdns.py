#!/usr/bin/python3

# Lets get ready for python 3
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys

# Remove the current directory to avoid name conflicts
sys.path=sys.path[1:]

import vdns.util.runutil

if __name__=="__main__":
    vdns.util.runutil.runutil(None)

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:

