#!/usr/bin/env python
# coding=UTF-8
#

from distutils.core import setup

version='2.1.0'

packages=[
    'vdns',
    'vdns.src',
    'vdns.util',
    'vdns.util.export',
]

package_dirs={'vdns': 'src/vdns'}

scripts=['src/bin/vdns.py']

setup(
    name            = 'vdns',
    version         = version,
    author          = 'Stefanos Harhalakis',
    author_email    = 'v13@v13.gr',
    url             = '...',
    packages        = packages,
    package_dir     = package_dirs,
    scripts         = scripts,
)

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:

