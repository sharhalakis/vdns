#!/usr/bin/env python
# coding=UTF-8
#
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

import dataclasses as dc

from typing import List


@dc.dataclass
class Config:
    olddir: str = '/etc/bind/db'  # Directory that stores existing config
    outdir: str = 'db/'
    keydir: str = 'keys/'

    domains: List[str] = dc.field(default_factory=list)
    networks: List[str] = dc.field(default_factory=list)
    doall: bool = False  # Do all domains/networks?
    dokeys: bool = False  # Export keys?

    incserial: bool = True  # Increment serial number?

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
