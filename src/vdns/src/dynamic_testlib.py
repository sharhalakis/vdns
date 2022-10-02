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

import vdns.db
import vdns.src.dynamic
import vdns.zoneparser

from typing import Any, Optional
from unittest import mock

_contents: str = ''
_dynamic_entries: vdns.db.DBReadResults = []


def _mock_read_file(fn: str) -> Optional[list[str]]:  # pylint: disable=unused-argument
    return _contents.splitlines()


def _mock_get_dynamic() -> vdns.db.DBReadResults:
    return _dynamic_entries


def set_contents(st: str) -> None:
    global _contents
    _contents = st


def set_dynamic_entries(entries: vdns.db.DBReadResults) -> None:
    global _dynamic_entries
    _dynamic_entries = entries


def init() -> dict[str, Any]:
    patchers = {}

    p = mock.patch('os.path.exists', return_value=True)
    patchers['os.path.exists'] = p
    p.start()

    p = mock.patch.object(vdns.zoneparser.ZoneParser, '_read_file', side_effect=_mock_read_file)
    patchers['zoneparser.ZoneParser._read_file'] = p
    p.start()

    return patchers
