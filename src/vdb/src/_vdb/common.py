# Copyright (c) 2005-2016 Stefanos Harhalakis <v13@v13.gr>
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

from typing import Collection, Mapping, Union

import ipaddress

SupportedTypes = Union[str, int, float, bool, ipaddress.IPv4Interface, ipaddress.IPv6Interface,
                       ipaddress.IPv4Network, ipaddress.IPv6Network, dict, list, None]

# Convenience types
ResultDict = dict[str, SupportedTypes]  # A result in dict form
ResultsDict = list[ResultDict]  # A list of results

ValueParam = Mapping[str, SupportedTypes]  # A parameter suitable for passing db values
WhereParam = Mapping[str, SupportedTypes]  # A parameter suitable for WHERE
ParamDict = dict[str, SupportedTypes]  # A concrete dict for values
OrderParam = Collection[str]  # A parameter suitable for ORDER BY


class VDBError(Exception):
    pass
