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

    # This should be patched using db_testlib
    # p = mock.patch.object(vdns.db, 'get_db')
    # patchers['vdns.db.get_db'] = p
    # p.start()

    p = mock.patch.object(vdns.zoneparser.ZoneParser, '_read_file', side_effect=_mock_read_file)
    patchers['zoneparser.ZoneParser._read_file'] = p
    p.start()

    # p = mock.patch.object(vdns.src.dynamic.Dynamic, 'get_dynamic', side_effect=_mock_get_dynamic)
    # patchers['dynamic.Dynamic.get_dynamic'] = p
    # p.start()

    return patchers
