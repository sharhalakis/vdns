import textwrap
import unittest

import vdns.db
import vdns.db_testlib
from vdns.src import dynamic
from vdns.src import dynamic_testlib

_SOA = '$ORIGIN dom.com.\n$TTL 1D\n@ 1D IN SOA ns1.com. dom.com. ( 20220522 1D 1H 90D 1M )'


class DynamicTest(unittest.TestCase):

    _contents: str = ''
    _dynamic_entries: vdns.db.DBReadResults = [
        {'domain': 'dom.com', 'hostname': 'host1'},
        {'domain': 'dom.com', 'hostname': 'host3'},
    ]

    def setUp(self) -> None:
        vdns.db_testlib.init()
        db = vdns.db_testlib.init_db(dbname='test')
        patchers = dynamic_testlib.init()
        for p in patchers.values():
            self.addCleanup(p.stop)
        # dynamic_testlib.set_dynamic_entries(self._dynamic_entries)
        db.set_data('dynamic', self._dynamic_entries)

    def _get_dynamic(self, domain: str, contents: str) -> dynamic.Dynamic:
        # self._contents = contents
        dynamic_testlib.set_contents(contents)
        return dynamic.Dynamic(domain, './', 'somefile')

    def test_dynamic(self) -> None:
        contents = textwrap.dedent(f'''
        {_SOA}
        IN NS ns1.dom.com.
        IN A 1.2.3.4
        host1 IN A 10.1.1.1
        host2 IN A 10.1.1.2
        host4 IN A 10.1.1.3
              IN AAAA 2001:db8:1::1
        ''')
        d = self._get_dynamic('dom.com', contents)
        hosts = d.get_hosts()

        # There are dynamic entries
        self.assertIsNotNone(hosts)
        assert hosts is not None  # For mypy

        # Only the dynamic entry should be returned
        self.assertIn('10.1.1.1', [x['ip'].compressed for x in hosts])
        self.assertNotIn('10.1.1.2', [x['ip'].compressed for x in hosts])

        # Only the dynamic host with an entry should exist
        self.assertIn('host1', [x['hostname'] for x in hosts])
        self.assertNotIn('host2', [x['hostname'] for x in hosts])
        self.assertNotIn('host3', [x['hostname'] for x in hosts])

        # If the dynamic file's serial is higher than the known one the turn the dynamic file's
        self.assertEqual(d.determine_dynamic_serial(1), 20220522)
        self.assertEqual(d.determine_dynamic_serial(30000000), 30000000)
