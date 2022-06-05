# pylint: disable=protected-access

import typing
import datetime
import unittest

from vdns import db_testlib
import vdns.db

from typing import Optional


class TestlibTest(unittest.TestCase):

    _db: db_testlib.DB

    def setUp(self) -> None:
        db_testlib.init()
        vdns.db.init_db(dbname='somedb')
        self._db = db_testlib.get_db()
        db_testlib.add_test_data()

    def test_init(self) -> None:
        self.assertIsInstance(vdns.db._db, db_testlib.DB)

    def test_bad_domain(self) -> None:
        self.assertEqual(len(self._db.get_domain_related_data('cnames', 'baddomain')), 0)

        with self.assertRaises(Exception):
            self._db.store_serial('baddomain', 10)

        self.assertFalse(self._db.is_dynamic('baddomain'))

    def test_bad_table(self) -> None:
        with self.assertRaises(Exception):
            self._db.read_table('badtable')

    def test_read_table(self) -> None:
        rows = self._db.read_table('cnames')
        self.assertGreaterEqual(len(rows), 3)

        for row in rows:
            self.assertIsInstance(row['ttl'], typing.get_args(Optional[datetime.timedelta]))

    def test_get_domain_related_data(self) -> None:
        domain = 'dom1'
        rows = self._db.get_domain_related_data('cnames', domain)
        for row in rows:
            self.assertEqual(row['domain'], domain)

    def test_is_dynamic(self) -> None:
        self.assertFalse(self._db.is_dynamic('unknowndomain'))
        self.assertFalse(self._db.is_dynamic('dom1'))
        self.assertTrue(self._db.is_dynamic('dyn.v13.gr'))
