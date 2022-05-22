import unittest

import vdns.util.config


class MergeConfigTest(unittest.TestCase):

    def test_merge(self) -> None:
        class Obj1:
            t1 = 1
            t2 = 1

        class Obj2:
            t1 = 2
            t3 = 2
            t4 = None

        o1 = Obj1()
        o2 = Obj2()

        mo = vdns.util.config.MergedConfig(o1, o2)

        self.assertEqual(mo.t1, 1)
        self.assertEqual(mo.t2, 1)
        self.assertEqual(mo.t3, 2)
        self.assertIsNone(mo.t4)

        mo.t1 = 9
        self.assertEqual(mo.t1, 9)
        self.assertEqual(o1.t1, 9)
        self.assertEqual(o2.t1, 2)

        mo.t2 = 9
        self.assertEqual(mo.t2, 9)
        self.assertEqual(o1.t2, 9)

        mo.t3 = 9
        self.assertEqual(mo.t3, 9)
        self.assertEqual(o2.t3, 9)

        mo.t4 = 9
        self.assertEqual(mo.t4, 9)
        self.assertEqual(o2.t4, 9)
