import datetime
import unittest
import parameterized

import vdns.zone0


class Zone0Test(unittest.TestCase):

    @parameterized.parameterized.expand([
        (datetime.timedelta(seconds=1000), ("1000", "16 minutes, 40 seconds")),
        (datetime.timedelta(seconds=1200), ("20M", "20 minutes")),
        (datetime.timedelta(seconds=7200), ("2H", "2 hours")),
        (datetime.timedelta(100), ("100D", "14 weeks, 2 days")),
        (datetime.timedelta(100, 1), ("8640001", "14 weeks, 2 days, 1 second")),
        (datetime.timedelta(14), ("2W", "2 weeks")),
    ])
    def test_fmttd(self, dt: datetime.timedelta, output: str):
        z = vdns.zone0.Zone0(dt)
        self.assertEqual(z.fmttd(dt), output)

    def test_fmttd_invalid(self):
        dt = datetime.timedelta(0)
        z = vdns.zone0.Zone0(dt)
        with self.assertRaises(ValueError):
            z.fmttd(dt)
