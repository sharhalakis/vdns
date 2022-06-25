import logging
import textwrap
import unittest

import vdns.db_testlib
import vdns.src.dynamic_testlib
import vdns.common
import vdns.parsing
import vdns.zonemaker

from typing import Sequence, Union

NeedLines = Sequence[Union[str, tuple[str, bool]]]


class TestZoneMaker(unittest.TestCase):

    def setUp(self) -> None:
        vdns.db_testlib.init()
        vdns.db_testlib.init_db()
        vdns.src.dynamic_testlib.init()
        vdns.db_testlib.add_test_data()

    def _check_lines(self, lines: Sequence[str], needed_lines: NeedLines, ignore_spaces: bool = True) -> None:
        """Checks whether needed_lines are in lines.

        needed_lines is a list of either:
        * A tring that's a line to search for
        * A tuple of (string, bool) where the bool indicates that the line must be immediately after the
          previous one.

        Args:
            lines: The lines to scan
            needed_lines: The lines to look for, as described above
            ignore_spaces: Whether to consider all spaces equal
        """
        if ignore_spaces:
            lines = [vdns.common.compact_spaces(x) for x in lines]
            needed_lines0 = needed_lines
            needed_lines = []
            for line in needed_lines0:
                if isinstance(line, tuple):
                    needed_lines.append((vdns.common.compact_spaces(line[0]), line[1]))
                else:
                    needed_lines.append(vdns.common.compact_spaces(line))

        remaining_lines = lines
        for line in needed_lines:
            if isinstance(line, str):
                needle = line
                subsequent = False
            elif isinstance(line, tuple):
                needle = line[0]
                subsequent = True
            else:
                raise Exception(f'Unsupported needed_line: {line}')

            if subsequent:
                # Skip empty lines
                while remaining_lines and not remaining_lines[0]:
                    remaining_lines = remaining_lines[1:]
                self.assertEqual(needle, remaining_lines[0])
                remaining_lines = remaining_lines[1:]
            else:
                self.assertIn(needle, remaining_lines)
                # Limit the next search to the subsequent lines
                remaining_lines = remaining_lines[remaining_lines.index(line) + 1:]

    def _remove_soa(self, lines: Sequence[str]) -> Sequence[str]:
        """Removes the SOA lines from a set of lines."""
        soa_idx: int = 0
        for idx, line in enumerate(lines):
            if 'SOA' in line:
                soa_idx = idx
                break

        if not soa_idx:
            return lines

        lines = lines[soa_idx + 1:]

        # Assume that the SOA ends with a line with a single ')'
        for idx, line in enumerate(lines):
            if line.strip() == ')':
                return lines[idx + 1:]

        raise Exception('Failed to find end of SOA')

    def _assert_allowed_rrs(self, lines: Sequence[str], allowed: Sequence[str] = (),
                            forbidden: Sequence[str] = ()) -> None:
        lines = self._remove_soa(lines)

        assert allowed or forbidden, 'One of allowed or forbidden must be passed'

        for line in lines:
            r = vdns.parsing.parse_line(line)
            if not r:
                continue
            if allowed:
                self.assertIn(r.rr, allowed, f"{r.rr} isn't an allowed RR: {line}")
            elif forbidden:
                self.assertNotIn(r.rr, forbidden, f"{r.rr} isn't an allowed RR: {line}")

    def test_v13_gr(self) -> None:
        domain = 'v13.gr'
        zm = vdns.zonemaker.ZoneMaker(domain, None)
        res = zm.doit(False, False)

        logging.debug('Output for %s:\n%s', domain, res.zone)
        lines = res.zone.splitlines()

        self._assert_allowed_rrs(lines, forbidden=('PTR',))

        # The order matters
        needed_lines: NeedLines = [
            '1H IN NS ns1.dns.example.com.',
            '1H IN NS ns2.dns.example.com.',

            '1H IN MX 1 aspmx.l.google.com.',
            '1H IN MX 5 alt1.aspmx.l.google.com.',

            '1H IN A 192.168.1.1',
            'IN AAAA 2001:db8:1::1',

            'dyn 5M IN NS ns1.example.com.',
            'sub 5M IN NS ns1.sub.v13.gr.',
            'sub 5M IN NS ns2.sub.v13.gr.',
            'sub 5M IN NS ns3.example.com.',

            'host1 IN A 10.1.1.1',
            'www IN CNAME host1',

            'host3 15M IN A 10.1.1.3',
            'IN AAAA 2001:db8:2c1:12::1',
            'IN TXT "v=spf1 include:_spf.google.com ~all"',
            'IN SSHFP 1 1 1234567890abcdef1234567890abcdef12345678',
            'IN SSHFP 2 1 01234567890abcdef1234567890abcdef1234567',

            'ldap 30D IN CNAME host2.v13.gr.',

            # entries not associated with any host
            'host100 IN TXT "v=spf1 include:_spf.google.com ~all"',
            'host100 IN SSHFP 1 1 234567890abcdef1234567890abcdef123456789',
        ]

        self._check_lines(lines, needed_lines)

    def test_dyn_v13_gr(self) -> None:
        domain = 'dyn.v13.gr'
        vdns.src.dynamic_testlib.set_contents(textwrap.dedent('''
        $ORIGIN         dyn.v13.gr.
        $TTL            1D      ; 1 day
        @               1D      IN      SOA     ns1.example.com. dns.dyn.v13.gr. (
                                        2022060420       ; serial
                                        1D               ; refresh (1 day)
                                        1H               ; retry (1 hour)
                                        30D              ; expire (4 weeks, 2 days)
                                        1M               ; minimum (1 minute)
                                        )

                        5M      IN      NS      ns1.example.com.
                        5M      IN      NS      ns2.example.com.

        host1                   IN      A       10.9.1.1
        host2                   IN      AAAA    2001:db8:9::1
        '''))

        db = vdns.db_testlib.get_db()
        # Add a static entry for the dynamic entry
        db.add_data('hosts', {'ip': '10.1.1.1', 'domain': domain, 'hostname': 'host1', 'reverse': False, 'ttl': None})
        # Add a non-dynamic entry
        db.add_data('hosts', {'ip': '10.8.1.1', 'domain': domain, 'hostname': 'host2', 'reverse': False, 'ttl': None})

        zm = vdns.zonemaker.ZoneMaker(domain, '/dev/null')
        res = zm.doit(False, False)
        logging.debug('Output for %s:\n%s', domain, res.zone)
        lines = res.zone.splitlines()

        self._assert_allowed_rrs(lines, forbidden=('PTR',))

        # The order matters
        needed_lines: NeedLines = [
            '5M IN NS ns1.example.com.',
            '5M IN NS ns2.example.com.',
            'host1 IN A 10.1.1.1',       # The static of the dynamic
            ('IN A 10.9.1.1', True),     # The dynamic
            'host2 IN A 10.8.1.1',       # The fully static entry
        ]

        self._check_lines(lines, needed_lines)

    def test_reverse_10(self) -> None:
        domain = '10.in-addr.arpa'
        zm = vdns.zonemaker.ZoneMaker(domain, None)
        res = zm.doit(False, False)
        logging.debug('Output for %s:\n%s', domain, res.zone)
        lines = res.zone.splitlines()

        # Check that there are just PTRs
        self._assert_allowed_rrs(lines, allowed=('PTR', 'NS'))

        # The order matters
        needed_lines = [
            '1.0.0 IN PTR v13.gr.',
            '1.1.1 IN PTR host1.v13.gr.',
            '2.1.1 1H IN PTR host2.v13.gr.',
            '3.1.1 15M IN PTR host3.v13.gr.',
        ]
        self._check_lines(lines, needed_lines)

    def test_reverse_2001(self) -> None:
        domain = '8.b.d.0.1.0.0.2.ip6.arpa'
        zm = vdns.zonemaker.ZoneMaker(domain, None)
        res = zm.doit(False, False)
        logging.debug('Output for %s:\n%s', domain, res.zone)
        lines = res.zone.splitlines()

        # Check that there are just PTRs
        self._assert_allowed_rrs(lines, allowed=('PTR', 'NS'))

        # The order matters
        needed_lines = [
            '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0 IN PTR v13.gr.',
            '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.1.0.0.1.c.2.0 IN PTR host3.v13.gr.',
            '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.1.0.0.1.c.2.0 IN PTR host5.v13.gr.',
            '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.1.2.3.1.c.2.0 15M IN PTR host3.v13.gr.',
        ]
        self._check_lines(lines, needed_lines)

    def test_glue(self) -> None:
        domain = 'v13.gr'
        zm = vdns.zonemaker.ZoneMaker(domain, None)
        res = zm.doit(False, False)
        logging.debug('Output for %s:\n%s', domain, res.zone)
        lines = res.zone.splitlines()

        needed_lines = [
            'sub 5M IN NS ns1.sub.v13.gr.',
            'sub 5M IN NS ns2.sub.v13.gr.',
            'sub 5M IN NS ns3.example.com.',
            'ns2.sub IN A 10.1.2.2',  # Glue record
        ]
        self._check_lines(lines, needed_lines)
