#!/usr/bin/env python
# coding=UTF-8
#

import logging
import vdns.zone0


class ZoneRev(vdns.zone0.Zone0):

    def make(self) -> str:
        """!
        @param incserial    If True then increment the serial number
        """
        logging.info('Doing network %s - %s', self.dt.data.network, self.dt.domain)

        st = ''
        st += self.make_soa()
        st += self.make_toplevel()  # TBD
        st += '\n'
        st += self.make_reverse()

        return st


if __name__ == '__main__':
    pass

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
