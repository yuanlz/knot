#!/usr/bin/env python3

'''Test for AXFR from Knot to Knot'''

from dnstest.test import Test
import dnstest.keys

tsig=dnstest.keys.Tsig("key.", "hmac-sha224", "Zm9v")
t = Test(tsig=tsig, stress=False, address="127.0.0.1")

m1 = t.server("knot", address="127.0.0.1", port="5001")
m2 = t.server("knot",  address="127.0.0.1", port="5002")
zones = t.zone("x.", storage=".") + t.zone(".", storage=".")
t.link(zones, m1)
t.link(zones, m2)

t.start()
t.sleep(1)
t.xfr_diff(m1, m2, zones)
t.end()
