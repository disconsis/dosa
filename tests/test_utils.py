from nose.tools import assert_equal
import utils
import netaddr


def test_mac_has_broadcast_addr():
    assert_equal(str(utils.MAC.broadcast), 'ff:ff:ff:ff:ff:ff')
    assert_equal(utils.MAC.broadcast, netaddr.EUI('ff:ff:ff:ff:ff:ff'))
