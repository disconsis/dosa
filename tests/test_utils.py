import utils
import netaddr


def test_mac_has_broadcast_addr():
    assert str(utils.MAC.broadcast) == 'ff:ff:ff:ff:ff:ff'
    assert utils.MAC.broadcast == netaddr.EUI('ff:ff:ff:ff:ff:ff')


def test_mac_takes_argument_and_creates_eui_object():
    assert utils.MAC('11:22:33:44:55:66') == netaddr.EUI('11:22:33:44:55:66')
    assert utils.MAC('12:34:56:78:9a:bc') == netaddr.EUI('12:34:56:78:9a:bc')


def test_mac_has_valid_str_representation():
    assert str(utils.MAC('11:22:33:44:55:66')) == '11:22:33:44:55:66'
    assert str(utils.MAC('12:34:56:78:9a:bc')) == '12:34:56:78:9a:bc'
