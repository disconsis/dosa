import unittest
import utils


class MACTest(unittest.TestCase):

    def test_mac_has_broadcast_addr(self):
        self.assertEqual(str(utils.MAC.broadcast), 'ff:ff:ff:ff:ff:ff')


if __name__ == '__main__':
    unittest.main()
