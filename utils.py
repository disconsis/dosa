import netaddr


class MAC(netaddr.EUI):
    """class for MAC addresses

    attributes:
        broadcast
        mac
    """

    broadcast = netaddr.EUI('ff:ff:ff:ff:ff:ff',
                            dialect=netaddr.mac_unix_expanded)

    def __init__(self, mac):
        super().__init__(mac, dialect=netaddr.mac_unix_expanded)

    def __bool__(self):
        return self != self.broadcast


class Host:
    """class for single host

    attributes:
        ip
        mac
        active
        os
        vendor

    methods:
        resolve_mac()
        resolve_os()
    """

    def __init__(self, ip, mac=None):
        self.ip = netaddr.IPAddress(ip)
        if mac is None:
            self.mac = MAC.broadcast
        else:
            self.mac = netaddr.EUI(mac)

    def resolve_mac(self):
        pass

    def resolve_os(self):
        pass
