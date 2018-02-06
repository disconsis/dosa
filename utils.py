import netaddr


class MAC(netaddr.EUI):
    """class for MAC addresses

    attributes:
        broadcast
        mac
    """

    def __init__(self, mac):
        super().__init__(mac, dialect=netaddr.mac_unix_expanded)

    def __bool__(self):
        return self != self.broadcast

MAC.broadcast = MAC('ff:ff:ff:ff:ff:ff')


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
            self.mac = MAC(mac)

    @property
    def vendor(self):
        if not self.mac:
            return None
        return ' | '.join(
            self.mac.oui.registration(i).org.title()
            for i in range(self.mac.oui.reg_count)
        )

    def resolve_mac(self):
        pass

    def resolve_os(self):
        pass
