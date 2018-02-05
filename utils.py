import netaddr


class MAC(netaddr.EUI):
    """class for MAC addresses

    attributes:
        broadcast
        mac
    """

    def __init__(self):
        pass


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

    def __init__(self):
        pass

    def resolve_mac(self):
        pass

    def resolve_os(self):
        pass
