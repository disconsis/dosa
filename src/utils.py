import netaddr
from scapy.sendrecv import srp1
from scapy.layers.all import Ether, ARP
from scapy.config import conf
from scapy import route


class AddressNotResolvedError(Exception):
    pass


class MAC(netaddr.EUI):
    """class for MAC addresses

    attributes:
        broadcast
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
        arp_timeout

    methods:
        resolve_mac()
        resolve_os()
    """

    arp_timeout = 5
    arp_retries = 3

    def __init__(self, ip, mac=None):
        # TODO: make like ipaddress.IPv4Address and not have to str() for funcs
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

    def resolve_mac(self, timeout=None, retries=None):
        if timeout is None:
            timeout = self.arp_timeout
        if retries is None:
            retries = self.arp_retries

        # TODO: randomize source
        resp = srp1(
            Ether() / ARP(pdst=str(self.ip)),
            retry=retries,
            timeout=timeout,
            iface=conf.iface,
        )
        if resp is None:
            raise AddressNotResolvedError(
                'failed to resolve {}'.format(self.ip)
            )
        else:
            self.mac = MAC(resp[ARP].hwsrc)

    def resolve_os(self):
        raise NotImplementedError
