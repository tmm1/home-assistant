"""
homeassistant.components.device_tracker.arp_scan
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Device tracker platform that supports scanning a network with arp-scan.

Configuration:

To use the arp_scan tracker you will need to add something like the following
to your configuration.yaml file.

device_tracker:
  platform: arp_scan

Variables:

hosts
*Optional
The IP addresses to scan in the network-prefix notation (192.168.1.1/24) or
the range notation (192.168.1.1-255). By default, the local network with be
scanned.
"""
import logging
from datetime import timedelta
from collections import namedtuple
import os
import re

import homeassistant.util.dt as dt_util
from homeassistant.const import CONF_HOSTS
from homeassistant.helpers import validate_config
from homeassistant.util import Throttle, convert
from homeassistant.components.device_tracker import DOMAIN

# Return cached results if last scan was less then this time ago
MIN_TIME_BETWEEN_SCANS = timedelta(seconds=60)

_LOGGER = logging.getLogger(__name__)


def get_scanner(hass, config):
    """ Validates config and returns a Arp scanner. """
    if not validate_config(config, {DOMAIN: []},
                           _LOGGER):
        return None

    scanner = ArpScanner(config[DOMAIN])

    return scanner if scanner.success_init else None

Device = namedtuple("Device", ["mac", "name", "ip", "last_update"])


class ArpScanner(object):
    """ This class scans for devices using arp-scan. """

    def __init__(self, config):
        self.last_results = []

        self.hosts = config.get(CONF_HOSTS)

        self.success_init = self._update_info()
        _LOGGER.info("arp scanner initialized")

    def scan_devices(self):
        """
        Scans for new devices and return a list containing found device ids.
        """

        self._update_info()

        return [device.mac for device in self.last_results]

    def get_device_name(self, mac):
        """ Returns the name of the given device or None if we don't know. """

        filter_named = [device.name for device in self.last_results
                        if device.mac == mac]

        if filter_named:
            return filter_named[0]
        else:
            return None

    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _update_info(self):
        """
        Scans the network for devices.
        Returns boolean if scanning successful.
        """
        _LOGGER.info("Scanning")

        cmd = "arp-scan "
        if self.hosts:
            cmd += self.hosts
        else:
            cmd += "-l"

        now = dt_util.now()
        self.last_results = []
        for line in os.popen("arp-scan -l").read().split("\n")[2:-4]:
            ipv4, mac, name = line.split("\t")
            device = Device(mac.upper(), name, ipv4, now)
            self.last_results.append(device)

        _LOGGER.info("arp scan successful")
        return True
