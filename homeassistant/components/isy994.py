"""
homeassistant.components.isy994
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Connects to an ISY-994 controller and loads relevant components to control its
devices. Also contains the base classes for ISY Sensors, Lights, and Switches.

For configuration details please visit the documentation for this component at
https://home-assistant.io/components/isy994.html
"""
import logging
from urllib.parse import urlparse

from homeassistant import bootstrap
from homeassistant.loader import get_component
from homeassistant.helpers import validate_config
from homeassistant.helpers.entity import ToggleEntity
from homeassistant.const import (
    CONF_HOST, CONF_USERNAME, CONF_PASSWORD, EVENT_PLATFORM_DISCOVERED,
    EVENT_HOMEASSISTANT_STOP, ATTR_SERVICE, ATTR_DISCOVERED,
    ATTR_FRIENDLY_NAME)

DOMAIN = "isy994"
DEPENDENCIES = []
REQUIREMENTS = ['PyISY==1.0.5']
DISCOVER_LIGHTS = "isy994.lights"
DISCOVER_SWITCHES = "isy994.switches"
DISCOVER_SENSORS = "isy994.sensors"
ISY = None
SENSOR_STRING = 'Sensor'
HIDDEN_STRING = '{HIDE ME}'
CONF_TLS_VER = 'tls'

_LOGGER = logging.getLogger(__name__)


def setup(hass, config):
    """
    Setup ISY994 component.
    This will automatically import associated lights, switches, and sensors.
    """
    try:
        import PyISY
    except ImportError:
        _LOGGER.error("Error while importing dependency PyISY.")
        return False

    # pylint: disable=global-statement
    # check for required values in configuration file
    if not validate_config(config,
                           {DOMAIN: [CONF_HOST, CONF_USERNAME, CONF_PASSWORD]},
                           _LOGGER):
        return False

    # pull and parse standard configuration
    user = config[DOMAIN][CONF_USERNAME]
    password = config[DOMAIN][CONF_PASSWORD]
    host = urlparse(config[DOMAIN][CONF_HOST])
    addr = host.geturl()
    if host.scheme == 'http':
        addr = addr.replace('http://', '')
        https = False
    elif host.scheme == 'https':
        addr = addr.replace('https://', '')
        https = True
    else:
        _LOGGER.error('isy994 host value in configuration file is invalid.')
        return False
    port = host.port
    addr = addr.replace(':{}'.format(port), '')

    # pull and parse optional configuration
    global SENSOR_STRING
    global HIDDEN_STRING
    SENSOR_STRING = str(config[DOMAIN].get('sensor_string', SENSOR_STRING))
    HIDDEN_STRING = str(config[DOMAIN].get('hidden_string', HIDDEN_STRING))
    tls_version = config[DOMAIN].get(CONF_TLS_VER, None)

    # connect to ISY controller
    global ISY
    ISY = PyISY.ISY(addr, port, user, password, use_https=https,
                    tls_ver=tls_version, log=_LOGGER)
    if not ISY.connected:
        return False

    # listen for HA stop to disconnect
    hass.bus.listen_once(EVENT_HOMEASSISTANT_STOP, stop)

    # Load components for the devices in the ISY controller that we support
    for comp_name, discovery in ((('sensor', DISCOVER_SENSORS),
                                  ('light', DISCOVER_LIGHTS),
                                  ('switch', DISCOVER_SWITCHES))):
        component = get_component(comp_name)
        bootstrap.setup_component(hass, component.DOMAIN, config)
        hass.bus.fire(EVENT_PLATFORM_DISCOVERED,
                      {ATTR_SERVICE: discovery,
                       ATTR_DISCOVERED: {}})

    ISY.auto_update = True
    return True


def stop(event):
    """ Cleanup the ISY subscription. """
    ISY.auto_update = False


class ISYDeviceABC(ToggleEntity):
    """ Abstract Class for an ISY device. """

    _attrs = {}
    _onattrs = []
    _states = []
    _dtype = None
    _domain = None
    _name = None

    def __init__(self, node):
        # setup properties
        self.node = node
        self.hidden = HIDDEN_STRING in self.raw_name

        # track changes
        self._change_handler = self.node.status. \
            subscribe('changed', self.on_update)

    def __del__(self):
        """ cleanup subscriptions because it is the right thing to do. """
        self._change_handler.unsubscribe()

    @property
    def domain(self):
        """ Returns the domain of the entity. """
        return self._domain

    @property
    def dtype(self):
        """ Returns the data type of the entity (binary or analog). """
        if self._dtype in ['analog', 'binary']:
            return self._dtype
        return 'binary' if self.unit_of_measurement is None else 'analog'

    @property
    def should_poll(self):
        """ Tells Home Assistant not to poll this entity. """
        return False

    @property
    def value(self):
        """ Returns the unclean value from the controller. """
        # pylint: disable=protected-access
        return self.node.status._val

    @property
    def state_attributes(self):
        """ Returns the state attributes for the node. """
        attr = {ATTR_FRIENDLY_NAME: self.name}
        for name, prop in self._attrs.items():
            attr[name] = getattr(self, prop)
            attr = self._attr_filter(attr)
        return attr

    def _attr_filter(self, attr):
        """ Placeholder for attribute filters. """
        # pylint: disable=no-self-use
        return attr

    @property
    def unique_id(self):
        """ Returns the id of this ISY sensor. """
        # pylint: disable=protected-access
        return self.node._id

    @property
    def raw_name(self):
        """ Returns the unclean node name. """
        return str(self._name) \
            if self._name is not None else str(self.node.name)

    @property
    def name(self):
        """ Returns the cleaned name of the node. """
        return self.raw_name.replace(HIDDEN_STRING, '').strip() \
            .replace('_', ' ')

    def update(self):
        """ Update state of the sensor. """
        # ISY objects are automatically updated by the ISY's event stream
        pass

    def on_update(self, event):
        """ Handles the update received event. """
        self.update_ha_state()

    @property
    def is_on(self):
        """ Returns boolean response if the node is on. """
        return bool(self.value)

    @property
    def is_open(self):
        """ Returns boolean respons if the node is open. On = Open. """
        return self.is_on

    @property
    def state(self):
        """ Returns the state of the node. """
        if len(self._states) > 0:
            return self._states[0] if self.is_on else self._states[1]
        return self.value

    def turn_on(self, **kwargs):
        """ Turns the device on. """
        if self.domain is not 'sensor':
            attrs = [kwargs.get(name) for name in self._onattrs]
            self.node.on(*attrs)
        else:
            _LOGGER.error('ISY cannot turn on sensors.')

    def turn_off(self, **kwargs):
        """ Turns the device off. """
        if self.domain is not 'sensor':
            self.node.off()
        else:
            _LOGGER.error('ISY cannot turn off sensors.')

    @property
    def unit_of_measurement(self):
        """ Returns the defined units of measurement or None. """
        try:
            return self.node.units
        except AttributeError:
            return None
