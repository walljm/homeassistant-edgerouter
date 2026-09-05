"""Constants for the EdgeRouter integration."""

DOMAIN = "edgerouter"

# Configuration keys
CONF_CONSIDER_HOME = "consider_home"
CONF_SSH_PORT = "ssh_port"
CONF_SSH_KEY_PATH = "ssh_key_path"

# Default values
DEFAULT_SCAN_INTERVAL = 30  # seconds
DEFAULT_CONSIDER_HOME = 180  # seconds - how long to consider a device "home" after last seen
DEFAULT_SSH_PORT = 22

# Events
EVENT_NEW_DEVICE = "edgerouter_new_device"
EVENT_UNKNOWN_DEVICE = "edgerouter_unknown_device"

# Attributes
ATTR_HOSTNAME = "hostname"
ATTR_MAC_ADDRESS = "mac_address"
ATTR_IP_ADDRESS = "ip_address"
ATTR_INTERFACE = "interface"
ATTR_LEASE_EXPIRES = "lease_expires"
ATTR_CONNECTION_TYPE = "connection_type"
ATTR_IPV6_ADDRESS = "ipv6_address"
ATTR_IPV6_CONNECTION_TYPE = "ipv6_connection_type"
ATTR_IPV6_LEASE_STATE = "ipv6_lease_state"
ATTR_IPV6_LEASE_ENDS = "ipv6_lease_ends"
ATTR_IPV6_DUID = "ipv6_duid"
