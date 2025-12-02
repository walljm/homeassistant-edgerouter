"""Constants for the EdgeRouter integration."""

DOMAIN = "edgerouter"

# Configuration keys
CONF_CONSIDER_HOME = "consider_home"
CONF_SSH_PORT = "ssh_port"

# Default values
DEFAULT_SCAN_INTERVAL = 30  # seconds
DEFAULT_CONSIDER_HOME = 180  # seconds - how long to consider a device "home" after last seen
DEFAULT_SSH_PORT = 22

# Attributes
ATTR_HOSTNAME = "hostname"
ATTR_MAC_ADDRESS = "mac_address"
ATTR_IP_ADDRESS = "ip_address"
ATTR_INTERFACE = "interface"
ATTR_LEASE_EXPIRES = "lease_expires"
ATTR_LAST_SEEN = "last_seen"
ATTR_CONNECTION_TYPE = "connection_type"
