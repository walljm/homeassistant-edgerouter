# Ubiquiti EdgeRouter Integration for Home Assistant

[![GitHub Release](https://img.shields.io/github/release/walljm/homeassistant-edgerouter.svg?style=flat-square)](https://github.com/walljm/homeassistant-edgerouter/releases)
[![GitHub](https://img.shields.io/github/license/walljm/homeassistant-edgerouter.svg?style=flat-square)](LICENSE)
[![HACS](https://img.shields.io/badge/HACS-Custom-orange.svg?style=flat-square)](https://hacs.xyz/docs/faq/custom_repositories)

A custom Home Assistant integration to monitor connected clients on your Ubiquiti EdgeRouter via SSH. This integration does **not** require UniFi Controller - it connects directly to your EdgeRouter.

## Features

- **Device Tracker**: Track connected devices on your network using ARP table data
- **Presence Detection**: Configurable "consider home" window for more stable presence detection
- **DHCP Lease Information**: View DHCP hostnames and lease expiration times
- **Sensors**: Monitor total connected clients, ARP entries, and DHCP leases

## Requirements

- Ubiquiti EdgeRouter with SSH access enabled
- Home Assistant 2023.1 or newer
- SSH credentials for your EdgeRouter

## Installation

### HACS (Recommended)

1. Open HACS in Home Assistant
2. Click the three dots menu → Custom repositories
3. Add `https://github.com/walljm/homeassistant-edgerouter` and select "Integration" as the category
4. Search for "EdgeRouter" and install it
5. Restart Home Assistant

### Manual Installation

1. Download the latest release from [GitHub Releases](https://github.com/walljm/homeassistant-edgerouter/releases)
2. Copy the `custom_components/edgerouter` folder to your Home Assistant's `custom_components` directory
3. Restart Home Assistant

## Configuration

1. Go to **Settings** → **Devices & Services** → **Add Integration**
2. Search for "Ubiquiti EdgeRouter"
3. Enter your EdgeRouter's connection details:
   - **Host**: IP address or hostname of your EdgeRouter
   - **Username**: SSH username (default: `ubnt`)
   - **Password**: SSH password
   - **Port**: SSH port (default: `22`)

### Options

After setup, you can configure additional options:

- **Scan Interval**: How often to poll the router (10-300 seconds, default: 30)
- **Consider Home**: How long to consider a device as "home" after last seen (0-600 seconds, default: 180)

## Entities Created

### Device Trackers

For each device discovered on your network, a device tracker entity is created:
- Entity ID: `device_tracker.edgerouter_<mac_address>`
- Source type: Router
- Attributes include: MAC address, IP address, hostname, interface, lease expiration

### Sensors

- **Connected Clients**: Number of devices currently in the ARP table
- **ARP Entries**: Count of ARP table entries
- **DHCP Leases**: Count of active DHCP leases

## How It Works

This integration connects to your EdgeRouter via SSH and runs the following commands:

```bash
show arp          # Get ARP table (IP to MAC mappings)
show dhcp leases  # Get DHCP lease information
```

The data is combined to provide:
- MAC address to IP mappings
- Hostnames from DHCP
- Interface information
- Lease expiration times

Devices appearing in the ARP table are considered "connected". The "consider home" setting prevents devices from appearing as away due to temporary network changes.

## Troubleshooting

### Cannot Connect

- Verify SSH is enabled on your EdgeRouter
- Check that the host, username, and password are correct
- Ensure your Home Assistant can reach the EdgeRouter (no firewall blocking)
- Try connecting via SSH from the command line to test credentials

### Devices Not Appearing

- Devices must be in the ARP table to appear as "connected"
- Static IP devices without recent network activity may not appear in ARP
- Try pinging the device from the router to refresh the ARP table

### Enable Debug Logging

Add this to your `configuration.yaml`:

```yaml
logger:
  default: info
  logs:
    custom_components.edgerouter: debug
```

## EdgeRouter Commands Reference

Useful commands you can run on your EdgeRouter to troubleshoot:

```bash
# Show ARP table
show arp

# Show DHCP leases
show dhcp leases

# Show DHCP server status
show dhcp statistics

# Show network interfaces
show interfaces

# Show system info
show version
```

## Testing

Before installing in Home Assistant, you can test the connection to your EdgeRouter:

```bash
# Install dependencies
pip install -r requirements.txt

# Run the test script
python test_edgerouter.py <router-ip> <username> <password>

# Example
python test_edgerouter.py 192.168.1.1 ubnt mypassword
```

The test script will verify connectivity and display your ARP table and DHCP leases.

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on [GitHub](https://github.com/walljm/homeassistant-edgerouter).

## Credits

- Developed for Home Assistant integration with Ubiquiti EdgeOS routers
- Uses [Paramiko](https://www.paramiko.org/) for SSH connectivity

## Links

- [GitHub Repository](https://github.com/walljm/homeassistant-edgerouter)
- [Report an Issue](https://github.com/walljm/homeassistant-edgerouter/issues)
- [Home Assistant Community](https://community.home-assistant.io/)
