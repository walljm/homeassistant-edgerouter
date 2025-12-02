# Ubiquiti EdgeRouter Integration for Home Assistant

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
3. Add this repository URL and select "Integration" as the category
4. Search for "EdgeRouter" and install it
5. Restart Home Assistant

### Manual Installation

1. Copy the `custom_components/edgerouter` folder to your Home Assistant's `custom_components` directory
2. Restart Home Assistant

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

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Credits

- Developed for Home Assistant integration with Ubiquiti EdgeOS routers
- Uses [Paramiko](https://www.paramiko.org/) for SSH connectivity
