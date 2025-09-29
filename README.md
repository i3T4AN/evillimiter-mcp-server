# EvilLimiter MCP Server

A Model Context Protocol (MCP) server that provides controlled access to EvilLimiter network bandwidth management and monitoring capabilities.

##  IMPORTANT LEGAL NOTICE

This tool performs ARP spoofing and traffic manipulation. It must ONLY be used on:
- Networks you own
- Networks where you have explicit written permission to perform testing
- Isolated lab environments for educational purposes

Unauthorized use may violate computer fraud laws, network policies, and regulations. You are solely responsible for ensuring legal compliance.

## Purpose

This MCP server provides a secure API interface for AI assistants to control network bandwidth, monitor traffic, and manage device connections using EvilLimiter. Designed for authorized network testing, debugging, and educational purposes only.

## Features

### Current Implementation
- **`scan_network`** - Scan for online hosts with optional IP range specification
- **`list_hosts`** - Display all discovered hosts with IDs and network information
- **`limit_bandwidth`** - Throttle bandwidth for specific hosts (upload/download/both)
- **`block_host`** - Block internet access for specific hosts
- **`free_host`** - Remove all restrictions from hosts
- **`add_host`** - Manually add hosts to the management list
- **`monitor_bandwidth`** - Real-time bandwidth usage monitoring
- **`analyze_traffic`** - Analyze traffic patterns without limiting
- **`watch_status`** - View watchlist for reconnection detection
- **`watch_add`** - Add hosts to reconnection watchlist
- **`watch_remove`** - Remove hosts from watchlist
- **`watch_configure`** - Configure watch settings (range, interval)
- **`flush_configuration`** - Reset all network configurations

## Prerequisites

- Docker Desktop with MCP Toolkit enabled
- Docker MCP CLI plugin (`docker mcp` command)
- Linux host (EvilLimiter requires Linux)
- Network interface access (container needs NET_ADMIN and NET_RAW capabilities)

## Installation

### 1. Build Docker Image
```bash
docker build -t evillimiter-mcp-server .
```

### 2. Create Custom Catalog
Create `~/.docker/mcp/catalogs/custom.yaml`:
```yaml
version: 2
name: custom
displayName: Custom MCP Servers
registry:
  evillimiter:
    description: "Network bandwidth control and monitoring via EvilLimiter"
    title: "EvilLimiter"
    type: server
    dateAdded: "2025-01-29T00:00:00Z"
    image: evillimiter-mcp-server:latest
    ref: ""
    tools:
      - name: scan_network
      - name: list_hosts
      - name: limit_bandwidth
      - name: block_host
      - name: free_host
      - name: add_host
      - name: monitor_bandwidth
      - name: analyze_traffic
      - name: watch_status
      - name: watch_add
      - name: watch_remove
      - name: watch_configure
      - name: flush_configuration
    metadata:
      category: monitoring
      tags:
        - network
        - bandwidth
        - monitoring
        - security
      license: MIT
      owner: local
    containerConfig:
      capAdd:
        - NET_ADMIN
        - NET_RAW
      network: host
```

### 3. Update Registry
Edit `~/.docker/mcp/registry.yaml` and add under `registry:`:
```yaml
evillimiter:
  ref: ""
```

### 4. Configure Claude Desktop
Add `"--catalog=/mcp/catalogs/custom.yaml"` to your Claude Desktop config args.

### 5. Restart Claude Desktop

## Container Privileges

This container requires elevated network privileges to function:
```bash
docker run --cap-add=NET_ADMIN --cap-add=NET_RAW --network=host evillimiter-mcp-server
```
Or use `--privileged` flag (less secure but simpler).

## Usage Examples

In Claude Desktop, you can ask:
- "Scan the network for all devices"
- "List all connected hosts on the network"
- "Limit device ID 3 to 100kbit bandwidth"
- "Block internet access for device IDs 2 and 4"
- "Monitor current bandwidth usage of limited devices"
- "Analyze traffic for device ID 5 for 60 seconds"
- "Add device 192.168.1.100 to the watchlist"
- "Free all restrictions from device ID 6"
- "Show the current watch status"
- "Flush all network configurations"

## Environment Variables

- `EVILLIMITER_INTERFACE` - Network interface to use (auto-detected if not set)
- `EVILLIMITER_GATEWAY_IP` - Gateway IP address (auto-detected if not set)
- `EVILLIMITER_GATEWAY_MAC` - Gateway MAC address (auto-detected if not set)
- `EVILLIMITER_NETMASK` - Network mask (auto-detected if not set)
- `EVILLIMITER_SAFETY_MODE` - Enable safety checks (default: true)
- `EVILLIMITER_ALLOWED_RANGES` - Comma-separated IP ranges to allow (if safety mode on)
- `EVILLIMITER_API_TOKEN` - API token for authentication (optional)

## Architecture

```
Claude Desktop → MCP Gateway → EvilLimiter MCP Server → EvilLimiter CLI
                                         ↓
                              Network Interface (ARP/iptables/tc)
                                         ↓
                                 Docker Secrets (optional)
```

## Development

### Local Testing
```bash
# Set environment variables for testing
export EVILLIMITER_INTERFACE="eth0"
export EVILLIMITER_SAFETY_MODE="true"
export EVILLIMITER_ALLOWED_RANGES="192.168.1.0/24"

# Run directly (requires root/sudo)
sudo python evillimiter_server.py

# Test MCP protocol
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | sudo python evillimiter_server.py
```

### Adding New Tools
1. Add the function to evillimiter_server.py
2. Decorate with @mcp.tool()
3. Update the catalog entry with the new tool name
4. Rebuild the Docker image

## Troubleshooting

### Tools Not Appearing
- Verify Docker image built successfully
- Check catalog and registry files syntax
- Ensure Claude Desktop config includes custom catalog
- Restart Claude Desktop completely

### Permission Errors
- Ensure container runs with proper capabilities
- Check if running with --network=host
- Verify iptables/tc access

### Network Detection Issues
- Manually specify interface with EVILLIMITER_INTERFACE
- Set gateway IP/MAC if auto-detection fails
- Check container network mode

## Security Considerations

- Container requires elevated privileges (NET_ADMIN, NET_RAW)
- ARP spoofing affects entire network segment
- All actions are logged to stderr
- Safety mode restricts target IP ranges
- API token authentication available
- Input sanitization prevents command injection
- Never expose this service to the internet

## Limitations

- IPv4 only (ARP spoofing requires IPv4)
- Linux host required
- Affects all devices on local network segment
- Cannot bypass HTTPS certificate pinning
- Detection possible via ARP monitoring tools

## License

MIT License - Use at your own risk and responsibility
