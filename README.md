# CNI Output Plugin

## Overview

The CNI Output Plugin is a Container Network Interface (CNI) plugin designed to manage outbound network traffic for containers. It creates and manages iptables rules to control outbound connections based on specified configurations and supports dynamic runtime rules.

## Features

- Creates a main iptables chain for outbound traffic control
- Generates container-specific iptables chains
- Applies outbound rules for each container based on configuration
- Supports runtime rules for dynamic traffic control
- Supports ADD, DEL, and CHECK operations as per CNI specification
- Integrates with existing CNI plugins as a chained plugin

## Installation

To install the CNI Output Plugin, follow these steps:

1. Ensure you have Go installed on your system.
2. Clone the repository:
   ```
   git clone https://github.com/ncode/cni-output.git
   ```
3. Navigate to the project directory:
   ```
   cd cni-output/plugins/output
   ```
4. Build the plugin:
   ```
   go build -o output
   ```
5. Move the built binary to your CNI bin directory (typically `/opt/cni/bin/`):
   ```
   sudo mv output /opt/cni/bin/
   ```

## Configuration

The plugin is configured as part of a CNI configuration file. Here's an example configuration:

```json
{
  "cniVersion": "0.4.0",
  "name": "nomad-docker-bridge",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "docker0",
      "ipMasq": true,
      "isGateway": true,
      "forceAddress": true,
      "hairpinMode": false,
      "ipam": {
        "type": "host-local",
        "ranges": [
          [
            {
              "subnet": "172.18.0.0/16"
            }
          ]
        ],
        "routes": [
          { "dst": "0.0.0.0/0" }
        ]
      }
    },
    {
      "type": "firewall",
      "backend": "iptables",
      "iptablesAdminChainName": "CNI-NDB"
    },
    {
      "type": "output",
      "chainName": "CNI-OUTBOUND",
      "defaultAction": "DROP",
      "outboundRules": [
        {
          "host": "8.8.8.8",
          "proto": "udp",
          "port": "53",
          "action": "ACCEPT"
        },
        {
          "host": "192.168.1.0/24",
          "proto": "tcp",
          "port": "80",
          "action": "ACCEPT"
        }
      ],
      "runtimeRules": [
        {
          "host": "10.0.0.0/8",
          "proto": "tcp",
          "port": "443",
          "action": "ACCEPT"
        }
      ]
    },
    {
      "type": "portmap",
      "capabilities": {"portMappings": true}
    }
  ]
}
```

Plugin-specific configuration:
- `type`: Must be "output" for this plugin
- `chainName`: The name of the main iptables chain (default: "CNI-OUTBOUND")
- `defaultAction`: The default action for the container chain (default: "DROP")
- `outboundRules`: A list of outbound rules to apply to each container
- `runtimeRules`: A list of rules that can be dynamically added or removed at runtime

## Usage

This plugin is designed to be used as part of a CNI plugin chain. Include it in your CNI configuration file along with other plugins that set up the basic network configuration.

To use the CNI Output Plugin:

1. Install the plugin in your CNI bin directory.
2. Create a CNI configuration file (e.g., `/etc/cni/net.d/10-nomad-docker-bridge.conf`) with the content similar to the example above.
3. Ensure that container runtimes or orchestrators (like Docker or Nomad) are configured to use this CNI configuration.

The plugin will create the necessary iptables rules when containers are created and clean them up when containers are destroyed.

### Runtime Rules

Runtime rules allow for dynamic modification of the firewall rules without changing the CNI configuration. These rules can be added or removed while containers are running, providing flexibility in managing network traffic.

To add or remove runtime rules, you'll need to use the plugin's runtime API (details of which should be documented separately, based on how your plugin implements this feature).

## Development

To contribute to the CNI Output Plugin:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under Apache-2.0

## Acknowledgments

- [CNI - Container Network Interface](https://github.com/containernetworking/cni)
- [go-iptables](https://github.com/coreos/go-iptables)

For more information on CNI plugins, refer to the [CNI Specification](https://github.com/containernetworking/cni/blob/master/SPEC.md).
