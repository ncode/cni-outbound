# CNI Outbound Plugin

## Overview

The CNI Outbound Plugin is a Container Network Interface (CNI) plugin designed to manage outbound network traffic for containers in Nomad environments. It creates and manages iptables rules to control outbound connections based on specified configurations and supports dynamic runtime rules.

## Features

- Creates a main iptables chain for outbound traffic control
- Generates container-specific iptables chains
- Applies outbound rules for each container based on configuration
- Supports runtime rules for dynamic traffic control
- Supports ADD, DEL, and CHECK operations as per CNI specification
- Integrates with existing CNI plugins as a chained plugin
- Specifically designed for use with Nomad

## Installation

To install the CNI Outbound Plugin, follow these steps:

1. Ensure you have Go installed on your system (version 1.15 or later recommended).
2. Clone the repository:
   ```
   git clone https://github.com/ncode/cni-outbound.git
   ```
3. Navigate to the project directory:
   ```
   cd cni-outbound
   ```
4. Build the plugin:
   ```
   go build -o outbound
   ```
5. Move the built binary to your CNI bin directory (typically `/opt/cni/bin/`):
   ```
   sudo mv outbound /opt/cni/bin/
   ```

## Configuration

The plugin is configured as part of a CNI configuration file. Here's an example configuration for use with Nomad:

```json
{
  "cniVersion": "0.4.0",
  "name": "my-network",
  "plugins": [
    {
      "type": "loopback"
    },
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
      "type": "portmap",
      "capabilities": {"portMappings": true}
    },
    {
      "type": "outbound",
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
      ]
    }
  ]
}
```

Plugin-specific configuration:
- `type`: Must be "outbound" for this plugin
- `chainName`: The name of the main iptables chain (default: "CNI-OUTBOUND")
- `defaultAction`: The default action for the container chain (default: "DROP")
- `outboundRules`: A list of outbound rules to apply to each container
- `runtimeRules`: A list of rules that can be dynamically added or removed at runtime (optional)

## Usage with Nomad

To use the CNI Outbound Plugin with Nomad:

1. Install the plugin in your CNI bin directory on all Nomad clients.
2. Create a CNI configuration file (e.g., `/opt/cni/config/my-network.conflist`) with content similar to the example above.
3. Configure Nomad to use this CNI configuration. In your Nomad client configuration, set:

   ```hcl
   client {
     cni_path = "/opt/cni/bin"
     cni_config_dir = "/opt/cni/config"
   }
   ```

4. In your Nomad job specification, use the network mode `cni`:

   ```hcl
   network {
     mode = "cni/my-network"
   }
   ```

The plugin will create the necessary iptables rules when Nomad launches containers and clean them up when containers are destroyed.

### Runtime Rules

Runtime rules allow for dynamic modification of the firewall rules without changing the CNI configuration. These rules can be added or removed while containers are running, providing flexibility in managing network traffic.

To add or remove runtime rules, you'll need to use the plugin's runtime API (details of which should be documented separately, based on how your plugin implements this feature).

## Development

To contribute to the CNI Outbound Plugin:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Troubleshooting

If you encounter issues with the plugin in your Nomad environment, consider the following steps:

1. Check Nomad's logs for any error messages related to CNI or networking.
2. Verify that the plugin binary is correctly installed in the CNI bin directory specified in your Nomad configuration.
3. Ensure that the CNI configuration file is correctly formatted and located in the directory specified by `cni_config_dir` in your Nomad client configuration.
4. Use `iptables -L` and `iptables-save` to inspect the current iptables rules and verify that the plugin is creating the expected chains and rules.
5. If using Consul Connect with Nomad, ensure that the outbound rules allow necessary communication between services.
6. Check the Nomad allocation logs for any network-related errors or warnings.

## Nomad Job Example

Here's a simple Nomad job example that uses the CNI Outbound Plugin:

```hcl
job "example" {
  datacenters = ["dc1"]

  group "app" {
    network {
      mode = "cni/my-network"
    }

    task "server" {
      driver = "docker"
      
      config {
        image = "nginx:latest"
      }
    }
  }
}
```

Ensure that the network mode matches the name of your CNI configuration file.

## License

This project is licensed under Apache-2.0

## Acknowledgments

- [CNI - Container Network Interface](https://github.com/containernetworking/cni)
- [go-iptables](https://github.com/coreos/go-iptables)
- [Nomad by HashiCorp](https://www.nomadproject.io/)

For more information on CNI plugins and their use with Nomad, refer to the [Nomad CNI documentation](https://www.nomadproject.io/docs/networking/cni).
