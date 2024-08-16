# CNI Outbound Plugin Development Environment

This folder contains the development environment setup for the CNI Outbound Plugin. It uses Docker Compose to create a Nomad server with the plugin pre-installed and configured.

## Docker Build

The Docker image is built using the `Dockerfile` in this directory. It:

1. Uses Oracle Linux 9 as the base image
2. Installs necessary tools like `dig`, `curl`, `iptables`, and more
3. Downloads and installs Nomad
4. Downloads and installs CNI plugins
5. Copies the CNI plugin binary and configuration files
6. Sets up the entrypoint script

To build the Docker image manually:

```bash
docker build -t ncode/cni-output:dev .
```

## Nomad Configuration

The Nomad agent is configured with the following settings (in `config.hcl`):

```hcl
server {
  enabled          = true
  bootstrap_expect = 1
}
datacenter = "dc1"
region     = "rg1"
bind_addr  = "0.0.0.0"
data_dir   = "/var/lib/nomad"
client {
  enabled               = true
  cpu_total_compute     = 2000
  bridge_network_name   = "cni0"
  bridge_network_subnet = "172.18.0.0/16"
}
```

This configuration:
- Enables both server and client mode on the same node
- Sets up a single-node cluster (bootstrap_expect = 1)
- Configures the datacenter as "dc1" and region as "rg1"
- Binds Nomad to all network interfaces
- Sets the data directory to "/var/lib/nomad"
- Configures the client with 2000 MHz of CPU
- Sets up the CNI bridge network named "cni0" with the subnet 172.18.0.0/16

## Docker Compose Setup

The development environment is set up using Docker Compose with the following configuration:

```yaml
services:
  nomad:
    image: ncode/cni-output:dev 
    ports:
      - "4646:4646"  # HTTP API
      - "4647:4647"  # RPC
      - "4648:4648"  # Serf WAN
      - "8080:8080"  # Container handler
    volumes:
      - /sys/fs/cgroup:/sys/fs/cgroup:rw
    privileged: true
    deploy:
      resources:
        limits:
          cpus: 2.0
          memory: 512M
        reservations:
          cpus: 2.0
          memory: 512M
networks:
  default:
    driver: bridge
```

This setup:
- Uses the custom `ncode/cni-output:dev` image
- Exposes necessary ports for Nomad and the test container
- Mounts the host's cgroup filesystem
- Runs in privileged mode for full network access
- Limits and reserves 2 CPUs and 512MB of memory
- Uses the default bridge network driver

## CNI Setup

The CNI configuration is defined in the `my-network.conflist` file, which is copied into the Docker image. This configuration sets up a network with multiple plugins:

1. **Loopback**: Sets up the loopback interface.

2. **Bridge**: Creates a bridge network named "cni0".
   - Enables IP masquerading
   - Acts as a gateway
   - Uses the "host-local" IPAM plugin to assign IPs from the 172.18.0.0/16 subnet

3. **Firewall**: Sets up iptables rules with an admin chain named "CNI-NDB".

4. **Portmap**: Enables port mapping capabilities.

5. **Outbound** (Custom Plugin): Configures outbound traffic rules.
   - Creates a chain named "CNI-OUTBOUND"
   - Sets the default action to DROP
   - Enables logging to /var/log/cni
   - Defines a rule to allow UDP traffic to 8.8.8.8 on port 53 (DNS)

This configuration allows the CNI Outbound Plugin to control outbound traffic, specifically allowing DNS queries to 8.8.8.8 while blocking other outbound traffic by default.

## Container Entrypoint

The development environment uses an entrypoint script (`entrypoint.sh`) to set up the necessary network settings and start the Nomad agent. Here's what the script does:

```bash
#!/bin/bash

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Enable iptables processing for bridge networks
echo 1 > /proc/sys/net/bridge/bridge-nf-call-arptables
echo 1 > /proc/sys/net/bridge/bridge-nf-call-ip6tables
echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables

# Start the Nomad agent with the provided configuration
nomad agent -config=/etc/nomad
```

This script:

1. Enables IP forwarding, which is necessary for NAT and routing between containers and the host.
2. Enables iptables processing for bridge networks, allowing the CNI plugins to manage network rules effectively.
3. Starts the Nomad agent using the configuration file at `/etc/nomad`.

These settings are crucial for the proper functioning of the CNI plugins, especially the custom Outbound plugin, as they ensure that network traffic can be properly routed and filtered.

## Development Workflow

1. Build the project, create the Docker image, and start the development environment:
   ```bash
   make all
   ```

2. To stop and remove the development environment:
   ```bash
   make down
   ```

3. To rebuild and restart the environment after making changes:
   ```bash
   make down all
   ```

## Testing the Setup

Once the development environment is running:

1. Access the Nomad UI at `http://localhost:4646`

2. Submit the `cni-outbound-job.hcl` job to Nomad:
   ```bash
   NOMAD_ADDR=http://127.0.0.1:4646 nomad job run cni-outbound-job.hcl
   ```
   This command sets the `NOMAD_ADDR` environment variable to ensure the Nomad CLI connects to the correct Nomad server.

3. Test the NAT configuration:
   ```bash
   curl http://127.0.0.1:8080
   ```
   This should return "Hello, World!", confirming that the NAT is working correctly and the job's HTTP server is accessible.

4. Check the job logs in the Nomad UI. You should see:
   - Successful DNS queries to 8.8.8.8 (Google's primary DNS server)
   - Failed DNS queries to 8.8.4.4 (Google's secondary DNS server)

This behavior demonstrates that the CNI Outbound Plugin is correctly applying the outbound rules:
- Allowing traffic to 8.8.8.8
- Blocking traffic to 8.8.4.4

## The cni-outbound-job

The `cni-outbound-job.hcl` file defines a Nomad job that:
- Sets up a simple HTTP server on port 8080
- Performs periodic DNS lookups to 8.8.8.8 and 8.8.4.4

This job helps verify the CNI Outbound Plugin's functionality by demonstrating allowed and blocked outbound traffic.

## Network Troubleshooting

When troubleshooting network issues or verifying the CNI plugin's behavior, the following commands can be helpful. First, access the Nomad container:

```bash
docker compose exec nomad bash
```

Then, you can use these commands:

1. List network namespaces:
   ```bash
   ip netns list
   ```

1. Connect to a specific network namespace (replace `<namespace_name>` with the actual namespace):
   ```bash
   ip netns exec <namespace_name> bash
   ```

   Once inside the namespace, you can run network-related commands to inspect that specific namespace's configuration. For example:

   ```bash
   # Inside the namespace
   ip addr show
   ip route show
   iptables -L -v -n
   ```

   To exit the namespace, simply type `exit`.

1. Inspect bridge configuration:
   ```bash
   ip link show type bridge
   bridge link show
   ```

1. Examine iptables rules (both in host and within namespaces):
   ```bash
   iptables -L -v -n
   iptables -t nat -L -v -n
   ```

1. View network interfaces and their configurations:
   ```bash
   ip addr show
   ip link show
   ```

1. Check routing table (both in host and within namespaces):
   ```bash
   ip route show
   ```

1. Inspect CNI configuration:
   ```bash
   cat /opt/cni/config/my-network.conflist
   ```

1. Verify CNI plugin binary:
   ```bash
   ls -l /opt/cni/bin/outbound
   ```

1. Check CNI plugin logs:
    ```bash
    tail /var/log/cni/outbound.log
    ```

1. Test DNS resolution (both in host and within namespaces):
    ```bash
    dig google.com @8.8.8.8
    dig google.com @8.8.4.4
    ```

1. Trace network path (both in host and within namespaces):
    ```bash
    traceroute 8.8.8.8
    ```

1. To run commands in a specific namespace without entering it, use:
    ```bash
    ip netns exec <namespace_name> <command>
    ```
    For example:
    ```bash
    ip netns exec <namespace_name> ip addr show
    ```

These commands will help you inspect various aspects of the network configuration, including network namespaces, bridges, iptables rules, routing, and DNS resolution when troubleshooting issues with the CNI Outbound Plugin or understanding how the network is configured in the development environment.

## Troubleshooting

If you encounter issues:

1. Check the Nomad server logs:
   ```bash
   docker compose logs nomad
   ```

2. Inspect the iptables rules inside the Nomad container:
   ```bash
   docker compose exec nomad iptables -L
   ```

3. Verify the CNI configuration:
   ```bash
   docker compose exec nomad cat /opt/cni/config/my-network.conflist
   ```

4. Ensure the plugin binary is correctly installed:
   ```bash
   docker compose exec nomad ls -l /opt/cni/bin/outbound
   ```

5. Check the CNI plugin logs:
   ```bash
   docker compose exec nomad cat /var/log/cni/outbound.log
   ```

6. Use the network troubleshooting commands listed in the previous section to gather more detailed information about the network configuration.

Remember to rebuild the Docker image and restart the environment after making changes to the plugin or configuration:

```bash
make down all
```

This development environment allows you to iterate quickly on the CNI Outbound Plugin, testing its functionality within a Nomad setup.