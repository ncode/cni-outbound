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

