job "dig-job" {
  datacenters = ["dc1"]

  group "dig-group" {
    network {
      mode = "cni/my-network"
    }

    task "dig-task" {
      driver = "exec"

      config {
        command = "/bin/bash"
        args    = ["-c", "/local/dig-loop.sh"]
      }

      template {
        destination = "local/dig-loop.sh"
        perms       = "755"
        data        = <<-EOT
          #!/bin/bash
          while true ; do
            dig martinez.io @8.8.8.8
            sleep 5
          done
        EOT
      }

      resources {
        cpu    = 100
        memory = 20
      }
    }
  }
}
