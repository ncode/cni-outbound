job "dig-job" {
  datacenters = ["dc1"]

  group "dig-group" {
    network {
      mode = "cni/my-network"
    }

    task "dig-task" {
      driver = "exec"

      config {
        command = "/usr/bin/dig"
        args    = ["martinez.io", "@8.8.8.8"]
      }
    }
  }
}
