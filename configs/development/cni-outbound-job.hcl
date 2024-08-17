job "dig-outbound-job" {
  datacenters = ["dc1"]

  group "dig-group" {
    network {
       port "nc" {
        static = 8080
      }
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

          # Define the port to listen on
          PORT=8080
          WEBROOT="/tmp/webroot"
          OUTPUTFILE="$WEBROOT/index.html"

          # Ensure WEBROOT exists
          mkdir -p $WEBROOT

          # Ensure OUTPUTFILE exists and has initial content
          echo "Initializing..." > $OUTPUTFILE

          # Start the busybox httpd server
          busybox httpd -f -p $PORT -h $WEBROOT &

          # Main loop for DNS lookups
          while true; do
              echo "Performing DNS lookup for google.com..."
              echo "against 8.8.8.8"
              dig +short google.com @8.8.8.8
              echo "against 8.8.4.4"
              dig +short google.com @8.8.4.4
              sleep 60  # Wait for 60 seconds before next lookup
          done > $OUTPUTFILE
        EOT
      }

      resources {
        cpu    = 100
        memory = 20
      }
    }
  }
}
