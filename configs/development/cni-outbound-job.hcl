job "dig-job" {
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

          # Create the HTTP response
          response="HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, World!"

          # Start the socat HTTP server in a subshell
          (
              while true; do
                  echo -e "$response" | socat TCP-LISTEN:$PORT,fork,reuseaddr -
              done
          ) &

          # Store the subshell PID
          busybox httpd -f -p $PORT -h "$TEMP_DIR" &

          # Main loop for DNS lookups
          while true; do
              echo "Performing DNS lookup for google.com..."
              echo "against 8.8.8.8"
              dig +short google.com @8.8.8.8
              echo "against 8.8.4.4"
              dig +short google.com @8.8.4.4
              sleep 60  # Wait for 60 seconds before next lookup
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
