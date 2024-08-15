#!/bin/bash

echo 1 > /proc/sys/net/ipv4/ip_forward
nomad agent -config=/etc/nomad
