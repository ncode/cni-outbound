#!/bin/bash

systemd.unified_cgroup_hierarchy=0

# cgroup v2: enable nesting
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    # move the processes from the root group to the /init group,
    # otherwise writing subtree_control fails with EBUSY.
    # An error during moving non-existent process (i.e., "cat") is ignored.
    mkdir -p /sys/fs/cgroup/init
    xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || :
    # enable controllers
    sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
        > /sys/fs/cgroup/cgroup.subtree_control
fi

nomad agent -config=/etc/nomad
