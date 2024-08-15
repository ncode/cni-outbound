# Use Oracle Linux 9 as the base image
FROM oraclelinux:9

# Set environment variables
ENV NOMAD_VERSION=1.8.2
ENV CNI_PLUGINS_VERSION=v1.5.1
ENV ARCH=arm64

# Install necessary packages
RUN dnf update -y && \
    dnf install -y \
    curl \
    git \
    unzip \
    tcpdump \
    bind-utils \
    iproute \
    iputils \
    iptables \
    ipset \
    ca-certificates && \
    dnf clean all 

# Download and install Nomad for the appropriate architecture
RUN curl -fsSL https://releases.hashicorp.com/nomad/${NOMAD_VERSION}/nomad_${NOMAD_VERSION}_linux_${ARCH}.zip -o nomad.zip && \
    mkdir -p /etc/nomad /var/lib/nomad && \
    unzip nomad.zip && \
    rm nomad.zip && \
    mv nomad /usr/local/bin/nomad

# Download and install CNI plugins for the appropriate architecture
RUN mkdir -p /opt/cni/bin /opt/cni/config && \
    curl -L https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-${ARCH}-${CNI_PLUGINS_VERSION}.tgz | tar -C /opt/cni/bin -xz

# Create a basic CNI configuration
RUN mkdir -p /opt/cni/config
COPY entrypoint.sh /entrypoint.sh
COPY my-network.conflist /opt/cni/config/my-network.conflist
COPY outbound /opt/cni/bin/outbound
COPY config.hcl /etc/nomad/config.hcl

# Expose Nomad's default ports
EXPOSE 4646 4647 4648 4649

# Set the entrypoint to start Nomad in development mode
ENTRYPOINT ["/entrypoint.sh"]
