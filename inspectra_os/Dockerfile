# Use the official Ubuntu image
FROM ubuntu:22.04
LABEL maintainer="Chef Software, Inc. <docker@chef.io>"

# Define InSpec version and channel
ARG VERSION=5.22.3
ARG CHANNEL=stable

# Set locale and environment
ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8 \
    PATH=/opt/inspec/bin:$PATH

# Install dependencies
RUN apt-get update && \
    apt-get install -y locales wget git lsb-release && \
    locale-gen en_US.UTF-8 && \
    update-locale LANG=en_US.UTF-8 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install qemu for architecture emulation
RUN apt-get update && apt-get install -y qemu-user-static && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Download and install Chef Workstation with architecture emulation
RUN wget --no-check-certificate -O /tmp/chef-workstation.deb "https://packages.chef.io/files/stable/chef-workstation/0.4.2/ubuntu/18.04/chef-workstation_0.4.2-1_amd64.deb" && \
    dpkg --add-architecture amd64 && \
    apt-get update && \
    apt-get install -y /tmp/chef-workstation.deb && \
    rm -rf /tmp/chef-workstation.deb || { echo "❌ Failed to download or install Chef Workstation"; exit 1; }

# Add environment variables for dynamic paths
ENV TEST_DIR=/app/test
ENV SRC_DIR=/app/src

# Chainloop integration
RUN apt-get install -y chainloop-cli

# Set working directory
WORKDIR /app

# Copy project files
COPY test/ /app/test/
COPY src/ /app/src/

# Create reports directory
RUN mkdir -p /app/reports

# Add wrapper script
COPY run_all_profiles.sh /usr/local/bin/run_all_profiles.sh
RUN chmod +x /usr/local/bin/run_all_profiles.sh

# Volume for sharing reports- have to replace it with chainloop
VOLUME ["/app/reports"]

# Default command
ENTRYPOINT ["run_all_profiles.sh"]
