# Dockerfile for InSpec project
FROM --platform=linux/amd64 ubuntu:22.04
LABEL maintainer="Chef Software, Inc. <docker@chef.io>"

# Define InSpec version and channel
ARG VERSION=5.22.3
ARG CHANNEL=stable

# Set environment variables
ENV PATH=/opt/inspec/bin:/opt/inspec/embedded/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Set locale to en_US.UTF-8
RUN apt-get update && \
    apt-get install -y locales && \
    locale-gen en_US.UTF-8 && \
    update-locale LANG=en_US.UTF-8 && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8

# Install InSpec
RUN apt-get update && \
    apt-get install -y wget rpm2cpio cpio && \
    wget "https://packages.chef.io/files/${CHANNEL}/inspec/${VERSION}/el/7/inspec-${VERSION}-1.el7.x86_64.rpm" -O /tmp/inspec.rpm && \
    rpm2cpio /tmp/inspec.rpm | cpio -idmv && \
    rm -rf /tmp/inspec.rpm

# Install additional tools
RUN apt-get install -y git

# Set up working directory
WORKDIR /app

# Copy configuration files and controls
COPY config/ /app/config/
COPY controls/ /app/controls/
COPY inspec.yml /app/

# Install Ruby and dependencies
RUN apt-get install -y ruby ruby-dev build-essential && \
    gem install inspec

# Define entrypoint and default command
ENTRYPOINT ["inspec"]
CMD ["exec", "/app", "--reporter", "json:/app/reports/scan_report.json"]

# Volume for sharing reports
VOLUME ["/app/reports"]
