#!/bin/bash

# Detect the OS and run corresponding profiles
PROFILE_DIR="/app/src"
REPORT_DIR="/app/reports"

if [ -f "/etc/redhat-release" ]; then
  echo "Detected RHEL-based Linux"
  inspec exec "$PROFILE_DIR/RHEL_7/rhel7_controls.rb" --reporter json:"$REPORT_DIR/rhel7_report.json"
  inspec exec "$PROFILE_DIR/RHEL_8/rhel8_controls.rb" --reporter json:"$REPORT_DIR/rhel8_report.json"
elif [ -f "/etc/lsb-release" ]; then
  echo "Detected Ubuntu-based Linux"
  inspec exec "$PROFILE_DIR/ubuntu_linux/ubuntu_controls.rb" --reporter json:"$REPORT_DIR/ubuntu_report.json"
elif [[ "$(uname -s)" =~ CYGWIN*|MINGW32*|MSYS*|MINGW* ]]; then
  echo "Detected Windows"
  inspec exec "$PROFILE_DIR/windows_server_2016/win2016_controls.rb" --reporter json:"$REPORT_DIR/win2016_report.json"
  inspec exec "$PROFILE_DIR/windows_server_2019/win2019_controls.rb" --reporter json:"$REPORT_DIR/win2019_report.json"
  inspec exec "$PROFILE_DIR/windows_server_2022/win2022_controls.rb" --reporter json:"$REPORT_DIR/win2022_report.json"
else
  echo "Unsupported or unknown OS"
fi
