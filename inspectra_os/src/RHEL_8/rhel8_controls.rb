# Security controls for RHEL8

# 1. Ensure /tmp is configured
control 'rhel8-ensure-tmp-configured' do
  impact 1.0
  title 'Ensure /tmp is configured'
  desc 'The /tmp directory should be configured with appropriate mount options.'
  describe mount('/tmp') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
    its('options') { should include 'nosuid' }
    its('options') { should include 'noexec' }
  end
end

# 2. Disable the rhnsd Daemon
control 'rhel8-disable-rhnsd-daemon' do
  impact 1.0
  title 'Disable the rhnsd Daemon'
  desc 'The rhnsd daemon should be disabled to prevent unnecessary services.'
  describe service('rhnsd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 3. Ensure core dumps are restricted
control 'rhel8-restrict-core-dumps' do
  impact 1.0
  title 'Ensure core dumps are restricted'
  desc 'Core dumps should be restricted to prevent sensitive information leakage.'
  describe file('/etc/security/limits.conf') do
    its('content') { should match /hard core 0/ }
  end
end

# 4. Ensure HTTP server is not enabled
control 'rhel8-disable-http-server' do
  impact 1.0
  title 'Ensure HTTP server is not enabled'
  desc 'The HTTP server should be disabled unless explicitly required.'
  describe service('httpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 5. Ensure NFS is not enabled
control 'rhel8-disable-nfs' do
  impact 1.0
  title 'Ensure NFS is not enabled'
  desc 'The NFS service should be disabled unless explicitly required.'
  describe service('nfs') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 6. Ensure LDAP server is not enabled
control 'rhel8-disable-ldap-server' do
  impact 1.0
  title 'Ensure LDAP server is not enabled'
  desc 'The LDAP server should be disabled unless explicitly required.'
  describe service('ldap') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 7. Ensure RDS is disabled
control 'rhel8-disable-rds' do
  impact 1.0
  title 'Ensure RDS is disabled'
  desc 'The RDS kernel module should be disabled to prevent unnecessary functionality.'
  describe kernel_module('rds') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

# 8. Ensure remote rsyslog messages are only accepted on designated log hosts
control 'rhel8-remote-rsyslog-designated-hosts' do
  impact 1.0
  title 'Ensure remote rsyslog messages are only accepted on designated log hosts'
  desc 'Remote rsyslog messages should only be accepted on designated log hosts.'
  describe file('/etc/rsyslog.conf') do
    its('content') { should match /$ModLoad imtcp/ }
    its('content') { should match /$InputTCPServerRun/ }
  end
end

# 9. Ensure mounting of cramfs filesystems is disabled
control 'rhel8-ensure-cramfs-disabled' do
  impact 1.0
  title 'Ensure mounting of cramfs filesystems is disabled'
  desc 'The cramfs filesystem should not be mountable.'
  describe file('/etc/modprobe.d/cramfs.conf') do
    its('content') { should match(/^install cramfs /bin/true$/) }
  end
end

# 10. Ensure mounting of squashfs filesystems is disabled
control 'rhel8-ensure-squashfs-disabled' do
  impact 1.0
  title 'Ensure mounting of squashfs filesystems is disabled'
  desc 'The squashfs filesystem should not be mountable.'
  describe file('/etc/modprobe.d/squashfs.conf') do
    its('content') { should match(/^install squashfs /bin/true$/) }
  end
end

# 11. Ensure mounting of udf filesystems is disabled
control 'rhel8-ensure-udf-disabled' do
  impact 1.0
  title 'Ensure mounting of udf filesystems is disabled'
  desc 'The udf filesystem should not be mountable.'
  describe file('/etc/modprobe.d/udf.conf') do
    its('content') { should match(/^install udf /bin/true$/) }
  end
end

# 12. Ensure separate partition exists for /var
control 'rhel8-ensure-var-partition' do
  impact 1.0
  title 'Ensure separate partition exists for /var'
  desc 'The /var directory should be on a separate partition.'
  describe mount('/var') do
    it { should be_mounted }
  end
end

# 13. Ensure separate partition exists for /home
control 'rhel8-ensure-home-partition' do
  impact 1.0
  title 'Ensure separate partition exists for /home'
  desc 'The /home directory should be on a separate partition.'
  describe mount('/home') do
    it { should be_mounted }
  end
end

# 14. Ensure nodev option set on /dev/shm partition
control 'rhel8-ensure-devshm-nodev' do
  impact 1.0
  title 'Ensure nodev option set on /dev/shm partition'
  desc 'The nodev option should be set on the /dev/shm partition.'
  describe mount('/dev/shm') do
    its('options') { should include 'nodev' }
  end
end

# 15. Ensure nosuid option set on /dev/shm partition
control 'rhel8-ensure-devshm-nosuid' do
  impact 1.0
  title 'Ensure nosuid option set on /dev/shm partition'
  desc 'The nosuid option should be set on the /dev/shm partition.'
  describe mount('/dev/shm') do
    its('options') { should include 'nosuid' }
  end
end

# 16. Ensure noexec option set on /dev/shm partition
control 'rhel8-ensure-devshm-noexec' do
  impact 1.0
  title 'Ensure noexec option set on /dev/shm partition'
  desc 'The noexec option should be set on the /dev/shm partition.'
  describe mount('/dev/shm') do
    its('options') { should include 'noexec' }
  end
end

# 17. Ensure nodev option set on removable media partitions
control 'rhel8-ensure-removable-nodev' do
  impact 1.0
  title 'Ensure nodev option set on removable media partitions'
  desc 'The nodev option should be set on removable media partitions.'
  describe mount('/media') do
    its('options') { should include 'nodev' }
  end
end

# 18. Ensure nosuid option set on removable media partitions
control 'rhel8-ensure-removable-nosuid' do
  impact 1.0
  title 'Ensure nosuid option set on removable media partitions'
  desc 'The nosuid option should be set on removable media partitions.'
  describe mount('/media') do
    its('options') { should include 'nosuid' }
  end
end

# 19. Ensure noexec option set on removable media partitions
control 'rhel8-ensure-removable-noexec' do
  impact 1.0
  title 'Ensure noexec option set on removable media partitions'
  desc 'The noexec option should be set on removable media partitions.'
  describe mount('/media') do
    its('options') { should include 'noexec' }
  end
end

# 20. Ensure sticky bit is set on all world-writable directories
control 'rhel8-ensure-sticky-bit' do
  impact 1.0
  title 'Ensure sticky bit is set on all world-writable directories'
  desc 'The sticky bit should be set on all world-writable directories.'
  describe command('find / -type d -perm -0002 ! -perm -1000') do
    its('stdout') { should eq '' }
  end
end

# 21. Disable Automounting
control 'rhel8-disable-automounting' do
  impact 1.0
  title 'Disable Automounting'
  desc 'Automounting should be disabled to prevent unauthorized access to filesystems.'
  describe kernel_module('autofs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

# 22. Disable USB Storage
control 'rhel8-disable-usb-storage' do
  impact 1.0
  title 'Disable USB Storage'
  desc 'USB storage should be disabled to prevent unauthorized data transfer.'
  describe kernel_module('usb-storage') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

# 23. Ensure sudo is installed
control 'rhel8-ensure-sudo-installed' do
  impact 1.0
  title 'Ensure sudo is installed'
  desc 'The sudo package should be installed to manage administrative privileges.'
  describe package('sudo') do
    it { should be_installed }
  end
end

# 24. Ensure sudo commands use pty
control 'rhel8-ensure-sudo-pty' do
  impact 1.0
  title 'Ensure sudo commands use pty'
  desc 'Sudo commands should use a pseudo-terminal to improve security.'
  describe file('/etc/sudoers') do
    its('content') { should match /Defaults use_pty/ }
  end
end

# 25. Ensure sudo log file exists
control 'rhel8-ensure-sudo-log-file' do
  impact 1.0
  title 'Ensure sudo log file exists'
  desc 'A log file for sudo commands should exist to track administrative actions.'
  describe file('/var/log/sudo.log') do
    it { should exist }
  end
end

# 26. Ensure AIDE is installed
control 'rhel8-ensure-aide-installed' do
  impact 1.0
  title 'Ensure AIDE is installed'
  desc 'AIDE should be installed to monitor filesystem integrity.'
  describe package('aide') do
    it { should be_installed }
  end
end

# 27. Ensure filesystem integrity is regularly checked
control 'rhel8-ensure-filesystem-integrity' do
  impact 1.0
  title 'Ensure filesystem integrity is regularly checked'
  desc 'Filesystem integrity should be checked regularly to detect unauthorized changes.'
  describe cron do
    its('entries') { should include(match(/aide check/)) }
  end
end

# 28. Ensure permissions on bootloader config are configured
control 'rhel8-ensure-bootloader-permissions' do
  impact 1.0
  title 'Ensure permissions on bootloader config are configured'
  desc 'Permissions on the bootloader configuration file should be restricted.'
  describe file('/boot/grub2/grub.cfg') do
    its('mode') { should cmp '0600' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

# 29. Ensure address space layout randomization (ASLR) is enabled
control 'rhel8-ensure-aslr-enabled' do
  impact 1.0
  title 'Ensure address space layout randomization (ASLR) is enabled'
  desc 'ASLR should be enabled to prevent memory-based attacks.'
  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should eq 2 }
  end
end

# 30. Ensure SELinux is installed
control 'rhel8-ensure-selinux-installed' do
  impact 1.0
  title 'Ensure SELinux is installed'
  desc 'SELinux should be installed to enforce mandatory access controls.'
  describe package('selinux-policy') do
    it { should be_installed }
  end
end

# 31. Ensure SELinux policy is configured
control 'rhel8-ensure-selinux-policy' do
  impact 1.0
  title 'Ensure SELinux policy is configured'
  desc 'SELinux policy should be configured to enforce security policies.'
  describe file('/etc/selinux/config') do
    its('content') { should match /SELINUXTYPE=targeted/ }
  end
end

# 32. Ensure the SELinux state is permissive
control 'rhel8-ensure-selinux-permissive' do
  impact 1.0
  title 'Ensure the SELinux state is permissive'
  desc 'SELinux should be set to permissive mode for testing purposes.'
  describe file('/etc/selinux/config') do
    its('content') { should match /SELINUX=permissive/ }
  end
end

# 33. Ensure no unconfined services exist
control 'rhel8-ensure-no-unconfined-services' do
  impact 1.0
  title 'Ensure no unconfined services exist'
  desc 'Unconfined services should not exist to ensure SELinux policies are enforced.'
  describe command('ps -eZ | grep unconfined_service_t') do
    its('stdout') { should eq '' }
  end
end

# 34. Ensure SETroubleshoot is not installed
control 'rhel8-ensure-setroubleshoot-not-installed' do
  impact 1.0
  title 'Ensure SETroubleshoot is not installed'
  desc 'SETroubleshoot should not be installed to reduce unnecessary services.'
  describe package('setroubleshoot') do
    it { should_not be_installed }
  end
end

# 35. Ensure the MCS Translation Service (mcstrans) is not installed
control 'rhel8-ensure-mcstrans-not-installed' do
  impact 1.0
  title 'Ensure the MCS Translation Service (mcstrans) is not installed'
  desc 'The MCS Translation Service should not be installed to reduce unnecessary services.'
  describe package('mcstrans') do
    it { should_not be_installed }
  end
end

# 36. Ensure message of the day is configured properly
control 'rhel8-ensure-motd-configured' do
  impact 1.0
  title 'Ensure message of the day is configured properly'
  desc 'The message of the day should be configured to display security warnings.'
  describe file('/etc/motd') do
    its('content') { should match /Authorized use only/ }
  end
end

# 37. Ensure local login warning banner is configured properly
control 'rhel8-ensure-local-login-banner' do
  impact 1.0
  title 'Ensure local login warning banner is configured properly'
  desc 'The local login warning banner should be configured to display security warnings.'
  describe file('/etc/issue') do
    its('content') { should match /Authorized use only/ }
  end
end

# 38. Ensure remote login warning banner is configured properly
control 'rhel8-ensure-remote-login-banner' do
  impact 1.0
  title 'Ensure remote login warning banner is configured properly'
  desc 'The remote login warning banner should be configured to display security warnings.'
  describe file('/etc/issue.net') do
    its('content') { should match /Authorized use only/ }
  end
end

# 39. Ensure permissions on /etc/motd are configured
control 'rhel8-ensure-motd-permissions' do
  impact 1.0
  title 'Ensure permissions on /etc/motd are configured'
  desc 'Permissions on the /etc/motd file should be restricted.'
  describe file('/etc/motd') do
    its('mode') { should cmp '0644' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

# 40. Ensure permissions on /etc/issue are configured
control 'rhel8-ensure-issue-permissions' do
  impact 1.0
  title 'Ensure permissions on /etc/issue are configured'
  desc 'Permissions on the /etc/issue file should be restricted.'
  describe file('/etc/issue') do
    its('mode') { should cmp '0644' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

# 41. Ensure permissions on /etc/issue.net are configured
control 'rhel8-ensure-issue-net-permissions' do
  impact 1.0
  title 'Ensure permissions on /etc/issue.net are configured'
  desc 'Permissions on the /etc/issue.net file should be restricted.'
  describe file('/etc/issue.net') do
    its('mode') { should cmp '0644' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

# 42. Ensure GDM login banner is configured
control 'rhel8-ensure-gdm-login-banner' do
  impact 1.0
  title 'Ensure GDM login banner is configured'
  desc 'The GDM login banner should be configured to display security warnings.'
  describe file('/etc/dconf/db/gdm.d/01-banner-message') do
    its('content') { should match /Authorized use only/ }
  end
end

# 43. Ensure system-wide crypto policy is not legacy
control 'rhel8-ensure-crypto-policy' do
  impact 1.0
  title 'Ensure system-wide crypto policy is not legacy'
  desc 'The system-wide crypto policy should not be set to legacy.'
  describe command('update-crypto-policies --show') do
    its('stdout') { should_not match /LEGACY/ }
  end
end

# 44. Ensure xinetd is not installed
control 'rhel8-ensure-xinetd-not-installed' do
  impact 1.0
  title 'Ensure xinetd is not installed'
  desc 'The xinetd service should not be installed to reduce unnecessary services.'
  describe package('xinetd') do
    it { should_not be_installed }
  end
end

# 45. Ensure time synchronization is in use
control 'rhel8-ensure-time-synchronization' do
  impact 1.0
  title 'Ensure time synchronization is in use'
  desc 'Time synchronization should be in use to ensure accurate system time.'
  describe service('chronyd') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 46. Ensure X Window System is not installed
control 'rhel8-ensure-x-window-system-not-installed' do
  impact 1.0
  title 'Ensure X Window System is not installed'
  desc 'The X Window System should not be installed to reduce unnecessary services.'
  describe package('xorg-x11-server-common') do
    it { should_not be_installed }
  end
end

# 47. Ensure rsync service is not enabled
control 'rhel8-ensure-rsync-service-not-enabled' do
  impact 1.0
  title 'Ensure rsync service is not enabled'
  desc 'The rsync service should not be enabled to reduce unnecessary services.'
  describe service('rsync') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 48. Ensure Avahi Server is not enabled
control 'rhel8-ensure-avahi-server-not-enabled' do
  impact 1.0
  title 'Ensure Avahi Server is not enabled'
  desc 'The Avahi Server should not be enabled to reduce unnecessary services.'
  describe service('avahi-daemon') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 49. Ensure SNMP Server is not enabled
control 'rhel8-ensure-snmp-server-not-enabled' do
  impact 1.0
  title 'Ensure SNMP Server is not enabled'
  desc 'The SNMP Server should not be enabled to reduce unnecessary services.'
  describe service('snmpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 50. Ensure HTTP Proxy Server is not enabled
control 'rhel8-ensure-http-proxy-server-not-enabled' do
  impact 1.0
  title 'Ensure HTTP Proxy Server is not enabled'
  desc 'The HTTP Proxy Server should not be enabled to reduce unnecessary services.'
  describe service('squid') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 51. Ensure Samba is not enabled
control 'rhel8-ensure-samba-not-enabled' do
  impact 1.0
  title 'Ensure Samba is not enabled'
  desc 'The Samba service should not be enabled to reduce unnecessary services.'
  describe service('smb') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 52. Ensure IMAP and POP3 server is not enabled
control 'rhel8-ensure-imap-pop3-not-enabled' do
  impact 1.0
  title 'Ensure IMAP and POP3 server is not enabled'
  desc 'The IMAP and POP3 services should not be enabled to reduce unnecessary services.'
  describe service('dovecot') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 53. Ensure FTP Server is not enabled
control 'rhel8-ensure-ftp-server-not-enabled' do
  impact 1.0
  title 'Ensure FTP Server is not enabled'
  desc 'The FTP service should not be enabled to reduce unnecessary services.'
  describe service('vsftpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 54. Ensure DNS Server is not enabled
control 'rhel8-ensure-dns-server-not-enabled' do
  impact 1.0
  title 'Ensure DNS Server is not enabled'
  desc 'The DNS service should not be enabled to reduce unnecessary services.'
  describe service('named') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 55. Ensure RPC is not enabled
control 'rhel8-ensure-rpc-not-enabled' do
  impact 1.0
  title 'Ensure RPC is not enabled'
  desc 'The RPC service should not be enabled to reduce unnecessary services.'
  describe service('rpcbind') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 56. Ensure DHCP Server is not enabled
control 'rhel8-ensure-dhcp-server-not-enabled' do
  impact 1.0
  title 'Ensure DHCP Server is not enabled'
  desc 'The DHCP service should not be enabled to reduce unnecessary services.'
  describe service('dhcpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 57. Ensure CUPS is not enabled
control 'rhel8-ensure-cups-not-enabled' do
  impact 1.0
  title 'Ensure CUPS is not enabled'
  desc 'The CUPS service should not be enabled to reduce unnecessary services.'
  describe service('cups') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 58. Ensure NIS Server is not enabled
control 'rhel8-ensure-nis-server-not-enabled' do
  impact 1.0
  title 'Ensure NIS Server is not enabled'
  desc 'The NIS service should not be enabled to reduce unnecessary services.'
  describe service('ypserv') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 59. Ensure mail transfer agent is configured for local-only mode
control 'rhel8-ensure-mta-local-only' do
  impact 1.0
  title 'Ensure mail transfer agent is configured for local-only mode'
  desc 'The mail transfer agent should be configured to only accept local mail.'
  describe file('/etc/postfix/main.cf') do
    its('content') { should match /inet_interfaces = loopback-only/ }
  end
end

# 60. Ensure NIS Client is not installed
control 'rhel8-ensure-nis-client-not-installed' do
  impact 1.0
  title 'Ensure NIS Client is not installed'
  desc 'The NIS client should not be installed to reduce unnecessary services.'
  describe package('ypbind') do
    it { should_not be_installed }
  end
end

# 61. Ensure IP forwarding is disabled
control 'rhel8-ensure-ip-forwarding-disabled' do
  impact 1.0
  title 'Ensure IP forwarding is disabled'
  desc 'IP forwarding should be disabled to prevent unauthorized routing.'
  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should eq 0 }
  end
end

# 62. Ensure packet redirect sending is disabled
control 'rhel8-ensure-packet-redirect-disabled' do
  impact 1.0
  title 'Ensure packet redirect sending is disabled'
  desc 'Packet redirect sending should be disabled to prevent unauthorized routing.'
  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should eq 0 }
  end
end

# 63. Ensure source routed packets are not accepted
control 'rhel8-ensure-source-routed-packets-not-accepted' do
  impact 1.0
  title 'Ensure source routed packets are not accepted'
  desc 'Source routed packets should not be accepted to prevent spoofing.'
  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should eq 0 }
  end
end

# 64. Ensure ICMP redirects are not accepted
control 'rhel8-ensure-icmp-redirects-not-accepted' do
  impact 1.0
  title 'Ensure ICMP redirects are not accepted'
  desc 'ICMP redirects should not be accepted to prevent spoofing.'
  describe kernel_parameter('net.ipv4.conf.all.accept_redirects') do
    its('value') { should eq 0 }
  end
end

# 65. Ensure secure ICMP redirects are not accepted
control 'rhel8-ensure-secure-icmp-redirects-not-accepted' do
  impact 1.0
  title 'Ensure secure ICMP redirects are not accepted'
  desc 'Secure ICMP redirects should not be accepted to prevent spoofing.'
  describe kernel_parameter('net.ipv4.conf.all.secure_redirects') do
    its('value') { should eq 0 }
  end
end

# 66. Ensure suspicious packets are logged
control 'rhel8-ensure-suspicious-packets-logged' do
  impact 1.0
  title 'Ensure suspicious packets are logged'
  desc 'Suspicious packets should be logged to detect potential attacks.'
  describe kernel_parameter('net.ipv4.conf.all.log_martians') do
    its('value') { should eq 1 }
  end
end

# 67. Ensure broadcast ICMP requests are ignored
control 'rhel8-ensure-broadcast-icmp-requests-ignored' do
  impact 1.0
  title 'Ensure broadcast ICMP requests are ignored'
  desc 'Broadcast ICMP requests should be ignored to prevent amplification attacks.'
  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should eq 1 }
  end
end

# 68. Ensure bogus ICMP responses are ignored
control 'rhel8-ensure-bogus-icmp-responses-ignored' do
  impact 1.0
  title 'Ensure bogus ICMP responses are ignored'
  desc 'Bogus ICMP responses should be ignored to prevent spoofing.'
  describe kernel_parameter('net.ipv4.icmp_ignore_bogus_error_responses') do
    its('value') { should eq 1 }
  end
end

# 69. Ensure Reverse Path Filtering is enabled
control 'rhel8-ensure-reverse-path-filtering-enabled' do
  impact 1.0
  title 'Ensure Reverse Path Filtering is enabled'
  desc 'Reverse Path Filtering should be enabled to prevent spoofing.'
  describe kernel_parameter('net.ipv4.conf.all.rp_filter') do
    its('value') { should eq 1 }
  end
end

# 70. Ensure TCP SYN Cookies is enabled
control 'rhel8-ensure-tcp-syn-cookies-enabled' do
  impact 1.0
  title 'Ensure TCP SYN Cookies is enabled'
  desc 'TCP SYN Cookies should be enabled to prevent SYN flood attacks.'
  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should eq 1 }
  end
end

# 71. Ensure IPv6 router advertisements are not accepted
control 'rhel8-ensure-ipv6-router-advertisements-not-accepted' do
  impact 1.0
  title 'Ensure IPv6 router advertisements are not accepted'
  desc 'IPv6 router advertisements should not be accepted to prevent unauthorized routing.'
  describe kernel_parameter('net.ipv6.conf.all.accept_ra') do
    its('value') { should eq 0 }
  end
end

# 72. Ensure DCCP is disabled
control 'rhel8-ensure-dccp-disabled' do
  impact 1.0
  title 'Ensure DCCP is disabled'
  desc 'The DCCP protocol should be disabled to reduce unnecessary functionality.'
  describe kernel_module('dccp') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

# 73. Ensure SCTP is disabled
control 'rhel8-ensure-sctp-disabled' do
  impact 1.0
  title 'Ensure SCTP is disabled'
  desc 'The SCTP protocol should be disabled to reduce unnecessary functionality.'
  describe kernel_module('sctp') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

# 74. Ensure TIPC is disabled
control 'rhel8-ensure-tipc-disabled' do
  impact 1.0
  title 'Ensure TIPC is disabled'
  desc 'The TIPC protocol should be disabled to reduce unnecessary functionality.'
  describe kernel_module('tipc') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

# 75. Ensure a Firewall package is installed
control 'rhel8-ensure-firewall-package-installed' do
  impact 1.0
  title 'Ensure a Firewall package is installed'
  desc 'A firewall package should be installed to enforce network security.'
  describe package('firewalld') do
    it { should be_installed }
  end
end

# 76. Ensure firewalld service is enabled and running
control 'rhel8-ensure-firewalld-enabled-running' do
  impact 1.0
  title 'Ensure firewalld service is enabled and running'
  desc 'The firewalld service should be enabled and running to enforce network security.'
  describe service('firewalld') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 77. Ensure nftables is not enabled
control 'rhel8-ensure-nftables-not-enabled' do
  impact 1.0
  title 'Ensure nftables is not enabled'
  desc 'The nftables service should not be enabled to reduce unnecessary services.'
  describe service('nftables') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 78. Ensure auditd is installed
control 'rhel8-ensure-auditd-installed' do
  impact 1.0
  title 'Ensure auditd is installed'
  desc 'The auditd package should be installed to monitor system events.'
  describe package('audit') do
    it { should be_installed }
  end
end

# 79. Ensure auditd service is enabled
control 'rhel8-ensure-auditd-service-enabled' do
  impact 1.0
  title 'Ensure auditd service is enabled'
  desc 'The auditd service should be enabled to monitor system events.'
  describe service('auditd') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 80. Ensure auditing for processes that start prior to auditd is enabled
control 'rhel8-ensure-audit-prior-processes-enabled' do
  impact 1.0
  title 'Ensure auditing for processes that start prior to auditd is enabled'
  desc 'Auditing for processes that start prior to auditd should be enabled to monitor system events.'
  describe file('/etc/default/grub') do
    its('content') { should match /audit=1/ }
  end
end

# 81. Ensure audit_backlog_limit is sufficient
control 'rhel8-ensure-audit-backlog-limit-sufficient' do
  impact 1.0
  title 'Ensure audit_backlog_limit is sufficient'
  desc 'The audit_backlog_limit should be sufficient to prevent loss of audit records.'
  describe kernel_parameter('audit_backlog_limit') do
    its('value') { should cmp >= 8192 }
  end
end

# 82. Ensure audit log storage size is configured
control 'rhel8-ensure-audit-log-storage-configured' do
  impact 1.0
  title 'Ensure audit log storage size is configured'
  desc 'The audit log storage size should be configured to prevent loss of audit records.'
  describe file('/etc/audit/auditd.conf') do
    its('content') { should match /max_log_file = [0-9]+/ }
  end
end

# 83. Ensure changes to system administration scope (sudoers) is collected
control 'rhel8-ensure-sudoers-changes-collected' do
  impact 1.0
  title 'Ensure changes to system administration scope (sudoers) is collected'
  desc 'Changes to the sudoers file should be collected to monitor administrative actions.'
  describe auditd_rules do
    its('lines') { should include '-w /etc/sudoers -p wa -k scope' }
  end
end

# 84. Ensure login and logout events are collected
control 'rhel8-ensure-login-logout-events-collected' do
  impact 1.0
  title 'Ensure login and logout events are collected'
  desc 'Login and logout events should be collected to monitor user activity.'
  describe auditd_rules do
    its('lines') { should include '-w /var/log/wtmp -p wa -k logins' }
    its('lines') { should include '-w /var/log/btmp -p wa -k logins' }
  end
end

# 85. Ensure session initiation information is collected
control 'rhel8-ensure-session-initiation-collected' do
  impact 1.0
  title 'Ensure session initiation information is collected'
  desc 'Session initiation information should be collected to monitor user activity.'
  describe auditd_rules do
    its('lines') { should include '-w /var/run/utmp -p wa -k session' }
  end
end

# 86. Ensure events that modify date and time information are collected
control 'rhel8-ensure-date-time-modification-events-collected' do
  impact 1.0
  title 'Ensure events that modify date and time information are collected'
  desc 'Events that modify date and time information should be collected to monitor system changes.'
  describe auditd_rules do
    its('lines') { should include '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change' }
    its('lines') { should include '-a always,exit -F arch=b64 -S clock_settime -k time-change' }
  end
end

# 87. Ensure events that modify the system's Mandatory Access Controls are collected
control 'rhel8-ensure-mac-modification-events-collected' do
  impact 1.0
  title 'Ensure events that modify the system's Mandatory Access Controls are collected'
  desc 'Events that modify the system's Mandatory Access Controls should be collected to monitor security changes.'
  describe auditd_rules do
    its('lines') { should include '-w /etc/selinux/ -p wa -k MAC-policy' }
  end
end

# 88. Ensure events that modify the system's network environment are collected
control 'rhel8-ensure-network-modification-events-collected' do
  impact 1.0
  title 'Ensure events that modify the system's network environment are collected'
  desc 'Events that modify the system's network environment should be collected to monitor security changes.'
  describe auditd_rules do
    its('lines') { should include '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network-change' }
  end
end

# 89. Ensure discretionary access control permission modification events are collected
control 'rhel8-ensure-dac-modification-events-collected' do
  impact 1.0
  title 'Ensure discretionary access control permission modification events are collected'
  desc 'Discretionary access control permission modification events should be collected to monitor security changes.'
  describe auditd_rules do
    its('lines') { should include '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod' }
    its('lines') { should include '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -k perm_mod' }
    its('lines') { should include '-a always,exit -F arch=b64 -S lchown -k perm_mod' }
  end
end

# 90. Ensure unsuccessful unauthorized file access attempts are collected
control 'rhel8-ensure-unauthorized-file-access-attempts-collected' do
  impact 1.0
  title 'Ensure unsuccessful unauthorized file access attempts are collected'
  desc 'Unsuccessful unauthorized file access attempts should be collected to monitor security changes.'
  describe auditd_rules do
    its('lines') { should include '-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -F exit=-EPERM -k access' }
  end
end

# 91. Ensure events that modify user/group information are collected
control 'rhel8-ensure-user-group-modification-events-collected' do
  impact 1.0
  title 'Ensure events that modify user/group information are collected'
  desc 'Events that modify user/group information should be collected to monitor security changes.'
  describe auditd_rules do
    its('lines') { should include '-w /etc/passwd -p wa -k identity' }
    its('lines') { should include '-w /etc/group -p wa -k identity' }
    its('lines') { should include '-w /etc/shadow -p wa -k identity' }
    its('lines') { should include '-w /etc/gshadow -p wa -k identity' }
  end
end

# 92. Ensure successful file system mounts are collected
control 'rhel8-ensure-successful-mounts-collected' do
  impact 1.0
  title 'Ensure successful file system mounts are collected'
  desc 'Successful file system mounts should be collected to monitor security changes.'
  describe auditd_rules do
    its('lines') { should include '-a always,exit -F arch=b64 -S mount -k mounts' }
  end
end

# 93. Ensure use of privileged commands is collected
control 'rhel8-ensure-privileged-commands-collected' do
  impact 1.0
  title 'Ensure use of privileged commands is collected'
  desc 'Use of privileged commands should be collected to monitor administrative actions.'
  describe auditd_rules do
    its('lines') { should include '-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k privileged' }
  end
end

# 94. Ensure file deletion events by users are collected
control 'rhel8-ensure-file-deletion-events-collected' do
  impact 1.0
  title 'Ensure file deletion events by users are collected'
  desc 'File deletion events by users should be collected to monitor security changes.'
  describe auditd_rules do
    its('lines') { should include '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete' }
  end
end

# 95. Ensure kernel module loading and unloading is collected
control 'rhel8-ensure-kernel-module-events-collected' do
  impact 1.0
  title 'Ensure kernel module loading and unloading is collected'
  desc 'Kernel module loading and unloading events should be collected to monitor security changes.'
  describe auditd_rules do
    its('lines') { should include '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules' }
  end
end

# 96. Ensure system administrator actions (sudolog) are collected
control 'rhel8-ensure-sudolog-actions-collected' do
  impact 1.0
  title 'Ensure system administrator actions (sudolog) are collected'
  desc 'System administrator actions should be collected to monitor administrative actions.'
  describe auditd_rules do
    its('lines') { should include '-w /var/log/sudo.log -p wa -k actions' }
  end
end

# 97. Ensure the audit configuration is immutable
control 'rhel8-ensure-audit-configuration-immutable' do
  impact 1.0
  title 'Ensure the audit configuration is immutable'
  desc 'The audit configuration should be immutable to prevent unauthorized changes.'
  describe auditd_rules do
    its('lines') { should include '-e 2' }
  end
end

# 98. Ensure rsyslog is installed
control 'rhel8-ensure-rsyslog-installed' do
  impact 1.0
  title 'Ensure rsyslog is installed'
  desc 'The rsyslog package should be installed to manage system logs.'
  describe package('rsyslog') do
    it { should be_installed }
  end
end

# 99. Ensure rsyslog Service is enabled
control 'rhel8-ensure-rsyslog-service-enabled' do
  impact 1.0
  title 'Ensure rsyslog Service is enabled'
  desc 'The rsyslog service should be enabled to manage system logs.'
  describe service('rsyslog') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 100. Ensure rsyslog default file permissions configured
control 'rhel8-ensure-rsyslog-default-permissions-configured' do
  impact 1.0
  title 'Ensure rsyslog default file permissions configured'
  desc 'The rsyslog default file permissions should be configured to restrict access.'
  describe file('/etc/rsyslog.conf') do
    its('content') { should match /$FileCreateMode 0640/ }
  end
end

# 101. Ensure logging is configured
control 'rhel8-ensure-logging-configured' do
  title 'Ensure logging is configured'
  desc 'Verify that logging is properly configured on the system.'
  impact 1.0
  describe file('/var/log') do
    it { should exist }
    it { should be_directory }
  end
end

# 102. Ensure rsyslog is configured to send logs to a remote log host
control 'rhel8-ensure-rsyslog-remote-log-host' do
  title 'Ensure rsyslog is configured to send logs to a remote log host'
  desc 'Verify that rsyslog is configured to send logs to a remote log host.'
  impact 1.0
  describe file('/etc/rsyslog.conf') do
    its('content') { should match /\*\.\* @remote-log-host/ }
  end
end

# 103. Ensure journald is configured to send logs to rsyslog
control 'rhel8-ensure-journald-sends-logs-to-rsyslog' do
  title 'Ensure journald is configured to send logs to rsyslog'
  desc 'Verify that journald is configured to forward logs to rsyslog.'
  impact 1.0
  describe file('/etc/systemd/journald.conf') do
    its('content') { should match /ForwardToSyslog=yes/ }
  end
end

# 104. Ensure journald is configured to compress large log files
control 'rhel8-ensure-journald-compresses-large-log-files' do
  title 'Ensure journald is configured to compress large log files'
  desc 'Verify that journald is configured to compress large log files.'
  impact 1.0
  describe file('/etc/systemd/journald.conf') do
    its('content') { should match /Compress=yes/ }
  end
end

# 105. Ensure permissions on all logfiles are configured
control 'rhel8-ensure-logfile-permissions-configured' do
  title 'Ensure permissions on all logfiles are configured'
  desc 'Verify that permissions on all logfiles are properly configured.'
  impact 1.0
  describe command('find /var/log -type f -exec stat -c "%a %n" {} \;') do
    its('stdout') { should_not match /[0-7][0-7][0-7]/ }
  end
end

# 106. Ensure logrotate is configured
control 'rhel8-ensure-logrotate-configured' do
  title 'Ensure logrotate is configured'
  desc 'Verify that logrotate is properly configured on the system.'
  impact 1.0
  describe file('/etc/logrotate.conf') do
    it { should exist }
  end
end

# 107. Ensure cron daemon is enabled
control 'rhel8-ensure-cron-daemon-enabled' do
  title 'Ensure cron daemon is enabled'
  desc 'Verify that the cron daemon is enabled and running.'
  impact 1.0
  describe service('crond') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 108. Ensure permissions on /etc/crontab are configured
control 'rhel8-ensure-crontab-permissions-configured' do
  title 'Ensure permissions on /etc/crontab are configured'
  desc 'Verify that permissions on /etc/crontab are properly configured.'
  impact 1.0
  describe file('/etc/crontab') do
    its('mode') { should cmp '0644' }
  end
end

# 109. Ensure permissions on /etc/cron.hourly are configured
control 'rhel8-ensure-cron-hourly-permissions-configured' do
  title 'Ensure permissions on /etc/cron.hourly are configured'
  desc 'Verify that permissions on /etc/cron.hourly are properly configured.'
  impact 1.0
  describe file('/etc/cron.hourly') do
    its('mode') { should cmp '0755' }
  end
end

# 110. Ensure permissions on /etc/cron.daily are configured
control 'rhel8-ensure-cron-daily-permissions-configured' do
  title 'Ensure permissions on /etc/cron.daily are configured'
  desc 'Verify that permissions on /etc/cron.daily are properly configured.'
  impact 1.0
  describe file('/etc/cron.daily') do
    its('mode') { should cmp '0755' }
  end
end

# 111. Ensure permissions on /etc/cron.weekly are configured
control 'rhel8-ensure-cron-weekly-permissions-configured' do
  title 'Ensure permissions on /etc/cron.weekly are configured'
  desc 'Verify that permissions on /etc/cron.weekly are properly configured.'
  impact 1.0
  describe file('/etc/cron.weekly') do
    its('mode') { should cmp '0755' }
  end
end

# 112. Ensure permissions on /etc/cron.monthly are configured
control 'rhel8-ensure-cron-monthly-permissions-configured' do
  title 'Ensure permissions on /etc/cron.monthly are configured'
  desc 'Verify that permissions on /etc/cron.monthly are properly configured.'
  impact 1.0
  describe file('/etc/cron.monthly') do
    its('mode') { should cmp '0755' }
  end
end

# 113. Ensure permissions on /etc/cron.d are configured
control 'rhel8-ensure-cron-d-permissions-configured' do
  title 'Ensure permissions on /etc/cron.d are configured'
  desc 'Verify that permissions on /etc/cron.d are properly configured.'
  impact 1.0
  describe file('/etc/cron.d') do
    its('mode') { should cmp '0755' }
  end
end

# 114. Ensure at/cron is restricted to authorized users
control 'rhel8-ensure-at-cron-restricted' do
  title 'Ensure at/cron is restricted to authorized users'
  desc 'Verify that at/cron is restricted to authorized users.'
  impact 1.0
  describe file('/etc/cron.allow') do
    it { should exist }
  end
  describe file('/etc/cron.deny') do
    it { should_not exist }
  end
end

# 115. Ensure permissions on /etc/ssh/sshd_config are configured
control 'rhel8-ensure-sshd-config-permissions-configured' do
  title 'Ensure permissions on /etc/ssh/sshd_config are configured'
  desc 'Verify that permissions on /etc/ssh/sshd_config are properly configured.'
  impact 1.0
  describe file('/etc/ssh/sshd_config') do
    its('mode') { should cmp '0600' }
  end
end

# 116. Ensure permissions on SSH private host key files are configured
control 'rhel8-ensure-ssh-private-host-key-permissions-configured' do
  title 'Ensure permissions on SSH private host key files are configured'
  desc 'Verify that permissions on SSH private host key files are properly configured.'
  impact 1.0
  describe command('find /etc/ssh -type f -name "*key" -exec stat -c "%a %n" {} \;') do
    its('stdout') { should_not match /[0-7][0-7][0-7]/ }
  end
end

# 117. Ensure permissions on SSH public host key files are configured
control 'rhel8-ensure-ssh-public-host-key-permissions-configured' do
  title 'Ensure permissions on SSH public host key files are configured'
  desc 'Verify that permissions on SSH public host key files are properly configured.'
  impact 1.0
  describe command('find /etc/ssh -type f -name "*.pub" -exec stat -c "%a %n" {} \;') do
    its('stdout') { should_not match /[0-7][0-7][0-7]/ }
  end
end

# 118. Ensure SSH LogLevel is appropriate
control 'rhel8-ensure-ssh-loglevel-configured' do
  title 'Ensure SSH LogLevel is appropriate'
  desc 'Verify that SSH LogLevel is set to INFO or higher.'
  impact 1.0
  describe sshd_config do
    its('LogLevel') { should eq 'INFO' }
  end
end

# 119. Ensure SSH X11 forwarding is disabled
control 'rhel8-ensure-ssh-x11-forwarding-disabled' do
  title 'Ensure SSH X11 forwarding is disabled'
  desc 'Verify that SSH X11 forwarding is disabled.'
  impact 1.0
  describe sshd_config do
    its('X11Forwarding') { should eq 'no' }
  end
end

# 120. Ensure SSH MaxAuthTries is set to 4 or less
control 'rhel8-ensure-ssh-maxauthtries-configured' do
  title 'Ensure SSH MaxAuthTries is set to 4 or less'
  desc 'Verify that SSH MaxAuthTries is set to 4 or less.'
  impact 1.0
  describe sshd_config do
    its('MaxAuthTries') { should cmp <= 4 }
  end
end

# 121. Ensure SSH IgnoreRhosts is enabled
control 'rhel8-ensure-ssh-ignorerhosts-enabled' do
  title 'Ensure SSH IgnoreRhosts is enabled'
  desc 'Verify that SSH IgnoreRhosts is enabled.'
  impact 1.0
  describe sshd_config do
    its('IgnoreRhosts') { should eq 'yes' }
  end
end

# 122. Ensure SSH HostbasedAuthentication is disabled
control 'rhel8-ensure-ssh-hostbasedauthentication-disabled' do
  title 'Ensure SSH HostbasedAuthentication is disabled'
  desc 'Verify that SSH HostbasedAuthentication is disabled.'
  impact 1.0
  describe sshd_config do
    its('HostbasedAuthentication') { should eq 'no' }
  end
end

# 123. Ensure SSH PermitUserEnvironment is disabled
control 'rhel8-ensure-ssh-permituserenvironment-disabled' do
  title 'Ensure SSH PermitUserEnvironment is disabled'
  desc 'Verify that SSH PermitUserEnvironment is disabled.'
  impact 1.0
  describe sshd_config do
    its('PermitUserEnvironment') { should eq 'no' }
  end
end

# 124. Ensure SSH Idle Timeout Interval is configured
control 'rhel8-ensure-ssh-idle-timeout-interval-configured' do
  title 'Ensure SSH Idle Timeout Interval is configured'
  desc 'Verify that SSH Idle Timeout Interval is configured.'
  impact 1.0
  describe sshd_config do
    its('ClientAliveInterval') { should cmp <= 300 }
    its('ClientAliveCountMax') { should cmp <= 0 }
  end
end

# 125. Ensure SSH LoginGraceTime is set to one minute or less
control 'rhel8-ensure-ssh-logingracetime-configured' do
  title 'Ensure SSH LoginGraceTime is set to one minute or less'
  desc 'Verify that SSH LoginGraceTime is set to one minute or less.'
  impact 1.0
  describe sshd_config do
    its('LoginGraceTime') { should cmp <= 60 }
  end
end

# 126. Ensure SSH warning banner is configured
control 'rhel8-ensure-ssh-warning-banner-configured' do
  title 'Ensure SSH warning banner is configured'
  desc 'Verify that SSH warning banner is configured.'
  impact 1.0
  describe sshd_config do
    its('Banner') { should eq '/etc/issue.net' }
  end
end

# 127. Ensure SSH PAM is enabled
control 'rhel8-ensure-ssh-pam-enabled' do
  title 'Ensure SSH PAM is enabled'
  desc 'Verify that SSH PAM is enabled.'
  impact 1.0
  describe sshd_config do
    its('UsePAM') { should eq 'yes' }
  end
end

# 128. Ensure SSH AllowTcpForwarding is disabled
control 'rhel8-ensure-ssh-allowtcpforwarding-disabled' do
  title 'Ensure SSH AllowTcpForwarding is disabled'
  desc 'Verify that SSH AllowTcpForwarding is disabled.'
  impact 1.0
  describe sshd_config do
    its('AllowTcpForwarding') { should eq 'no' }
  end
end

# 129. Ensure SSH MaxStartups is configured
control 'rhel8-ensure-ssh-maxstartups-configured' do
  title 'Ensure SSH MaxStartups is configured'
  desc 'Verify that SSH MaxStartups is configured.'
  impact 1.0
  describe sshd_config do
    its('MaxStartups') { should cmp <= 10 }
  end
end

# 130. Ensure SSH MaxSessions is set to 4 or less
control 'rhel8-ensure-ssh-maxsessions-configured' do
  title 'Ensure SSH MaxSessions is set to 4 or less'
  desc 'Verify that SSH MaxSessions is set to 4 or less.'
  impact 1.0
  describe sshd_config do
    its('MaxSessions') { should cmp <= 4 }
  end
end

# 131. Ensure system-wide crypto policy is not over-ridden
control 'rhel8-ensure-system-wide-crypto-policy-not-overridden' do
  title 'Ensure system-wide crypto policy is not over-ridden'
  desc 'Verify that the system-wide crypto policy is not over-ridden.'
  impact 1.0
  describe file('/etc/crypto-policies/config') do
    its('content') { should_not match /LEGACY/ }
  end
end

# 132. Create custom authselect profile
control 'rhel8-create-custom-authselect-profile' do
  title 'Create custom authselect profile'
  desc 'Verify that a custom authselect profile is created.'
  impact 1.0
  describe command('authselect create-profile custom-profile') do
    its('exit_status') { should eq 0 }
  end
end

# 133. Select authselect profile
control 'rhel8-select-authselect-profile' do
  title 'Select authselect profile'
  desc 'Verify that the authselect profile is selected.'
  impact 1.0
  describe command('authselect select custom-profile') do
    its('exit_status') { should eq 0 }
  end
end

# 134. Ensure authselect includes with-faillock
control 'rhel8-ensure-authselect-includes-faillock' do
  title 'Ensure authselect includes with-faillock'
  desc 'Verify that authselect includes with-faillock.'
  impact 1.0
  describe command('authselect current | grep with-faillock') do
    its('stdout') { should match /with-faillock/ }
  end
end

# 135. Ensure password creation requirements are configured
control 'rhel8-ensure-password-creation-requirements-configured' do
  title 'Ensure password creation requirements are configured'
  desc 'Verify that password creation requirements are configured.'
  impact 1.0
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /minlen=14/ }
    its('content') { should match /dcredit=-1/ }
    its('content') { should match /ucredit=-1/ }
    its('content') { should match /ocredit=-1/ }
    its('content') { should match /lcredit=-1/ }
  end
end

# 136. Ensure lockout for failed password attempts is configured
control 'rhel8-ensure-lockout-for-failed-password-attempts-configured' do
  title 'Ensure lockout for failed password attempts is configured'
  desc 'Verify that lockout for failed password attempts is configured.'
  impact 1.0
  describe file('/etc/security/faillock.conf') do
    its('content') { should match /deny=5/ }
    its('content') { should match /unlock_time=900/ }
  end
end

# 137. Ensure password reuse is limited
control 'rhel8-ensure-password-reuse-limited' do
  title 'Ensure password reuse is limited'
  desc 'Verify that password reuse is limited.'
  impact 1.0
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /remember=5/ }
  end
end

# 138. Ensure password hashing algorithm is SHA-512
control 'rhel8-ensure-password-hashing-algorithm-sha512' do
  title 'Ensure password hashing algorithm is SHA-512'
  desc 'Verify that password hashing algorithm is SHA-512.'
  impact 1.0
  describe file('/etc/login.defs') do
    its('content') { should match /ENCRYPT_METHOD SHA512/ }
  end
end

# 139. Ensure password expiration is set to 45 days
control 'rhel8-ensure-password-expiration-set' do
  title 'Ensure password expiration is set to 45 days'
  desc 'Verify that password expiration is set to 45 days.'
  impact 1.0
  describe file('/etc/login.defs') do
    its('content') { should match /PASS_MAX_DAYS 45/ }
  end
end

# 140. Ensure password expiration warning days is 7 or more
control 'rhel8-ensure-password-expiration-warning-days-configured' do
  title 'Ensure password expiration warning days is 7 or more'
  desc 'Verify that password expiration warning days is 7 or more.'
  impact 1.0
  describe file('/etc/login.defs') do
    its('content') { should match /PASS_WARN_AGE 7/ }
  end
end

# 141. Ensure inactive password lock is 7 days or less
control 'rhel8-ensure-inactive-password-lock-configured' do
  title 'Ensure inactive password lock is 7 days or less'
  desc 'Verify that inactive password lock is configured to 7 days or less.'
  impact 1.0
  describe file('/etc/default/useradd') do
    its('content') { should match /INACTIVE=7/ }
  end
end

# 142. Ensure all users last password change date is in the past
control 'rhel8-ensure-last-password-change-date-in-past' do
  title 'Ensure all users last password change date is in the past'
  desc 'Verify that all users last password change date is in the past.'
  impact 1.0
  describe command('chage -l $(getent passwd | cut -d: -f1)') do
    its('stdout') { should_not match /never/ }
  end
end

# 143. Ensure system accounts are secured
control 'rhel8-ensure-system-accounts-secured' do
  title 'Ensure system accounts are secured'
  desc 'Verify that system accounts are secured.'
  impact 1.0
  describe passwd.where { uid < 1000 } do
    its('shells') { should_not include '/bin/bash' }
  end
end

# 144. Ensure default user shell timeout is set to 600 seconds
control 'rhel8-ensure-default-user-shell-timeout-configured' do
  title 'Ensure default user shell timeout is set to 600 seconds'
  desc 'Verify that default user shell timeout is set to 600 seconds.'
  impact 1.0
  describe file('/etc/profile') do
    its('content') { should match /TMOUT=600/ }
  end
end

# 145. Ensure default group for the root account is GID 0
control 'rhel8-ensure-default-group-for-root-account-configured' do
  title 'Ensure default group for the root account is GID 0'
  desc 'Verify that default group for the root account is GID 0.'
  impact 1.0
  describe passwd.where { user == 'root' } do
    its('gid') { should eq 0 }
  end
end

# 146. Ensure default user umask is 027 or more restrictive
control 'rhel8-ensure-default-user-umask-configured' do
  title 'Ensure default user umask is 027 or more restrictive'
  desc 'Verify that default user umask is configured to 027 or more restrictive.'
  impact 1.0
  describe file('/etc/profile') do
    its('content') { should match /umask 027/ }
  end
end

# 147. Ensure access to the su command is restricted
control 'rhel8-ensure-su-command-access-restricted' do
  title 'Ensure access to the su command is restricted'
  desc 'Verify that access to the su command is restricted.'
  impact 1.0
  describe file('/etc/pam.d/su') do
    its('content') { should match /auth required pam_wheel.so use_uid/ }
  end
end

# 148. Ensure permissions on /etc/passwd are configured
control 'rhel8-ensure-permissions-on-etc-passwd-configured' do
  title 'Ensure permissions on /etc/passwd are configured'
  desc 'Verify that permissions on /etc/passwd are configured.'
  impact 1.0
  describe file('/etc/passwd') do
    its('mode') { should cmp '0644' }
  end
end

# 149. Ensure permissions on /etc/shadow are configured
control 'rhel8-ensure-permissions-on-etc-shadow-configured' do
  title 'Ensure permissions on /etc/shadow are configured'
  desc 'Verify that permissions on /etc/shadow are configured.'
  impact 1.0
  describe file('/etc/shadow') do
    its('mode') { should cmp '0600' }
  end
end

# 150. Ensure permissions on /etc/group are configured
control 'rhel8-ensure-permissions-on-etc-group-configured' do
  title 'Ensure permissions on /etc/group are configured'
  desc 'Verify that permissions on /etc/group are configured.'
  impact 1.0
  describe file('/etc/group') do
    its('mode') { should cmp '0644' }
  end
end

# 151. Ensure permissions on /etc/gshadow are configured
control 'rhel8-ensure-permissions-on-etc-gshadow-configured' do
  title 'Ensure permissions on /etc/gshadow are configured'
  desc 'Verify that permissions on /etc/gshadow are configured.'
  impact 1.0
  describe file('/etc/gshadow') do
    its('mode') { should cmp '0600' }
  end
end

# 152. Ensure permissions on /etc/passwd- are configured
control 'rhel8-ensure-permissions-on-etc-passwd-dash-configured' do
  title 'Ensure permissions on /etc/passwd- are configured'
  desc 'Verify that permissions on /etc/passwd- are properly configured.'
  impact 1.0
  describe file('/etc/passwd-') do
    its('mode') { should cmp '0644' }
  end
end

# 153. Ensure permissions on /etc/shadow- are configured
control 'rhel8-ensure-permissions-on-etc-shadow-dash-configured' do
  title 'Ensure permissions on /etc/shadow- are configured'
  desc 'Verify that permissions on /etc/shadow- are properly configured.'
  impact 1.0
  describe file('/etc/shadow-') do
    its('mode') { should cmp '0600' }
  end
end

# 154. Ensure permissions on /etc/group- are configured
control 'rhel8-ensure-permissions-on-etc-group-dash-configured' do
  title 'Ensure permissions on /etc/group- are configured'
  desc 'Verify that permissions on /etc/group- are properly configured.'
  impact 1.0
  describe file('/etc/group-') do
    its('mode') { should cmp '0644' }
  end
end

# 155. Ensure permissions on /etc/gshadow- are configured
control 'rhel8-ensure-permissions-on-etc-gshadow-dash-configured' do
  title 'Ensure permissions on /etc/gshadow- are configured'
  desc 'Verify that permissions on /etc/gshadow- are properly configured.'
  impact 1.0
  describe file('/etc/gshadow-') do
    its('mode') { should cmp '0600' }
  end
end

# 156. Ensure no world writable files exist
control 'rhel8-ensure-no-world-writable-files-exist' do
  title 'Ensure no world writable files exist'
  desc 'Verify that no world writable files exist on the system.'
  impact 1.0
  describe command('find / -xdev -type f -perm -0002') do
    its('stdout') { should eq '' }
  end
end

# 157. Ensure no unowned files or directories exist
control 'rhel8-ensure-no-unowned-files-or-directories-exist' do
  title 'Ensure no unowned files or directories exist'
  desc 'Verify that no unowned files or directories exist on the system.'
  impact 1.0
  describe command('find / -xdev -nouser') do
    its('stdout') { should eq '' }
  end
end

# 158. Ensure no ungrouped files or directories exist
control 'rhel8-ensure-no-ungrouped-files-or-directories-exist' do
  title 'Ensure no ungrouped files or directories exist'
  desc 'Verify that no ungrouped files or directories exist on the system.'
  impact 1.0
  describe command('find / -xdev -nogroup') do
    its('stdout') { should eq '' }
  end
end

# 159. Audit SUID executables
control 'rhel8-audit-suid-executables' do
  title 'Audit SUID executables'
  desc 'Verify that SUID executables are audited.'
  impact 1.0
  describe command('find / -xdev -type f -perm -4000') do
    its('stdout') { should_not eq '' }
  end
end

# 160. Audit SGID executables
control 'rhel8-audit-sgid-executables' do
  title 'Audit SGID executables'
  desc 'Verify that SGID executables are audited.'
  impact 1.0
  describe command('find / -xdev -type f -perm -2000') do
    its('stdout') { should_not eq '' }
  end
end

# 161. Ensure password fields are not empty
control 'rhel8-ensure-password-fields-not-empty' do
  title 'Ensure password fields are not empty'
  desc 'Verify that password fields are not empty.'
  impact 1.0
  describe passwd do
    its('passwords') { should_not include '' }
  end
end

# 162. Ensure no legacy "+" entries exist in /etc/passwd
control 'rhel8-ensure-no-legacy-plus-entries-in-passwd' do
  title 'Ensure no legacy "+" entries exist in /etc/passwd'
  desc 'Verify that no legacy "+" entries exist in /etc/passwd.'
  impact 1.0
  describe file('/etc/passwd') do
    its('content') { should_not match /^\+/ }
  end
end

# 163. Ensure root PATH Integrity
control 'rhel8-ensure-root-path-integrity' do
  title 'Ensure root PATH Integrity'
  desc 'Verify that root PATH integrity is maintained.'
  impact 1.0
  describe command('echo $PATH') do
    its('stdout') { should_not match /\./ }
    its('stdout') { should_not match /:/ }
  end
end

# 164. Ensure no legacy "+" entries exist in /etc/shadow
control 'rhel8-ensure-no-legacy-plus-entries-in-shadow' do
  title 'Ensure no legacy "+" entries exist in /etc/shadow'
  desc 'Verify that no legacy "+" entries exist in /etc/shadow.'
  impact 1.0
  describe file('/etc/shadow') do
    its('content') { should_not match /^\+/ }
  end
end

# 165. Ensure no legacy "+" entries exist in /etc/group
control 'rhel8-ensure-no-legacy-plus-entries-in-group' do
  title 'Ensure no legacy "+" entries exist in /etc/group'
  desc 'Verify that no legacy "+" entries exist in /etc/group.'
  impact 1.0
  describe file('/etc/group') do
    its('content') { should_not match /^\+/ }
  end
end

# 166. Ensure root is the only UID 0 account
control 'rhel8-ensure-root-is-only-uid-0-account' do
  title 'Ensure root is the only UID 0 account'
  desc 'Verify that root is the only UID 0 account.'
  impact 1.0
  describe passwd.where { uid == 0 } do
    its('users') { should eq ['root'] }
  end
end

# 167. Ensure users home directories permissions are 750 or more restrictive
control 'rhel8-ensure-users-home-directories-permissions-configured' do
  title 'Ensure users home directories permissions are 750 or more restrictive'
  desc 'Verify that users home directories permissions are 750 or more restrictive.'
  impact 1.0
  describe command('find /home -type d -perm -022') do
    its('stdout') { should eq '' }
  end
end

# 168. Ensure users own their home directories
control 'rhel8-ensure-users-own-home-directories' do
  title 'Ensure users own their home directories'
  desc 'Verify that users own their home directories.'
  impact 1.0
  describe command('find /home -not -user $(basename $HOME)') do
    its('stdout') { should eq '' }
  end
end

# 169. Ensure users dot files are not group or world writable
control 'rhel8-ensure-users-dot-files-not-group-or-world-writable' do
  title 'Ensure users dot files are not group or world writable'
  desc 'Verify that users dot files are not group or world writable.'
  impact 1.0
  describe command('find /home -type f -name ".*" -perm -022') do
    its('stdout') { should eq '' }
  end
end

# 170. Ensure no users have .forward files
control 'rhel8-ensure-no-users-have-forward-files' do
  title 'Ensure no users have .forward files'
  desc 'Verify that no users have .forward files.'
  impact 1.0
  describe command('find /home -type f -name ".forward"') do
    its('stdout') { should eq '' }
  end
end

# 171. Ensure no users have .netrc files
control 'rhel8-ensure-no-users-have-netrc-files' do
  title 'Ensure no users have .netrc files'
  desc 'Verify that no users have .netrc files.'
  impact 1.0
  describe command('find /home -type f -name ".netrc"') do
    its('stdout') { should eq '' }
  end
end

# 172. Ensure users .netrc Files are not group or world accessible
control 'rhel8-ensure-netrc-files-not-group-or-world-accessible' do
  title 'Ensure users .netrc Files are not group or world accessible'
  desc 'Verify that users .netrc files are not group or world accessible.'
  impact 1.0
  describe command('find /home -type f -name ".netrc" -perm -022') do
    its('stdout') { should eq '' }
  end
end

# 173. Ensure no users have .rhosts files
control 'rhel8-ensure-no-users-have-rhosts-files' do
  title 'Ensure no users have .rhosts files'
  desc 'Verify that no users have .rhosts files.'
  impact 1.0
  describe command('find /home -type f -name ".rhosts"') do
    its('stdout') { should eq '' }
  end
end

# 174. Ensure all groups in /etc/passwd exist in /etc/group
control 'rhel8-ensure-all-groups-in-passwd-exist-in-group' do
  title 'Ensure all groups in /etc/passwd exist in /etc/group'
  desc 'Verify that all groups in /etc/passwd exist in /etc/group.'
  impact 1.0
  describe passwd do
    its('groups') { should be_subset_of group.groups }
  end
end

# 175. Ensure no duplicate UIDs exist
control 'rhel8-ensure-no-duplicate-uids-exist' do
  title 'Ensure no duplicate UIDs exist'
  desc 'Verify that no duplicate UIDs exist.'
  impact 1.0
  describe passwd do
    its('uids') { should be_unique }
  end
end

# 176. Ensure no duplicate GIDs exist
control 'rhel8-ensure-no-duplicate-gids-exist' do
  title 'Ensure no duplicate GIDs exist'
  desc 'Verify that no duplicate GIDs exist.'
  impact 1.0
  describe group do
    its('gids') { should be_unique }
  end
end

# 177. Ensure no duplicate user names exist
control 'rhel8-ensure-no-duplicate-user-names-exist' do
  title 'Ensure no duplicate user names exist'
  desc 'Verify that no duplicate user names exist.'
  impact 1.0
  describe passwd do
    its('users') { should be_unique }
  end
end

# 178. Ensure no duplicate group names exist
control 'rhel8-ensure-no-duplicate-group-names-exist' do
  title 'Ensure no duplicate group names exist'
  desc 'Verify that no duplicate group names exist.'
  impact 1.0
  describe group do
    its('groups') { should be_unique }
  end
end

# 179. Ensure shadow group is empty
control 'rhel8-ensure-shadow-group-empty' do
  title 'Ensure shadow group is empty'
  desc 'Verify that the shadow group is empty.'
  impact 1.0
  describe group.where { name == 'shadow' } do
    its('members') { should be_empty }
  end
end

# 180. Ensure all users home directories exist
control 'rhel8-ensure-all-users-home-directories-exist' do
  title 'Ensure all users home directories exist'
  desc 'Verify that all users home directories exist.'
  impact 1.0
  describe passwd do
    its('homes') { should all(exist) }
  end
end

# 181. Ensure nosuid option set on /home partition
control 'rhel8-ensure-nosuid-option-set-on-home-partition' do
  title 'Ensure nosuid option set on /home partition'
  desc 'Verify that nosuid option is set on /home partition.'
  impact 1.0
  describe mount('/home') do
    its('options') { should include 'nosuid' }
  end
end

# 182. Ensure usrquota option set on /home partition
control 'rhel8-ensure-usrquota-option-set-on-home-partition' do
  title 'Ensure usrquota option set on /home partition'
  desc 'Verify that usrquota option is set on /home partition.'
  impact 1.0
  describe mount('/home') do
    its('options') { should include 'usrquota' }
  end
end

# 183. Ensure grpquota option set on /home partition
control 'rhel8-ensure-grpquota-option-set-on-home-partition' do
  title 'Ensure grpquota option set on /home partition'
  desc 'Verify that grpquota option is set on /home partition.'
  impact 1.0
  describe mount('/home') do
    its('options') { should include 'grpquota' }
  end
end

# 184. Ensure authentication is required when booting into rescue mode
control 'rhel8-ensure-authentication-required-for-rescue-mode' do
  title 'Ensure authentication is required when booting into rescue mode'
  desc 'Verify that authentication is required when booting into rescue mode.'
  impact 1.0
  describe file('/etc/shadow') do
    its('content') { should match /root/ }
  end
end

# 185. Ensure automatic mounting of removable media is disabled
control 'rhel8-ensure-automatic-mounting-of-removable-media-disabled' do
  title 'Ensure automatic mounting of removable media is disabled'
  desc 'Verify that automatic mounting of removable media is disabled.'
  impact 1.0
  describe file('/etc/fstab') do
    its('content') { should_not match /auto/ }
  end
end

# 186. Ensure VSFTP Server is not installed
control 'rhel8-ensure-vsftp-server-not-installed' do
  title 'Ensure VSFTP Server is not installed'
  desc 'Verify that VSFTP Server is not installed.'
  impact 1.0
  describe package('vsftpd') do
    it { should_not be_installed }
  end
end

# 187. Ensure TFTP Server is not installed
control 'rhel8-ensure-tftp-server-not-installed' do
  title 'Ensure TFTP Server is not installed'
  desc 'Verify that TFTP Server is not installed.'
  impact 1.0
  describe package('tftp-server') do
    it { should_not be_installed }
  end
end

# 188. Ensure a web server is not installed
control 'rhel8-ensure-web-server-not-installed' do
  title 'Ensure a web server is not installed'
  desc 'Verify that a web server is not installed.'
  impact 1.0
  describe package('httpd') do
    it { should_not be_installed }
  end
end

# 189. Ensure talk client is not installed
control 'rhel8-ensure-talk-client-not-installed' do
  title 'Ensure talk client is not installed'
  desc 'Verify that talk client is not installed.'
  impact 1.0
  describe package('talk') do
    it { should_not be_installed }
  end
end

# 190. Ensure actions as another user are always logged
control 'rhel8-ensure-actions-as-another-user-logged' do
  title 'Ensure actions as another user are always logged'
  desc 'Verify that actions as another user are always logged.'
  impact 1.0
  describe file('/var/log/sudo.log') do
    it { should exist }
  end
end

# 191. Ensure successful and unsuccessful attempts to use the chcon command are recorded
control 'rhel8-ensure-chcon-command-attempts-recorded' do
  title 'Ensure successful and unsuccessful attempts to use the chcon command are recorded'
  desc 'Verify that successful and unsuccessful attempts to use the chcon command are recorded.'
  impact 1.0
  describe auditd do
    its('rules') { should include '-a always,exit -F arch=b64 -S chcon' }
  end
end

# 192. Ensure successful and unsuccessful attempts to use the setfacl command are recorded
control 'rhel8-ensure-setfacl-command-attempts-recorded' do
  title 'Ensure successful and unsuccessful attempts to use the setfacl command are recorded'
  desc 'Verify that successful and unsuccessful attempts to use the setfacl command are recorded.'
  impact 1.0
  describe auditd do
    its('rules') { should include '-a always,exit -F arch=b64 -S setfacl' }
  end
end

# 193. Ensure successful and unsuccessful attempts to use the chacl command are recorded
control 'rhel8-ensure-chacl-command-attempts-recorded' do
  title 'Ensure successful and unsuccessful attempts to use the chacl command are recorded'
  desc 'Verify that successful and unsuccessful attempts to use the chacl command are recorded.'
  impact 1.0
  describe auditd do
    its('rules') { should include '-a always,exit -F arch=b64 -S chacl' }
  end
end

# 194. Ensure successful and unsuccessful attempts to use the usermod command are recorded
control 'rhel8-ensure-usermod-command-attempts-recorded' do
  title 'Ensure successful and unsuccessful attempts to use the usermod command are recorded'
  desc 'Verify that successful and unsuccessful attempts to use the usermod command are recorded.'
  impact 1.0
  describe auditd do
    its('rules') { should include '-a always,exit -F arch=b64 -S usermod' }
  end
end

# 195. Ensure the running and on disk configuration is the same
control 'rhel8-ensure-running-and-on-disk-config-same' do
  title 'Ensure the running and on disk configuration is the same'
  desc 'Verify that the running and on disk configuration is the same.'
  impact 1.0
  describe command('diff /etc/sysctl.conf <(sysctl -a)') do
    its('stdout') { should eq '' }
  end
end

# 196. Ensure rsyslog is not configured to receive logs from a remote client
control 'rhel8-ensure-rsyslog-not-configured-to-receive-logs' do
  title 'Ensure rsyslog is not configured to receive logs from a remote client'
  desc 'Verify that rsyslog is not configured to receive logs from a remote client.'
  impact 1.0
  describe file('/etc/rsyslog.conf') do
    its('content') { should_not match /\*\.\* @/ }
  end
end

# 197. Ensure systemd-journal-remote is installed
control 'rhel8-ensure-systemd-journal-remote-installed' do
  title 'Ensure systemd-journal-remote is installed'
  desc 'Verify that systemd-journal-remote is installed.'
  impact 1.0
  describe package('systemd-journal-remote') do
    it { should be_installed }
  end
end

# 198. Ensure systemd-journal-remote is configured
control 'rhel8-ensure-systemd-journal-remote-configured' do
  title 'Ensure systemd-journal-remote is configured'
  desc 'Verify that systemd-journal-remote is configured.'
  impact 1.0
  describe file('/etc/systemd/journal-remote.conf') do
    it { should exist }
  end
end

# 199. Ensure systemd-journal-remote is enabled
control 'rhel8-ensure-systemd-journal-remote-enabled' do
  title 'Ensure systemd-journal-remote is enabled'
  desc 'Verify that systemd-journal-remote is enabled.'
  impact 1.0
  describe service('systemd-journal-remote') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 200. Ensure journald is not configured to receive logs from a remote client
control 'rhel8-ensure-journald-not-configured-to-receive-logs' do
  title 'Ensure journald is not configured to receive logs from a remote client'
  desc 'Verify that journald is not configured to receive logs from a remote client.'
  impact 1.0
  describe file('/etc/systemd/journald.conf') do
    its('content') { should_not match /ForwardToSyslog=yes/ }
  end
end

# 201. Ensure journald service is enabled
control 'rhel8-ensure-journald-service-enabled' do
  title 'Ensure journald service is enabled'
  desc 'Verify that journald service is enabled and running.'
  impact 1.0
  describe service('systemd-journald') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 202. Ensure journald is not sending logs to rsyslog
control 'rhel8-ensure-journald-not-sending-logs-to-rsyslog' do
  title 'Ensure journald is not configured to send logs to rsyslog'
  desc 'Verify that journald is not configured to send logs to rsyslog.'
  impact 1.0
  describe file('/etc/systemd/journald.conf') do
    its('content') { should_not match /ForwardToSyslog=yes/ }
  end
end

# 203. Ensure cron is restricted to authorized users
control 'rhel8-ensure-cron-restricted-to-authorized-users' do
  title 'Ensure cron is restricted to authorized users'
  desc 'Verify that cron is restricted to authorized users.'
  impact 1.0
  describe file('/etc/cron.allow') do
    it { should exist }
  end
  describe file('/etc/cron.deny') do
    it { should_not exist }
  end
end

# 204. Ensure at is restricted to authorized users
control 'rhel8-ensure-at-restricted-to-authorized-users' do
  title 'Ensure at is restricted to authorized users'
  desc 'Verify that at is restricted to authorized users.'
  impact 1.0
  describe file('/etc/at.allow') do
    it { should exist }
  end
  describe file('/etc/at.deny') do
    it { should_not exist }
  end
end

# 205. Ensure SSH PermitEmptyPasswords is disabled
control 'rhel8-ensure-ssh-permitemptypasswords-disabled' do
  title 'Ensure SSH PermitEmptyPasswords is disabled'
  desc 'Verify that SSH PermitEmptyPasswords is disabled.'
  impact 1.0
  describe sshd_config do
    its('PermitEmptyPasswords') { should eq 'no' }
  end
end

# 206. Ensure users must provide password for escalation
control 'rhel8-ensure-password-required-for-escalation' do
  title 'Ensure users must provide password for escalation'
  desc 'Verify that users must provide password for escalation.'
  impact 1.0
  describe file('/etc/sudoers') do
    its('content') { should_not match /NOPASSWD/ }
  end
end

# 207. Ensure re-authentication for privilege escalation is not disabled globally
control 'rhel8-ensure-reauthentication-not-disabled-globally' do
  title 'Ensure re-authentication for privilege escalation is not disabled globally'
  desc 'Verify that re-authentication for privilege escalation is not disabled globally.'
  impact 1.0
  describe file('/etc/sudoers') do
    its('content') { should_not match /!authenticate/ }
  end
end

# 208. Ensure sudo authentication timeout is configured correctly
control 'rhel8-ensure-sudo-authentication-timeout-configured' do
  title 'Ensure sudo authentication timeout is configured correctly'
  desc 'Verify that sudo authentication timeout is configured correctly.'
  impact 1.0
  describe file('/etc/sudoers') do
    its('content') { should match /timestamp_timeout=15/ }
  end
end

# 209. Ensure /tmp is a separate partition
control 'rhel8-ensure-tmp-separate-partition' do
  title 'Ensure /tmp is a separate partition'
  desc 'Verify that /tmp is a separate partition.'
  impact 1.0
  describe mount('/tmp') do
    it { should be_mounted }
    its('device') { should_not eq '/' }
  end
end

# 210. Ensure GNOME Display Manager is removed
control 'rhel8-ensure-gnome-display-manager-removed' do
  title 'Ensure GNOME Display Manager is removed'
  desc 'Verify that GNOME Display Manager is removed.'
  impact 1.0
  describe package('gdm') do
    it { should_not be_installed }
  end
end

# 211. Ensure last logged in user display is disabled
control 'rhel8-ensure-last-logged-in-user-display-disabled' do
  title 'Ensure last logged in user display is disabled'
  desc 'Verify that last logged in user display is disabled.'
  impact 1.0
  describe file('/etc/gdm/custom.conf') do
    its('content') { should match /LastLoggedInUser=false/ }
  end
end

# 212. Ensure XDMCP is not enabled
control 'rhel8-ensure-xdmcp-not-enabled' do
  title 'Ensure XDMCP is not enabled'
  desc 'Verify that XDMCP is not enabled.'
  impact 1.0
  describe file('/etc/gdm/custom.conf') do
    its('content') { should_not match /Enable=true/ }
  end
end

# 213. Ensure net-snmp is not installed
control 'rhel8-ensure-net-snmp-not-installed' do
  title 'Ensure net-snmp is not installed'
  desc 'Verify that net-snmp is not installed.'
  impact 1.0
  describe package('net-snmp') do
    it { should_not be_installed }
  end
end

# 214. Ensure telnet-server is not installed
control 'rhel8-ensure-telnet-server-not-installed' do
  title 'Ensure telnet-server is not installed'
  desc 'Verify that telnet-server is not installed.'
  impact 1.0
  describe package('telnet-server') do
    it { should_not be_installed }
  end
end

# 215. Ensure rsh client is not installed
control 'rhel8-ensure-rsh-client-not-installed' do
  title 'Ensure rsh client is not installed'
  desc 'Verify that rsh client is not installed.'
  impact 1.0
  describe package('rsh') do
    it { should_not be_installed }
  end
end

# 216. Ensure TFTP client is not installed
control 'rhel8-ensure-tftp-client-not-installed' do
  title 'Ensure TFTP client is not installed'
  desc 'Verify that TFTP client is not installed.'
  impact 1.0
  describe package('tftp') do
    it { should_not be_installed }
  end
end

# 217. Ensure nonessential services are removed or masked
control 'rhel8-ensure-nonessential-services-removed-or-masked' do
  title 'Ensure nonessential services are removed or masked'
  desc 'Verify that nonessential services are removed or masked.'
  impact 1.0
  describe command('systemctl list-unit-files | grep enabled') do
    its('stdout') { should eq '' }
  end
end

# 218. Verify if IPv6 is enabled on the system
control 'rhel8-verify-ipv6-enabled' do
  title 'Verify if IPv6 is enabled on the system'
  desc 'Verify if IPv6 is enabled on the system.'
  impact 1.0
  describe kernel_parameter('net.ipv6.conf.all.disable_ipv6') do
    its('value') { should eq 0 }
  end
end

# 219. Ensure firewalld is installed
control 'rhel8-ensure-firewalld-installed' do
  title 'Ensure firewalld is installed'
  desc 'Verify that firewalld is installed.'
  impact 1.0
  describe package('firewalld') do
    it { should be_installed }
  end
end

# 220. Ensure iptables-services not installed with firewalld
control 'rhel8-ensure-iptables-services-not-installed-with-firewalld' do
  title 'Ensure iptables-services not installed with firewalld'
  desc 'Verify that iptables-services is not installed with firewalld.'
  impact 1.0
  describe package('iptables-services') do
    it { should_not be_installed }
  end
end

# 221. Ensure nftables either not installed or masked with firewalld
control 'rhel8-ensure-nftables-not-installed-or-masked-with-firewalld' do
  title 'Ensure nftables either not installed or masked with firewalld'
  desc 'Verify that nftables is either not installed or masked with firewalld.'
  impact 1.0
  describe package('nftables') do
    it { should_not be_installed }
  end
end

# 222. Ensure journald log rotation is configured per site policy
control 'rhel8-ensure-journald-log-rotation-configured' do
  title 'Ensure journald log rotation is configured per site policy'
  desc 'Verify that journald log rotation is configured per site policy.'
  impact 1.0
  describe file('/etc/systemd/journald.conf') do
    its('content') { should match /SystemMaxUse=/ }
  end
end

# 223. Ensure journald default file permissions configured
control 'rhel8-ensure-journald-default-file-permissions-configured' do
  title 'Ensure journald default file permissions configured'
  desc 'Verify that journald default file permissions are configured.'
  impact 1.0
  describe file('/etc/systemd/journald.conf') do
    its('content') { should match /FilePermissions=0640/ }
  end
end

# 224. Ensure freevxfs kernel module is not available
control 'rhel8-ensure-freevxfs-kernel-module-not-available' do
  title 'Ensure freevxfs kernel module is not available'
  desc 'Verify that freevxfs kernel module is not available.'
  impact 1.0
  describe kernel_module('freevxfs') do
    it { should_not be_loaded }
  end
end

# 225. Ensure hfs kernel module is not available
control 'rhel8-ensure-hfs-kernel-module-not-available' do
  title 'Ensure hfs kernel module is not available'
  desc 'Verify that hfs kernel module is not available.'
  impact 1.0
  describe kernel_module('hfs') do
    it { should_not be_loaded }
  end
end

# 226. Ensure hfsplus kernel module is not available
control 'rhel8-ensure-hfsplus-kernel-module-not-available' do
  title 'Ensure hfsplus kernel module is not available'
  desc 'Verify that hfsplus kernel module is not available.'
  impact 1.0
  describe kernel_module('hfsplus') do
    it { should_not be_loaded }
  end
end

# 227. Ensure jffs2 kernel module is not available
control 'rhel8-ensure-jffs2-kernel-module-not-available' do
  title 'Ensure jffs2 kernel module is not available'
  desc 'Verify that jffs2 kernel module is not available.'
  impact 1.0
  describe kernel_module('jffs2') do
    it { should_not be_loaded }
  end
end

# 228. Ensure /dev/shm is a separate partition
control 'rhel8-ensure-devshm-separate-partition' do
  title 'Ensure /dev/shm is a separate partition'
  desc 'Verify that /dev/shm is a separate partition.'
  impact 1.0
  describe mount('/dev/shm') do
    it { should be_mounted }
    its('device') { should_not eq '/' }
  end
end

# 229. Ensure ptrace_scope is restricted
control 'rhel8-ensure-ptrace-scope-restricted' do
  title 'Ensure ptrace_scope is restricted'
  desc 'Verify that ptrace_scope is restricted.'
  impact 1.0
  describe kernel_parameter('kernel.yama.ptrace_scope') do
    its('value') { should eq 1 }
  end
end

# 230. Ensure system wide crypto policy is not set to legacy
control 'rhel8-ensure-system-wide-crypto-policy-not-legacy' do
  title 'Ensure system wide crypto policy is not set to legacy'
  desc 'Verify that system wide crypto policy is not set to legacy.'
  impact 1.0
  describe file('/etc/crypto-policies/config') do
    its('content') { should_not match /LEGACY/ }
  end
end

# 231. Ensure system wide crypto policy disables sha1 hash and signature support
control 'rhel8-ensure-system-wide-crypto-policy-disables-sha1' do
  title 'Ensure system wide crypto policy disables sha1 hash and signature support'
  desc 'Verify that system wide crypto policy disables sha1 hash and signature support.'
  impact 1.0
  describe file('/etc/crypto-policies/config') do
    its('content') { should_not match /SHA1/ }
  end
end

# 232. Ensure system wide crypto policy disables cbc for ssh
control 'rhel8-ensure-system-wide-crypto-policy-disables-cbc-for-ssh' do
  title 'Ensure system wide crypto policy disables cbc for ssh'
  desc 'Verify that system wide crypto policy disables cbc for ssh.'
  impact 1.0
  describe file('/etc/crypto-policies/config') do
    its('content') { should_not match /CBC/ }
  end
end

# 233. Ensure system wide crypto policy disables macs less than 128 bits
control 'rhel8-ensure-system-wide-crypto-policy-disables-macs-less-than-128-bits' do
  title 'Ensure system wide crypto policy disables macs less than 128 bits'
  desc 'Verify that system wide crypto policy disables macs less than 128 bits.'
  impact 1.0
  describe file('/etc/crypto-policies/config') do
    its('content') { should_not match /MACS128/ }
  end
end

# 234. Ensure GDM disableuser-list option is enabled
control 'rhel8-ensure-gdm-disableuser-list-enabled' do
  title 'Ensure GDM disableuser-list option is enabled'
  desc 'Verify that GDM disableuser-list option is enabled.'
  impact 1.0
  describe file('/etc/gdm/custom.conf') do
    its('content') { should match /disable-user-list=true/ }
  end
end

# 235. Ensure GDM screen locks when the user is idle
control 'rhel8-ensure-gdm-screen-locks-when-idle' do
  title 'Ensure GDM screen locks when the user is idle'
  desc 'Verify that GDM screen locks when the user is idle.'
  impact 1.0
  describe file('/etc/gdm/custom.conf') do
    its('content') { should match /idle-delay=300/ }
  end
end

# 236. Ensure GDM screen locks cannot be overridden
control 'rhel8-ensure-gdm-screen-locks-cannot-be-overridden' do
  title 'Ensure GDM screen locks cannot be overridden'
  desc 'Verify that GDM screen locks cannot be overridden.'
  impact 1.0
  describe file('/etc/gdm/custom.conf') do
    its('content') { should_not match /override-idle-delay/ }
  end
end

# 237. Ensure GDM automatic mounting of removable media is disabled
control 'rhel8-ensure-gdm-automatic-mounting-disabled' do
  title 'Ensure GDM automatic mounting of removable media is disabled'
  desc 'Verify that GDM automatic mounting of removable media is disabled.'
  impact 1.0
  describe file('/etc/gdm/custom.conf') do
    its('content') { should match /automount=false/ }
  end
end

# 238. Ensure GDM disabling automatic mounting of removable media is not overridden
control 'rhel8-ensure-gdm-disable-automatic-mounting-not-overridden' do
  title 'Ensure GDM disabling automatic mounting of removable media is not overridden'
  desc 'Verify that GDM disabling automatic mounting of removable media is not overridden.'
  impact 1.0
  describe file('/etc/gdm/custom.conf') do
    its('content') { should_not match /override-automount/ }
  end
end

# 239. Ensure GDM autorun-never is enabled
control 'rhel8-ensure-gdm-autorun-never-enabled' do
  title 'Ensure GDM autorun-never is enabled'
  desc 'Verify that GDM autorun-never is enabled.'
  impact 1.0
  describe file('/etc/gdm/custom.conf') do
    its('content') { should match /autorun-never=true/ }
  end
end

# 240. Ensure GDM autorun-never is not overridden
control 'rhel8-ensure-gdm-autorun-never-not-overridden' do
  title 'Ensure GDM autorun-never is not overridden'
  desc 'Verify that GDM autorun-never is not overridden.'
  impact 1.0
  describe file('/etc/gdm/custom.conf') do
    its('content') { should_not match /override-autorun-never/ }
  end
end

# 241. Ensure chrony is not run as the root user
control 'rhel8-ensure-chrony-not-run-as-root' do
  title 'Ensure chrony is not run as the root user'
  desc 'Verify that chrony is not run as the root user.'
  impact 1.0
  describe file('/etc/chrony/chrony.conf') do
    its('content') { should_not match /run_as_root/ }
  end
end

# 242. Ensure dnsmasq services are not in use
control 'rhel8-ensure-dnsmasq-services-not-in-use' do
  title 'Ensure dnsmasq services are not in use'
  desc 'Verify that dnsmasq services are not in use.'
  impact 1.0
  describe service('dnsmasq') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 243. Ensure message access server services are not in use
control 'rhel8-ensure-message-access-server-services-not-in-use' do
  title 'Ensure message access server services are not in use'
  desc 'Verify that message access server services are not in use.'
  impact 1.0
  describe service('dovecot') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 244. Ensure ftp client is not installed
control 'rhel8-ensure-ftp-client-not-installed' do
  title 'Ensure ftp client is not installed'
  desc 'Verify that ftp client is not installed.'
  impact 1.0
  describe package('ftp') do
    it { should_not be_installed }
  end
end

# 245. Ensure ldap client is not installed
control 'rhel8-ensure-ldap-client-not-installed' do
  title 'Ensure ldap client is not installed'
  desc 'Verify that ldap client is not installed.'
  impact 1.0
  describe package('openldap-clients') do
    it { should_not be_installed }
  end
end

# 246. Ensure bluetooth services are not in use
control 'rhel8-ensure-bluetooth-services-not-in-use' do
  title 'Ensure bluetooth services are not in use'
  desc 'Verify that bluetooth services are not in use.'
  impact 1.0
  describe service('bluetooth') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 247. Ensure tipc kernel module is not available
control 'rhel8-ensure-tipc-kernel-module-not-available' do
  title 'Ensure tipc kernel module is not available'
  desc 'Verify that tipc kernel module is not available.'
  impact 1.0
  describe kernel_module('tipc') do
    it { should_not be_loaded }
  end
end

# 248. Ensure rds kernel module is not available
control 'rhel8-ensure-rds-kernel-module-not-available' do
  title 'Ensure rds kernel module is not available'
  desc 'Verify that rds kernel module is not available.'
  impact 1.0
  describe kernel_module('rds') do
    it { should_not be_loaded }
  end
end

# 249. Ensure crontab is restricted to authorized users
control 'rhel8-ensure-crontab-restricted-to-authorized-users' do
  title 'Ensure crontab is restricted to authorized users'
  desc 'Verify that crontab is restricted to authorized users.'
  impact 1.0
  describe file('/etc/cron.allow') do
    it { should exist }
  end
  describe file('/etc/cron.deny') do
    it { should_not exist }
  end
end

# 250. Ensure sshdUsePAM is enabled
control 'rhel8-ensure-sshd-use-pam-enabled' do
  title 'Ensure sshdUsePAM is enabled'
  desc 'Verify that sshdUsePAM is enabled.'
  impact 1.0
  describe sshd_config do
    its('UsePAM') { should eq 'yes' }
  end
end

# 251. Ensure sshdcrypto_policy is not set
control 'rhel8-ensure-sshd-crypto-policy-not-set' do
  title 'Ensure sshdcrypto_policy is not set'
  desc 'Verify that sshdcrypto_policy is not set.'
  impact 1.0
  describe sshd_config do
    its('content') { should_not match /crypto_policy/ }
  end
end

# 252. Ensure latest version of pam is installed
control 'rhel8-ensure-latest-version-of-pam-installed' do
  title 'Ensure latest version of pam is installed'
  desc 'Verify that latest version of pam is installed.'
  impact 1.0
  describe package('pam') do
    it { should be_installed }
    its('version') { should cmp >= '1.3.1' }
  end
end

# 253. Ensure latest version of authselect is installed
control 'rhel8-ensure-latest-version-of-authselect-installed' do
  title 'Ensure latest version of authselect is installed'
  desc 'Verify that latest version of authselect is installed.'
  impact 1.0
  describe package('authselect') do
    it { should be_installed }
    its('version') { should cmp >= '1.2.2' }
  end
end

# 254. Ensure pam_faillock module is enabled
control 'rhel8-ensure-pam-faillock-module-enabled' do
  title 'Ensure pam_faillock module is enabled'
  desc 'Verify that pam_faillock module is enabled.'
  impact 1.0
  describe file('/etc/security/faillock.conf') do
    its('content') { should match /deny=5/ }
    its('content') { should match /unlock_time=900/ }
  end
end

# 255. Ensure pam_pwquality module is enabled
control 'rhel8-ensure-pam-pwquality-module-enabled' do
  title 'Ensure pam_pwquality module is enabled'
  desc 'Verify that pam_pwquality module is enabled.'
  impact 1.0
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /minlen=14/ }
    its('content') { should match /dcredit=-1/ }
    its('content') { should match /ucredit=-1/ }
    its('content') { should match /ocredit=-1/ }
    its('content') { should match /lcredit=-1/ }
  end
end

# 256. Ensure pam_pwhistory module is enabled
control 'rhel8-ensure-pam-pwhistory-module-enabled' do
  title 'Ensure pam_pwhistory module is enabled'
  desc 'Verify that pam_pwhistory module is enabled.'
  impact 1.0
  describe file('/etc/security/pwhistory.conf') do
    its('content') { should match /remember=5/ }
  end
end

# 257. Ensure pam_unix module is enabled
control 'rhel8-ensure-pam-unix-module-enabled' do
  title 'Ensure pam_unix module is enabled'
  desc 'Verify that pam_unix module is enabled.'
  impact 1.0
  describe file('/etc/pam.d/common-password') do
    its('content') { should match /pam_unix.so/ }
  end
end

# 258. Ensure password failed attempts lockout includes root account
control 'rhel8-ensure-password-failed-attempts-lockout-includes-root' do
  title 'Ensure password failed attempts lockout includes root account'
  desc 'Verify that password failed attempts lockout includes root account.'
  impact 1.0
  describe file('/etc/security/faillock.conf') do
    its('content') { should match /root/ }
  end
end

# 259. Ensure password number of changed characters is configured
control 'rhel8-ensure-password-number-of-changed-characters-configured' do
  title 'Ensure password number of changed characters is configured'
  desc 'Verify that password number of changed characters is configured.'
  impact 1.0
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /minclass=3/ }
  end
end

# 260. Ensure password complexity is configured
control 'rhel8-ensure-password-complexity-configured' do
  title 'Ensure password complexity is configured'
  desc 'Verify that password complexity is configured.'
  impact 1.0
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /minlen=14/ }
  end
end

# 261. Ensure password same consecutive characters is configured
control 'rhel8-ensure-password-same-consecutive-characters-configured' do
  title 'Ensure password same consecutive characters is configured'
  desc 'Verify that password same consecutive characters is configured.'
  impact 1.0
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /maxrepeat=3/ }
  end
end

# 262. Ensure password maximum sequential characters is configured
control 'rhel8-ensure-password-max-sequential-characters-configured' do
  title 'Ensure password maximum sequential characters is configured'
  desc 'Verify that password maximum sequential characters is configured.'
  impact 1.0
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /maxsequence=3/ }
  end
end

# 263. Ensure password dictionary check is enabled
control 'rhel8-ensure-password-dictionary-check-enabled' do
  title 'Ensure password dictionary check is enabled'
  desc 'Verify that password dictionary check is enabled.'
  impact 1.0
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /dictcheck=1/ }
  end
end

# 264. Ensure password quality is enforced for the root user
control 'rhel8-ensure-password-quality-enforced-for-root' do
  title 'Ensure password quality is enforced for the root user'
  desc 'Verify that password quality is enforced for the root user.'
  impact 1.0
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /rootcheck=1/ }
  end
end

# 265. Ensure password history remember is configured
control 'rhel8-ensure-password-history-remember-configured' do
  title 'Ensure password history remember is configured'
  desc 'Verify that password history remember is configured.'
  impact 1.0
  describe file('/etc/security/pwhistory.conf') do
    its('content') { should match /remember=5/ }
  end
end

# 266. Ensure password history is enforced for the root user
control 'rhel8-ensure-password-history-enforced-for-root' do
  title 'Ensure password history is enforced for the root user'
  desc 'Verify that password history is enforced for the root user.'
  impact 1.0
  describe file('/etc/security/pwhistory.conf') do
    its('content') { should match /rootremember=5/ }
  end
end

# 267. Ensure pam_pwhistory includes use_authtok
control 'rhel8-ensure-pam-pwhistory-includes-use-authtok' do
  title 'Ensure pam_pwhistory includes use_authtok'
  desc 'Verify that pam_pwhistory includes use_authtok.'
  impact 1.0
  describe file('/etc/pam.d/common-password') do
    its('content') { should match /use_authtok/ }
  end
end

# 268. Ensure pam_unix does not include nullok
control 'rhel8-ensure-pam-unix-does-not-include-nullok' do
  title 'Ensure pam_unix does not include nullok'
  desc 'Verify that pam_unix does not include nullok.'
  impact 1.0
  describe file('/etc/pam.d/common-password') do
    its('content') { should_not match /nullok/ }
  end
end

# 269. Ensure pam_unix does not include remember
control 'rhel8-ensure-pam-unix-does-not-include-remember' do
  title 'Ensure pam_unix does not include remember'
  desc 'Verify that pam_unix does not include remember.'
  impact 1.0
  describe file('/etc/pam.d/common-password') do
    its('content') { should_not match /remember/ }
  end
end

# 270. Ensure pam_unix includes a strong password hashing algorithm
control 'rhel8-ensure-pam-unix-includes-strong-password-hashing' do
  title 'Ensure pam_unix includes a strong password hashing algorithm'
  desc 'Verify that pam_unix includes a strong password hashing algorithm.'
  impact 1.0
  describe file('/etc/pam.d/common-password') do
    its('content') { should match /sha512/ }
  end
end

# 271. Ensure pam_unix includes use_authtok
control 'rhel8-ensure-pam-unix-includes-use-authtok' do
  title 'Ensure pam_unix includes use_authtok'
  desc 'Verify that pam_unix includes use_authtok.'
  impact 1.0
  describe file('/etc/pam.d/common-password') do
    its('content') { should match /use_authtok/ }
  end
end

# 272. Ensure strong password hashing algorithm is configured
control 'rhel8-ensure-strong-password-hashing-configured' do
  title 'Ensure strong password hashing algorithm is configured'
  desc 'Verify that strong password hashing algorithm is configured.'
  impact 1.0
  describe file('/etc/login.defs') do
    its('content') { should match /ENCRYPT_METHOD SHA512/ }
  end
end

# 273. Ensure root user umask is configured
control 'rhel8-ensure-root-user-umask-configured' do
  title 'Ensure root user umask is configured'
  desc 'Verify that root user umask is configured.'
  impact 1.0
  describe file('/etc/profile') do
    its('content') { should match /umask 027/ }
  end
end

# 274. Ensure root password is set
control 'rhel8-ensure-root-password-set' do
  title 'Ensure root password is set'
  desc 'Verify that root password is set.'
  impact 1.0
  describe passwd.where { user == 'root' } do
    its('passwords') { should_not include '' }
  end
end

# 275. Ensure nologin is not listed in /etc/shells
control 'rhel8-ensure-nologin-not-listed-in-etc-shells' do
  title 'Ensure nologin is not listed in /etc/shells'
  desc 'Verify that nologin is not listed in /etc/shells.'
  impact 1.0
  describe file('/etc/shells') do
    its('content') { should_not match /nologin/ }
  end
end

# 276. Ensure all logfiles have appropriate access
control 'rhel8-ensure-all-logfiles-have-appropriate-access' do
  title 'Ensure all logfiles have appropriate access configured'
  desc 'Verify that all logfiles have appropriate access configured.'
  impact 1.0
  describe command('find /var/log -type f -exec stat -c "%a %n" {} \;') do
    its('stdout') { should_not match /[0-7][0-7][0-7]/ }
  end
end

# 277. Ensure rsyslog not configured to receive logs
control 'rhel8-ensure-rsyslog-not-configured-to-receive-logs' do
  title 'Ensure rsyslog is not configured to receive logs from a remote client'
  desc 'Verify that rsyslog is not configured to receive logs from a remote client.'
  impact 1.0
  describe file('/etc/rsyslog.conf') do
    its('content') { should_not match /\*\.\* @/ }
  end
end

# 278. Ensure journald not configured to receive logs
control 'rhel8-ensure-journald-not-configured-to-receive-logs' do
  title 'Ensure journald is not configured to receive logs from a remote client'
  desc 'Verify that journald is not configured to receive logs from a remote client.'
  impact 1.0
  describe file('/etc/systemd/journald.conf') do
    its('content') { should_not match /ForwardToSyslog=yes/ }
  end
end

# 279. Ensure system warns when audit logs are low on space
control 'rhel8-ensure-system-warns-when-audit-logs-low-on-space' do
  title 'Ensure system warns when audit logs are low on space'
  desc 'Verify that system warns when audit logs are low on space.'
  impact 1.0
  describe file('/etc/audit/auditd.conf') do
    its('content') { should match /space_left_action = email/ }
  end
end

# 280. Ensure the audit log directory is 0750 or more restrictive
control 'rhel8-ensure-audit-log-directory-permissions-configured' do
  title 'Ensure the audit log directory is 0750 or more restrictive'
  desc 'Verify that the audit log directory is 0750 or more restrictive.'
  impact 1.0
  describe file('/var/log/audit') do
    its('mode') { should cmp '0750' }
  end
end

# 281. Ensure only authorized users own audit log files
control 'rhel8-ensure-authorized-users-own-audit-log-files' do
  title 'Ensure only authorized users own audit log files'
  desc 'Verify that only authorized users own audit log files.'
  impact 1.0
  describe file('/var/log/audit') do
    its('owner') { should eq 'root' }
  end
end

# 282. Ensure only authorized groups are assigned ownership of audit log files
control 'rhel8-ensure-authorized-groups-own-audit-log-files' do
  title 'Ensure only authorized groups are assigned ownership of audit log files'
  desc 'Verify that only authorized groups are assigned ownership of audit log files.'
  impact 1.0
  describe file('/var/log/audit') do
    its('group') { should eq 'root' }
  end
end

# 283. Ensure audit configuration files are 640 or more restrictive
control 'rhel8-ensure-audit-config-files-permissions-configured' do
  title 'Ensure audit configuration files are 640 or more restrictive'
  desc 'Verify that audit configuration files are 640 or more restrictive.'
  impact 1.0
  describe file('/etc/audit/auditd.conf') do
    its('mode') { should cmp '0640' }
  end
end

# 284. Ensure audit configuration files are owned by root
control 'rhel8-ensure-audit-config-files-owned-by-root' do
  title 'Ensure audit configuration files are owned by root'
  desc 'Verify that audit configuration files are owned by root.'
  impact 1.0
  describe file('/etc/audit/auditd.conf') do
    its('owner') { should eq 'root' }
  end
end

# 285. Ensure audit configuration files belong to group root
control 'rhel8-ensure-audit-config-files-group-root' do
  title 'Ensure audit configuration files belong to group root'
  desc 'Verify that audit configuration files belong to group root.'
  impact 1.0
  describe file('/etc/audit/auditd.conf') do
    its('group') { should eq 'root' }
  end
end

# 286. Ensure audit tools are 755 or more restrictive
control 'rhel8-ensure-audit-tools-permissions-configured' do
  title 'Ensure audit tools are 755 or more restrictive'
  desc 'Verify that audit tools are 755 or more restrictive.'
  impact 1.0
  describe file('/sbin/auditctl') do
    its('mode') { should cmp '0755' }
  end
end

# 287. Ensure audit tools are owned by root
control 'rhel8-ensure-audit-tools-owned-by-root' do
  title 'Ensure audit tools are owned by root'
  desc 'Verify that audit tools are owned by root.'
  impact 1.0
  describe file('/sbin/auditctl') do
    its('owner') { should eq 'root' }
  end
end

# 288. Ensure audit tools belong to group root
control 'rhel8-ensure-audit-tools-group-root' do
  title 'Ensure audit tools belong to group root'
  desc 'Verify that audit tools belong to group root.'
  impact 1.0
  describe file('/sbin/auditctl') do
    its('group') { should eq 'root' }
  end
end

# 289. Ensure cryptographic mechanisms are used to protect the integrity of audit tools
control 'rhel8-ensure-cryptographic-mechanisms-protect-audit-tools' do
  title 'Ensure cryptographic mechanisms are used to protect the integrity of audit tools'
  desc 'Verify that cryptographic mechanisms are used to protect the integrity of audit tools.'
  impact 1.0
  describe file('/sbin/auditctl') do
    its('content') { should match /integrity/ }
  end
end

# 290. Ensure permissions on /etc/opasswd are configured
control 'rhel8-ensure-permissions-on-etc-opasswd-configured' do
  title 'Ensure permissions on /etc/opasswd are configured'
  desc 'Verify that permissions on /etc/opasswd are configured.'
  impact 1.0
  describe file('/etc/opasswd') do
    its('mode') { should cmp '0640' }
  end
end

# 291. Ensure permissions on /etc/shells are configured
control 'rhel8-ensure-permissions-on-etc-shells-configured' do
  title 'Ensure permissions on /etc/shells are configured'
  desc 'Verify that permissions on /etc/shells are configured.'
  impact 1.0
  describe file('/etc/shells') do
    its('mode') { should cmp '0644' }
  end
end

# 292. Ensure world writable files and directories are secured
control 'rhel8-ensure-world-writable-files-secured' do
  title 'Ensure world writable files and directories are secured'
  desc 'Verify that world writable files and directories are secured.'
  impact 1.0
  describe command('find / -xdev -type f -perm -0002') do
    its('stdout') { should eq '' }
  end
end

# 293. Ensure accounts in /etc/passwd use shadowed passwords
control 'rhel8-ensure-shadowed-passwords-used' do
  title 'Ensure accounts in /etc/passwd use shadowed passwords'
  desc 'Verify that accounts in /etc/passwd use shadowed passwords.'
  impact 1.0
  describe file('/etc/passwd') do
    its('content') { should_not match /:x:/ }
  end
end

# 294. Ensure /etc/shadow password fields are not empty
control 'rhel8-ensure-shadow-password-fields-not-empty' do
  title 'Ensure /etc/shadow password fields are not empty'
  desc 'Verify that /etc/shadow password fields are not empty.'
  impact 1.0
  describe file('/etc/shadow') do
    its('content') { should_not match /:$/ }
  end
end

# 295. Ensure local interactive user home directories are configured
control 'rhel8-ensure-local-interactive-user-home-directories-configured' do
  title 'Ensure local interactive user home directories are configured'
  desc 'Verify that local interactive user home directories are configured.'
  impact 1.0
  describe command('find /home -type d -perm -022') do
    its('stdout') { should eq '' }
  end
end

# 296. Ensure default encryption scheme is not used for password storage
control 'rhel8-ensure-default-encryption-scheme-not-used' do
  title 'Ensure default encryption scheme is not used for password storage'
  desc 'Verify that default encryption scheme is not used for password storage.'
  impact 1.0
  describe file('/etc/login.defs') do
    its('content') { should_not match /ENCRYPT_METHOD DES/ }
  end
end

# 297. Ensure active User IDs which were not logged in for more than 90 days or never is to be disabled
control 'rhel8-ensure-inactive-user-ids-disabled' do
  title 'Ensure active User IDs which were not logged in for more than 90 days or never is to be disabled'
  desc 'Verify that active User IDs which were not logged in for more than 90 days or never is to be disabled.'
  impact 1.0
  describe command('lastlog | awk \'$NF > 90 {print $1}\'') do
    its('stdout') { should eq '' }
  end
end

# 298. Ensure Hidden files permissions is set to 640
control 'rhel8-ensure-hidden-files-permissions-configured' do
  title 'Ensure Hidden files permissions is set to 640'
  desc 'Verify that Hidden files permissions is set to 640.'
  impact 1.0
  describe command('find /home -type f -name ".*" -perm -022') do
    its('stdout') { should eq '' }
  end
end

# 299. Ensure no users to be part of wheel group
control 'rhel8-ensure-no-users-in-wheel-group' do
  title 'Ensure no users to be part of wheel group'
  desc 'Verify that no users to be part of wheel group.'
  impact 1.0
  describe group.where { name == 'wheel' } do
    its('members') { should be_empty }
  end
end

# 300. Ensure Users should not be added with full privileges in sudoers file.
control 'rhel8-ensure-no-full-privileges-in-sudoers' do
  title 'Ensure Users should not be added with full privileges in sudoers file.'
  desc 'Verify that Users should not be added with full privileges in sudoers file.'
  impact 1.0
  describe file('/etc/sudoers') do
    its('content') { should_not match /ALL=(ALL)/ }
  end
end

# 301. Ensure interactive login is disabled for default system accounts
control 'rhel8-ensure-interactive-login-disabled-for-system-accounts' do
  title 'Ensure interactive login is disabled for default system accounts'
  desc 'Verify that interactive login is disabled for default system accounts.'
  impact 1.0
  describe passwd.where { uid < 1000 } do
    its('shells') { should_not include '/bin/bash' }
  end
end

