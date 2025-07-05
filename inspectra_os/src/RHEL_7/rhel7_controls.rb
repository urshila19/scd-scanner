# Security controls for RHEL7

# 1. Ensure mounting of cramfs filesystems is disabled
control 'rhel7-cramfs-disabled' do
  impact 1.0
  title 'Ensure mounting of cramfs filesystems is disabled'
  desc 'The cramfs filesystem should not be mountable.'
  describe file('/etc/modprobe.d/cramfs.conf') do
    its('content') { should match(/^install cramfs /bin/true$/) }
  end
end

# 2. Ensure mounting of freevxfs filesystems is disabled
control 'rhel7-freevxfs-disabled' do
  impact 1.0
  title 'Ensure mounting of freevxfs filesystems is disabled'
  desc 'The freevxfs filesystem should not be mountable.'
  describe file('/etc/modprobe.d/freevxfs.conf') do
    its('content') { should match(/^install freevxfs /bin/true$/) }
  end
end

# 3. Ensure mounting of jffs2 filesystems is disabled
control 'rhel7-jffs2-disabled' do
  impact 1.0
  title 'Ensure mounting of jffs2 filesystems is disabled'
  desc 'The jffs2 filesystem should not be mountable.'
  describe file('/etc/modprobe.d/jffs2.conf') do
    its('content') { should match(/^install jffs2 /bin/true$/) }
  end
end

# 4. Ensure mounting of hfs filesystems is disabled
control 'rhel7-hfs-disabled' do
  impact 1.0
  title 'Ensure mounting of hfs filesystems is disabled'
  desc 'The hfs filesystem should not be mountable.'
  describe file('/etc/modprobe.d/hfs.conf') do
    its('content') { should match(/^install hfs /bin/true$/) }
  end
end

# 5. Ensure mounting of hfsplus filesystems is disabled
control 'rhel7-hfsplus-disabled' do
  impact 1.0
  title 'Ensure mounting of hfsplus filesystems is disabled'
  desc 'The hfsplus filesystem should not be mountable.'
  describe file('/etc/modprobe.d/hfsplus.conf') do
    its('content') { should match(/^install hfsplus /bin/true$/) }
  end
end

# 6. Ensure mounting of squashfs filesystems is disabled
control 'rhel7-squashfs-disabled' do
  impact 1.0
  title 'Ensure mounting of squashfs filesystems is disabled'
  desc 'The squashfs filesystem should not be mountable.'
  describe file('/etc/modprobe.d/squashfs.conf') do
    its('content') { should match(/^install squashfs /bin/true$/) }
  end
end

# 7. Ensure mounting of udf filesystems is disabled
control 'rhel7-udf-disabled' do
  impact 1.0
  title 'Ensure mounting of udf filesystems is disabled'
  desc 'The udf filesystem should not be mountable.'
  describe file('/etc/modprobe.d/udf.conf') do
    its('content') { should match(/^install udf /bin/true$/) }
  end
end

# 8. Ensure separate partition exists for /tmp
control 'rhel7-tmp-partition-exists' do
  impact 1.0
  title 'Ensure separate partition exists for /tmp'
  desc 'The /tmp directory should have a separate partition.'
  describe mount('/tmp') do
    it { should be_mounted }
  end
end

# 9. Ensure separate partition exists for /var
control 'rhel7-var-partition-exists' do
  impact 1.0
  title 'Ensure separate partition exists for /var'
  desc 'The /var directory should have a separate partition.'
  describe mount('/var') do
    it { should be_mounted }
  end
end

# 10. Ensure sticky bit is set on all world-writable directories
control 'rhel7-sticky-bit-set' do
  impact 1.0
  title 'Ensure sticky bit is set on all world-writable directories'
  desc 'The sticky bit should be set on all world-writable directories.'
  describe command('find / -xdev -type d -perm -0002 -exec ls -ld {} \;') do
    its('stdout') { should match(/t/) }
  end
end

# 11. Disable Automounting
control 'rhel7-disable-automounting' do
  impact 1.0
  title 'Disable Automounting'
  desc 'Automounting should be disabled.'
  describe file('/etc/modprobe.d/automount.conf') do
    its('content') { should match(/^install autofs /bin/true$/) }
  end
end

# 12. Ensure separate partition exists for /home
control 'rhel7-home-partition-exists' do
  impact 1.0
  title 'Ensure separate partition exists for /home'
  desc 'The /home directory should have a separate partition.'
  describe mount('/home') do
    it { should be_mounted }
  end
end

# 13. Ensure nodev option set on /dev/shm partition
control 'rhel7-nodev-on-dev-shm' do
  impact 1.0
  title 'Ensure nodev option set on /dev/shm partition'
  desc 'The nodev option should be set on /dev/shm.'
  describe mount('/dev/shm') do
    its('options') { should include 'nodev' }
  end
end

# 14. Ensure nosuid option set on /dev/shm partition
control 'rhel7-nosuid-on-dev-shm' do
  impact 1.0
  title 'Ensure nosuid option set on /dev/shm partition'
  desc 'The nosuid option should be set on /dev/shm.'
  describe mount('/dev/shm') do
    its('options') { should include 'nosuid' }
  end
end

# 15. Ensure noexec option set on /dev/shm partition
control 'rhel7-noexec-on-dev-shm' do
  impact 1.0
  title 'Ensure noexec option set on /dev/shm partition'
  desc 'The noexec option should be set on /dev/shm.'
  describe mount('/dev/shm') do
    its('options') { should include 'noexec' }
  end
end

# 16. Ensure AIDE is installed
control 'rhel7-aide-installed' do
  impact 1.0
  title 'Ensure AIDE is installed'
  desc 'The AIDE package should be installed.'
  describe package('aide') do
    it { should be_installed }
  end
end

# 17. Ensure filesystem integrity is regularly checked
control 'rhel7-filesystem-integrity-check' do
  impact 1.0
  title 'Ensure filesystem integrity is regularly checked'
  desc 'Filesystem integrity should be checked regularly.'
  describe cron do
    its('entries') { should include '* * * * * /usr/sbin/aide --check' }
  end
end

# 18. Ensure permissions on bootloader config are configured
control 'rhel7-bootloader-permissions' do
  impact 1.0
  title 'Ensure permissions on bootloader config are configured'
  desc 'Permissions on bootloader config should be configured.'
  describe file('/boot/grub2/grub.cfg') do
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# 19. Ensure SELinux policy is configured
control 'rhel7-selinux-policy-configured' do
  impact 1.0
  title 'Ensure SELinux policy is configured'
  desc 'SELinux policy should be configured.'
  describe selinux do
    its('status') { should eq 'enabled' }
    its('mode') { should eq 'enforcing' }
  end
end

# 20. Ensure core dumps are restricted
control 'rhel7-core-dumps-restricted' do
  impact 1.0
  title 'Ensure core dumps are restricted'
  desc 'Core dumps should be restricted.'
  describe file('/etc/security/limits.conf') do
    its('content') { should match(/\* hard core 0/) }
  end
end

# 21. Ensure XD/NX support is enabled
control 'rhel7-xd-nx-enabled' do
  impact 1.0
  title 'Ensure XD/NX support is enabled'
  desc 'XD/NX support should be enabled.'
  describe kernel_parameter('noexec') do
    its('value') { should eq '1' }
  end
end

# 22. Ensure prelink is disabled
control 'rhel7-prelink-disabled' do
  impact 1.0
  title 'Ensure prelink is disabled'
  desc 'Prelink should be disabled.'
  describe package('prelink') do
    it { should_not be_installed }
  end
end

# 23. Ensure the SELinux state is enforcing
control 'rhel7-selinux-enforcing' do
  impact 1.0
  title 'Ensure the SELinux state is enforcing'
  desc 'SELinux state should be enforcing.'
  describe selinux do
    its('mode') { should eq 'enforcing' }
  end
end

# 24. Ensure permissions on /etc/motd are configured
control 'rhel7-permissions-etc-motd' do
  impact 1.0
  title 'Ensure permissions on /etc/motd are configured'
  desc 'Permissions on /etc/motd should be configured.'
  describe file('/etc/motd') do
    its('mode') { should cmp '0644' }
  end
end

# 25. Ensure permissions on /etc/issue are configured
control 'rhel7-permissions-etc-issue' do
  impact 1.0
  title 'Ensure permissions on /etc/issue are configured'
  desc 'Permissions on /etc/issue should be configured.'
  describe file('/etc/issue') do
    its('mode') { should cmp '0644' }
  end
end

# 26. Ensure permissions on /etc/issue.net are configured
control 'rhel7-permissions-etc-issue-net' do
  impact 1.0
  title 'Ensure permissions on /etc/issue.net are configured'
  desc 'Permissions on /etc/issue.net should be configured.'
  describe file('/etc/issue.net') do
    its('mode') { should cmp '0644' }
  end
end

# 27. Ensure ntp is configured
control 'rhel7-ntp-configured' do
  impact 1.0
  title 'Ensure ntp is configured'
  desc 'NTP should be configured.'
  describe file('/etc/ntp.conf') do
    its('content') { should match(/server/) }
  end
end

# 28. Ensure mail transfer agent is configured for local-only mode
control 'rhel7-mail-transfer-agent-local-only' do
  impact 1.0
  title 'Ensure mail transfer agent is configured for local-only mode'
  desc 'Mail transfer agent should be configured for local-only mode.'
  describe file('/etc/postfix/main.cf') do
    its('content') { should match(/inet_interfaces = loopback-only/) }
  end
end

# 29. Ensure NIS Client is not installed
control 'rhel7-nis-client-not-installed' do
  impact 1.0
  title 'Ensure NIS Client is not installed'
  desc 'NIS Client should not be installed.'
  describe package('ypbind') do
    it { should_not be_installed }
  end
end

# 30. Ensure rsh client is not installed
control 'rhel7-rsh-client-not-installed' do
  impact 1.0
  title 'Ensure rsh client is not installed'
  desc 'Rsh client should not be installed.'
  describe package('rsh') do
    it { should_not be_installed }
  end
end

# 31. Ensure talk client is not installed
control 'rhel7-talk-client-not-installed' do
  impact 1.0
  title 'Ensure talk client is not installed'
  desc 'Talk client should not be installed.'
  describe package('talk') do
    it { should_not be_installed }
  end
end

# 32. Ensure address space layout randomization (ASLR) is enabled
control 'rhel7-aslr-enabled' do
  impact 1.0
  title 'Ensure address space layout randomization (ASLR) is enabled'
  desc 'ASLR should be enabled.'
  describe kernel_parameter('randomize_va_space') do
    its('value') { should eq '2' }
  end
end

# 33. Ensure LDAP client is not installed
control 'rhel7-ldap-client-not-installed' do
  impact 1.0
  title 'Ensure LDAP client is not installed'
  desc 'LDAP client should not be installed.'
  describe package('openldap-clients') do
    it { should_not be_installed }
  end
end

# 34. Ensure SELinux is not disabled in bootloader configuration
control 'rhel7-selinux-not-disabled-bootloader' do
  impact 1.0
  title 'Ensure SELinux is not disabled in bootloader configuration'
  desc 'SELinux should not be disabled in bootloader configuration.'
  describe file('/etc/default/grub') do
    its('content') { should_not match(/selinux=0/) }
  end
end

# 35. Ensure IP forwarding is disabled
control 'rhel7-ip-forwarding-disabled' do
  impact 1.0
  title 'Ensure IP forwarding is disabled'
  desc 'IP forwarding should be disabled.'
  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should eq '0' }
  end
end

# 36. Ensure ICMP redirects are not accepted
control 'rhel7-icmp-redirects-not-accepted' do
  impact 1.0
  title 'Ensure ICMP redirects are not accepted'
  desc 'ICMP redirects should not be accepted.'
  describe kernel_parameter('net.ipv4.conf.all.accept_redirects') do
    its('value') { should eq '0' }
  end
end

# 37. Ensure secure ICMP redirects are not accepted
control 'rhel7-secure-icmp-redirects-not-accepted' do
  impact 1.0
  title 'Ensure secure ICMP redirects are not accepted'
  desc 'Secure ICMP redirects should not be accepted.'
  describe kernel_parameter('net.ipv4.conf.all.secure_redirects') do
    its('value') { should eq '0' }
  end
end

# 38. Ensure the MCS Translation Service (mcstrans) is not installed
control 'rhel7-mcstrans-not-installed' do
  impact 1.0
  title 'Ensure the MCS Translation Service (mcstrans) is not installed'
  desc 'The MCS Translation Service (mcstrans) should not be installed.'
  describe package('mcstrans') do
    it { should_not be_installed }
  end
end

# 39. Ensure broadcast ICMP requests are ignored
control 'rhel7-broadcast-icmp-requests-ignored' do
  impact 1.0
  title 'Ensure broadcast ICMP requests are ignored'
  desc 'Broadcast ICMP requests should be ignored.'
  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should eq '1' }
  end
end

# 40. Ensure SELinux is installed
control 'rhel7-selinux-installed' do
  impact 1.0
  title 'Ensure SELinux is installed'
  desc 'SELinux should be installed.'
  describe package('selinux-policy-targeted') do
    it { should be_installed }
  end
end

# 41. Ensure message of the day is configured properly
control 'rhel7-message-of-the-day-configured' do
  impact 1.0
  title 'Ensure message of the day is configured properly'
  desc 'Message of the day should be configured properly.'
  describe file('/etc/motd') do
    its('content') { should match(/Authorized use only/) }
  end
end

# 42. Ensure local login warning banner is configured properly
control 'rhel7-local-login-warning-banner-configured' do
  impact 1.0
  title 'Ensure local login warning banner is configured properly'
  desc 'Local login warning banner should be configured properly.'
  describe file('/etc/issue') do
    its('content') { should match(/Authorized use only/) }
  end
end

# 43. Ensure remote login warning banner is configured properly
control 'rhel7-remote-login-warning-banner-configured' do
  impact 1.0
  title 'Ensure remote login warning banner is configured properly'
  desc 'Remote login warning banner should be configured properly.'
  describe file('/etc/issue.net') do
    its('content') { should match(/Authorized use only/) }
  end
end

# 44. Ensure bogus ICMP responses are ignored
control 'rhel7-bogus-icmp-responses-ignored' do
  impact 1.0
  title 'Ensure bogus ICMP responses are ignored'
  desc 'Bogus ICMP responses should be ignored.'
  describe kernel_parameter('net.ipv4.icmp_ignore_bogus_error_responses') do
    its('value') { should eq '1' }
  end
end

# 45. Ensure Reverse Path Filtering is enabled
control 'rhel7-reverse-path-filtering-enabled' do
  impact 1.0
  title 'Ensure Reverse Path Filtering is enabled'
  desc 'Reverse Path Filtering should be enabled.'
  describe kernel_parameter('net.ipv4.conf.all.rp_filter') do
    its('value') { should eq '1' }
  end
end

# 46. Ensure TCP SYN Cookies is enabled
control 'rhel7-tcp-syn-cookies-enabled' do
  impact 1.0
  title 'Ensure TCP SYN Cookies is enabled'
  desc 'TCP SYN Cookies should be enabled.'
  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should eq '1' }
  end
end

# 47. Ensure GDM login banner is configured
control 'rhel7-gdm-login-banner-configured' do
  impact 1.0
  title 'Ensure GDM login banner is configured'
  desc 'GDM login banner should be configured.'
  describe file('/etc/gdm/custom.conf') do
    its('content') { should match(/banner-message-enable=true/) }
  end
end

# 48. Ensure IPv6 router advertisements are not accepted
control 'rhel7-ipv6-router-advertisements-not-accepted' do
  impact 1.0
  title 'Ensure IPv6 router advertisements are not accepted'
  desc 'IPv6 router advertisements should not be accepted.'
  describe kernel_parameter('net.ipv6.conf.all.accept_ra') do
    its('value') { should eq '0' }
  end
end

# 49. Ensure chargen services are not enabled
control 'rhel7-chargen-services-not-enabled' do
  impact 1.0
  title 'Ensure chargen services are not enabled'
  desc 'Chargen services should not be enabled.'
  describe service('chargen') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 50. Ensure daytime services are not enabled
control 'rhel7-daytime-services-not-enabled' do
  impact 1.0
  title 'Ensure daytime services are not enabled'
  desc 'Daytime services should not be enabled.'
  describe service('daytime') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 51. Ensure discard services are not enabled
control 'rhel7-discard-services-not-enabled' do
  impact 1.0
  title 'Ensure discard services are not enabled'
  desc 'Discard services should not be enabled.'
  describe service('discard') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 52. Ensure echo services are not enabled
control 'rhel7-echo-services-not-enabled' do
  impact 1.0
  title 'Ensure echo services are not enabled'
  desc 'Echo services should not be enabled.'
  describe service('echo') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 53. Ensure time services are not enabled
control 'rhel7-time-services-not-enabled' do
  impact 1.0
  title 'Ensure time services are not enabled'
  desc 'Time services should not be enabled.'
  describe service('time') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 54. Ensure tftp server is not enabled
control 'rhel7-tftp-server-not-enabled' do
  impact 1.0
  title 'Ensure tftp server is not enabled'
  desc 'TFTP server should not be enabled.'
  describe service('tftp') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 55. Ensure xinetd is not enabled
control 'rhel7-xinetd-not-enabled' do
  impact 1.0
  title 'Ensure xinetd is not enabled'
  desc 'Xinetd should not be enabled.'
  describe service('xinetd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 56. Ensure time synchronization is in use
control 'rhel7-time-synchronization-in-use' do
  impact 1.0
  title 'Ensure time synchronization is in use'
  desc 'Time synchronization should be in use.'
  describe service('chronyd') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 57. Ensure IPv6 is disabled
control 'rhel7-ipv6-disabled' do
  impact 1.0
  title 'Ensure IPv6 is disabled'
  desc 'IPv6 should be disabled.'
  describe kernel_parameter('net.ipv6.conf.all.disable_ipv6') do
    its('value') { should eq '1' }
  end
end

# 58. Ensure DCCP is disabled
control 'rhel7-dccp-disabled' do
  impact 1.0
  title 'Ensure DCCP is disabled'
  desc 'DCCP should be disabled.'
  describe file('/etc/modprobe.d/dccp.conf') do
    its('content') { should match(/^install dccp /bin/true$/) }
  end
end

# 59. Ensure X Window System is not installed
control 'rhel7-x-window-system-not-installed' do
  impact 1.0
  title 'Ensure X Window System is not installed'
  desc 'X Window System should not be installed.'
  describe package('xorg-x11-server-common') do
    it { should_not be_installed }
  end
end

# 60. Ensure Avahi Server is not enabled
control 'rhel7-avahi-server-not-enabled' do
  impact 1.0
  title 'Ensure Avahi Server is not enabled'
  desc 'Avahi Server should not be enabled.'
  describe service('avahi-daemon') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 61. Ensure CUPS is not enabled
control 'rhel7-cups-not-enabled' do
  impact 1.0
  title 'Ensure CUPS is not enabled'
  desc 'CUPS should not be enabled.'
  describe service('cups') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 62. Ensure DHCP Server is not enabled
control 'rhel7-dhcp-server-not-enabled' do
  impact 1.0
  title 'Ensure DHCP Server is not enabled'
  desc 'DHCP Server should not be enabled.'
  describe service('dhcpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 63. Ensure LDAP server is not enabled
control 'rhel7-ldap-server-not-enabled' do
  impact 1.0
  title 'Ensure LDAP server is not enabled'
  desc 'LDAP server should not be enabled.'
  describe service('slapd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 64. Ensure NFS and RPC are not enabled
control 'rhel7-nfs-rpc-not-enabled' do
  impact 1.0
  title 'Ensure NFS and RPC are not enabled'
  desc 'NFS and RPC should not be enabled.'
  describe service('nfs') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
  describe service('rpcbind') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 65. Ensure DNS Server is not enabled
control 'rhel7-dns-server-not-enabled' do
  impact 1.0
  title 'Ensure DNS Server is not enabled'
  desc 'DNS Server should not be enabled.'
  describe service('named') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 66. Ensure FTP Server is not enabled
control 'rhel7-ftp-server-not-enabled' do
  impact 1.0
  title 'Ensure FTP Server is not enabled'
  desc 'FTP Server should not be enabled.'
  describe service('vsftpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 67. Ensure HTTP server is not enabled
control 'rhel7-http-server-not-enabled' do
  impact 1.0
  title 'Ensure HTTP server is not enabled'
  desc 'HTTP server should not be enabled.'
  describe service('httpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 68. Ensure IMAP and POP3 server is not enabled
control 'rhel7-imap-pop3-server-not-enabled' do
  impact 1.0
  title 'Ensure IMAP and POP3 server is not enabled'
  desc 'IMAP and POP3 server should not be enabled.'
  describe service('dovecot') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 69. Ensure Samba is not enabled
control 'rhel7-samba-not-enabled' do
  impact 1.0
  title 'Ensure Samba is not enabled'
  desc 'Samba should not be enabled.'
  describe service('smb') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 70. Ensure HTTP Proxy Server is not enabled
control 'rhel7-http-proxy-server-not-enabled' do
  impact 1.0
  title 'Ensure HTTP Proxy Server is not enabled'
  desc 'HTTP Proxy Server should not be enabled.'
  describe service('squid') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 71. Ensure SNMP Server is not enabled
control 'rhel7-snmp-server-not-enabled' do
  impact 1.0
  title 'Ensure SNMP Server is not enabled'
  desc 'SNMP Server should not be enabled.'
  describe service('snmpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 72. Ensure SCTP is disabled
control 'rhel7-sctp-disabled' do
  impact 1.0
  title 'Ensure SCTP is disabled'
  desc 'SCTP should be disabled.'
  describe file('/etc/modprobe.d/sctp.conf') do
    its('content') { should match(/^install sctp /bin/true$/) }
  end
end

# 73. Ensure NIS Server is not enabled
control 'rhel7-nis-server-not-enabled' do
  impact 1.0
  title 'Ensure NIS Server is not enabled'
  desc 'NIS Server should not be enabled.'
  describe service('ypserv') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 74. Ensure rsh server is not enabled
control 'rhel7-rsh-server-not-enabled' do
  impact 1.0
  title 'Ensure rsh server is not enabled'
  desc 'Rsh server should not be enabled.'
  describe service('rsh') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 75. Ensure talk server is not enabled
control 'rhel7-talk-server-not-enabled' do
  impact 1.0
  title 'Ensure talk server is not enabled'
  desc 'Talk server should not be enabled.'
  describe service('talk') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 76. Ensure telnet server is not enabled
control 'rhel7-telnet-server-not-enabled' do
  impact 1.0
  title 'Ensure telnet server is not enabled'
  desc 'Telnet server should not be enabled.'
  describe service('telnet') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 77. Ensure rsync service is not enabled
control 'rhel7-rsync-service-not-enabled' do
  impact 1.0
  title 'Ensure rsync service is not enabled'
  desc 'Rsync service should not be enabled.'
  describe service('rsync') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 78. Ensure unsuccessful unauthorized file access attempts are collected
control 'rhel7-unauthorized-file-access-attempts-collected' do
  impact 1.0
  title 'Ensure unsuccessful unauthorized file access attempts are collected'
  desc 'Unsuccessful unauthorized file access attempts should be collected.'
  describe auditd do
    its('lines') { should include '-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access' }
    its('lines') { should include '-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access' }
  end
end

# 79. Ensure use of privileged commands is collected
control 'rhel7-privileged-commands-collected' do
  impact 1.0
  title 'Ensure use of privileged commands is collected'
  desc 'Use of privileged commands should be collected.'
  describe auditd do
    its('lines') { should include '-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged' }
  end
end

# 80. Ensure kernel module loading and unloading is collected
control 'rhel7-kernel-module-loading-unloading-collected' do
  impact 1.0
  title 'Ensure kernel module loading and unloading is collected'
  desc 'Kernel module loading and unloading should be collected.'
  describe auditd do
    its('lines') { should include '-a always,exit -F arch=b64 -S init_module,delete_module -F auid>=1000 -F auid!=4294967295 -k modules' }
  end
end

# 81. Ensure rsyslog default file permissions configured
control 'rhel7-rsyslog-default-file-permissions-configured' do
  impact 1.0
  title 'Ensure rsyslog default file permissions configured'
  desc 'Rsyslog default file permissions should be configured.'
  describe file('/etc/rsyslog.conf') do
    its('content') { should match(/^\$FileCreateMode 0640$/) }
  end
end

# 82. Ensure remote rsyslog messages are only accepted on designated log hosts
control 'rhel7-remote-rsyslog-messages-designated-log-hosts' do
  impact 1.0
  title 'Ensure remote rsyslog messages are only accepted on designated log hosts'
  desc 'Remote rsyslog messages should only be accepted on designated log hosts.'
  describe file('/etc/rsyslog.conf') do
    its('content') { should match(/^\$ModLoad imtcp$/) }
    its('content') { should match(/^\$InputTCPServerRun 514$/) }
  end
end

# 83. Ensure permissions on all logfiles are configured
control 'rhel7-permissions-on-logfiles-configured' do
  impact 1.0
  title 'Ensure permissions on all logfiles are configured'
  desc 'Permissions on all logfiles should be configured.'
  describe command('find /var/log -type f -exec ls -l {} \;') do
    its('stdout') { should match(/^-rw-------/) }
  end
end

# 84. Ensure packet redirect sending is disabled
control 'rhel7-packet-redirect-sending-disabled' do
  impact 1.0
  title 'Ensure packet redirect sending is disabled'
  desc 'Packet redirect sending should be disabled.'
  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should eq '0' }
  end
end

# 85. Ensure source routed packets are not accepted
control 'rhel7-source-routed-packets-not-accepted' do
  impact 1.0
  title 'Ensure source routed packets are not accepted'
  desc 'Source routed packets should not be accepted.'
  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should eq '0' }
  end
end

# 86. Ensure at/cron is restricted to authorized users
control 'rhel7-at-cron-restricted-to-authorized-users' do
  impact 1.0
  title 'Ensure at/cron is restricted to authorized users'
  desc 'At/cron should be restricted to authorized users.'
  describe file('/etc/cron.allow') do
    it { should exist }
  end
  describe file('/etc/cron.deny') do
    it { should_not exist }
  end
end

# 87. Ensure SSH X11 forwarding is disabled
control 'rhel7-ssh-x11-forwarding-disabled' do
  impact 1.0
  title 'Ensure SSH X11 forwarding is disabled'
  desc 'SSH X11 forwarding should be disabled.'
  describe sshd_config do
    its('X11Forwarding') { should eq 'no' }
  end
end

# 88. Ensure suspicious packets are logged
control 'rhel7-suspicious-packets-logged' do
  impact 1.0
  title 'Ensure suspicious packets are logged'
  desc 'Suspicious packets should be logged.'
  describe kernel_parameter('net.ipv4.conf.all.log_martians') do
    its('value') { should eq '1' }
  end
end

# 89. Ensure SSH MaxAuthTries is set to 4 or less
control 'rhel7-ssh-maxauthtries-set' do
  impact 1.0
  title 'Ensure SSH MaxAuthTries is set to 4 or less'
  desc 'SSH MaxAuthTries should be set to 4 or less.'
  describe sshd_config do
    its('MaxAuthTries') { should cmp <= 4 }
  end
end

# 90. Ensure SSH IgnoreRhosts is enabled
control 'rhel7-ssh-ignorerhosts-enabled' do
  impact 1.0
  title 'Ensure SSH IgnoreRhosts is enabled'
  desc 'SSH IgnoreRhosts should be enabled.'
  describe sshd_config do
    its('IgnoreRhosts') { should eq 'yes' }
  end
end

# 91. Ensure SSH HostbasedAuthentication is disabled
control 'rhel7-ssh-hostbasedauthentication-disabled' do
  impact 1.0
  title 'Ensure SSH HostbasedAuthentication is disabled'
  desc 'SSH HostbasedAuthentication should be disabled.'
  describe sshd_config do
    its('HostbasedAuthentication') { should eq 'no' }
  end
end

# 92. Ensure SETroubleshoot is not installed
control 'rhel7-setroubleshoot-not-installed' do
  impact 1.0
  title 'Ensure SETroubleshoot is not installed'
  desc 'SETroubleshoot should not be installed.'
  describe package('setroubleshoot') do
    it { should_not be_installed }
  end
end

# 93. Ensure SSH PermitEmptyPasswords is disabled
control 'rhel7-ssh-permitempty-passwords-disabled' do
  impact 1.0
  title 'Ensure SSH PermitEmptyPasswords is disabled'
  desc 'SSH PermitEmptyPasswords should be disabled.'
  describe sshd_config do
    its('PermitEmptyPasswords') { should eq 'no' }
  end
end

# 94. Ensure IPv6 redirects are not accepted
control 'rhel7-ipv6-redirects-not-accepted' do
  impact 1.0
  title 'Ensure IPv6 redirects are not accepted'
  desc 'IPv6 redirects should not be accepted.'
  describe kernel_parameter('net.ipv6.conf.all.accept_redirects') do
    its('value') { should eq '0' }
  end
end

# 95. Ensure SSH PermitUserEnvironment is disabled
control 'rhel7-ssh-permituserenvironment-disabled' do
  impact 1.0
  title 'Ensure SSH PermitUserEnvironment is disabled'
  desc 'SSH PermitUserEnvironment should be disabled.'
  describe sshd_config do
    its('PermitUserEnvironment') { should eq 'no' }
  end
end

# 96. Ensure TCP Wrappers is installed
control 'rhel7-tcp-wrappers-installed' do
  impact 1.0
  title 'Ensure TCP Wrappers is installed'
  desc 'TCP Wrappers should be installed.'
  describe package('tcp_wrappers') do
    it { should be_installed }
  end
end

# 97. Ensure SSH Idle Timeout Interval is configured
control 'rhel7-ssh-idle-timeout-interval-configured' do
  impact 1.0
  title 'Ensure SSH Idle Timeout Interval is configured'
  desc 'SSH Idle Timeout Interval should be configured.'
  describe sshd_config do
    its('ClientAliveInterval') { should cmp <= 300 }
    its('ClientAliveCountMax') { should cmp <= 3 }
  end
end

# 98. Ensure SSH LoginGraceTime is set to one minute or less
control 'rhel7-ssh-logingracetime-set' do
  impact 1.0
  title 'Ensure SSH LoginGraceTime is set to one minute or less'
  desc 'SSH LoginGraceTime should be set to one minute or less.'
  describe sshd_config do
    its('LoginGraceTime') { should cmp <= 60 }
  end
end

# 99. Ensure permissions on /etc/hosts.allow are configured
control 'rhel7-permissions-hosts-allow-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/hosts.allow are configured'
  desc 'Permissions on /etc/hosts.allow should be configured.'
  describe file('/etc/hosts.allow') do
    its('mode') { should cmp '0644' }
  end
end

# 100. Ensure permissions on /etc/hosts.deny are configured
control 'rhel7-permissions-hosts-deny-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/hosts.deny are configured'
  desc 'Permissions on /etc/hosts.deny should be configured.'
  describe file('/etc/hosts.deny') do
    its('mode') { should cmp '0644' }
  end
end

# 101. Ensure SSH warning banner is configured
control 'rhel7-ssh-warning-banner-configured' do
  impact 1.0
  title 'Ensure SSH warning banner is configured'
  desc 'SSH warning banner should be configured.'
  describe sshd_config do
    its('Banner') { should eq '/etc/issue.net' }
  end
end

# 102. Ensure RDS is disabled
control 'rhel7-rds-disabled' do
  impact 1.0
  title 'Ensure RDS is disabled'
  desc 'RDS should be disabled.'
  describe file('/etc/modprobe.d/rds.conf') do
    its('content') { should match(/^install rds /bin/true$/) }
  end
end

# 103. Ensure TIPC is disabled
control 'rhel7-tipc-disabled' do
  impact 1.0
  title 'Ensure TIPC is disabled'
  desc 'TIPC should be disabled.'
  describe file('/etc/modprobe.d/tipc.conf') do
    its('content') { should match(/^install tipc /bin/true$/) }
  end
end

# 104. Ensure password creation requirements are configured
control 'rhel7-password-creation-requirements-configured' do
  impact 1.0
  title 'Ensure password creation requirements are configured'
  desc 'Password creation requirements should be configured.'
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match(/^minlen = 14$/) }
    its('content') { should match(/^dcredit = -1$/) }
    its('content') { should match(/^ucredit = -1$/) }
    its('content') { should match(/^ocredit = -1$/) }
    its('content') { should match(/^lcredit = -1$/) }
  end
end

# 105. Ensure lockout for failed password attempts is configured
control 'rhel7-lockout-for-failed-password-attempts-configured' do
  impact 1.0
  title 'Ensure lockout for failed password attempts is configured'
  desc 'Lockout for failed password attempts should be configured.'
  describe file('/etc/security/faillock.conf') do
    its('content') { should match(/^deny = 5$/) }
    its('content') { should match(/^unlock_time = 900$/) }
  end
end

# 106. Ensure password reuse is limited
control 'rhel7-password-reuse-limited' do
  impact 1.0
  title 'Ensure password reuse is limited'
  desc 'Password reuse should be limited.'
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match(/^remember = 5$/) }
  end
end

# 107. Ensure password hashing algorithm is SHA-512
control 'rhel7-password-hashing-algorithm-sha512' do
  impact 1.0
  title 'Ensure password hashing algorithm is SHA-512'
  desc 'Password hashing algorithm should be SHA-512.'
  describe file('/etc/login.defs') do
    its('content') { should match(/^ENCRYPT_METHOD SHA512$/) }
  end
end

# 108. Ensure wireless interfaces are disabled
control 'rhel7-wireless-interfaces-disabled' do
  impact 1.0
  title 'Ensure wireless interfaces are disabled'
  desc 'Wireless interfaces should be disabled.'
  describe command('nmcli radio wifi') do
    its('stdout') { should match(/disabled/) }
  end
end

# 109. Ensure no world writable files exist
control 'rhel7-no-world-writable-files-exist' do
  impact 1.0
  title 'Ensure no world writable files exist'
  desc 'No world writable files should exist.'
  describe command('find / -xdev -type f -perm -0002') do
    its('stdout') { should eq '' }
  end
end

# 110. Ensure no unowned files or directories exist
control 'rhel7-no-unowned-files-directories-exist' do
  impact 1.0
  title 'Ensure no unowned files or directories exist'
  desc 'No unowned files or directories should exist.'
  describe command('find / -xdev -nouser') do
    its('stdout') { should eq '' }
  end
end

# 111. Ensure no ungrouped files or directories exist
control 'rhel7-no-ungrouped-files-directories-exist' do
  impact 1.0
  title 'Ensure no ungrouped files or directories exist'
  desc 'No ungrouped files or directories should exist.'
  describe command('find / -xdev -nogroup') do
    its('stdout') { should eq '' }
  end
end

# 112. Ensure auditd service is enabled
control 'rhel7-auditd-service-enabled' do
  impact 1.0
  title 'Ensure auditd service is enabled'
  desc 'Auditd service should be enabled.'
  describe service('auditd') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 113. Ensure auditing for processes that start prior to auditd is enabled
control 'rhel7-auditing-processes-prior-to-auditd-enabled' do
  impact 1.0
  title 'Ensure auditing for processes that start prior to auditd is enabled'
  desc 'Auditing for processes that start prior to auditd should be enabled.'
  describe file('/boot/grub2/grub.cfg') do
    its('content') { should match(/audit=1/) }
  end
end

# 114. Ensure events that modify date and time information are collected
control 'rhel7-events-modify-date-time-collected' do
  impact 1.0
  title 'Ensure events that modify date and time information are collected'
  desc 'Events that modify date and time information should be collected.'
  describe auditd do
    its('lines') { should include '-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change' }
  end
end

# 115. Ensure events that modify user/group information are collected
control 'rhel7-events-modify-user-group-collected' do
  impact 1.0
  title 'Ensure events that modify user/group information are collected'
  desc 'Events that modify user/group information should be collected.'
  describe auditd do
    its('lines') { should include '-w /etc/group -p wa -k identity' }
    its('lines') { should include '-w /etc/passwd -p wa -k identity' }
    its('lines') { should include '-w /etc/gshadow -p wa -k identity' }
  end
end

# 116. Ensure events that modify the system's network environment are collected
control 'rhel7-events-modify-network-environment-collected' do
  impact 1.0
  title 'Ensure events that modify the system's network environment are collected'
  desc 'Events that modify the system's network environment should be collected.'
  describe auditd do
    its('lines') { should include '-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale' }
  end
end

# 117. Ensure events that modify the system's Mandatory Access Controls are collected
control 'rhel7-events-modify-mac-collected' do
  impact 1.0
  title 'Ensure events that modify the system's Mandatory Access Controls are collected'
  desc 'Events that modify the system's Mandatory Access Controls should be collected.'
  describe auditd do
    its('lines') { should include '-w /etc/selinux/ -p wa -k MAC-policy' }
  end
end

# 118. Ensure login and logout events are collected
control 'rhel7-login-logout-events-collected' do
  impact 1.0
  title 'Ensure login and logout events are collected'
  desc 'Login and logout events should be collected.'
  describe auditd do
    its('lines') { should include '-w /var/log/faillog -p wa -k logins' }
    its('lines') { should include '-w /var/log/lastlog -p wa -k logins' }
  end
end

# 119. Ensure session initiation information is collected
control 'rhel7-session-initiation-information-collected' do
  impact 1.0
  title 'Ensure session initiation information is collected'
  desc 'Session initiation information should be collected.'
  describe auditd do
    its('lines') { should include '-w /var/run/utmp -p wa -k session' }
    its('lines') { should include '-w /var/log/wtmp -p wa -k session' }
    its('lines') { should include '-w /var/log/btmp -p wa -k session' }
  end
end

# 120. Ensure discretionary access control permission modification events are collected
control 'rhel7-dac-permission-modification-events-collected' do
  impact 1.0
  title 'Ensure discretionary access control permission modification events are collected'
  desc 'Discretionary access control permission modification events should be collected.'
  describe auditd do
    its('lines') { should include '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -k perm_mod' }
  end
end

# 121. Audit SUID executables
control 'rhel7-audit-suid-executables' do
  impact 1.0
  title 'Audit SUID executables'
  desc 'SUID executables should be audited.'
  describe command('find / -xdev -type f -perm -4000') do
    its('stdout') { should_not eq '' }
  end
end

# 122. Audit SGID executables
control 'rhel7-audit-sgid-executables' do
  impact 1.0
  title 'Audit SGID executables'
  desc 'SGID executables should be audited.'
  describe command('find / -xdev -type f -perm -2000') do
    its('stdout') { should_not eq '' }
  end
end

# 123. Ensure successful file system mounts are collected
control 'rhel7-successful-file-system-mounts-collected' do
  impact 1.0
  title 'Ensure successful file system mounts are collected'
  desc 'Successful file system mounts should be collected.'
  describe auditd do
    its('lines') { should include '-a always,exit -F arch=b64 -S mount -k mounts' }
  end
end

# 124. Ensure file deletion events by users are collected
control 'rhel7-file-deletion-events-collected' do
  impact 1.0
  title 'Ensure file deletion events by users are collected'
  desc 'File deletion events by users should be collected.'
  describe auditd do
    its('lines') { should include '-a always,exit -F arch=b64 -S unlink,unlinkat -k delete' }
  end
end

# 125. Ensure changes to system administration scope (sudoers) is collected
control 'rhel7-changes-to-sudoers-collected' do
  impact 1.0
  title 'Ensure changes to system administration scope (sudoers) is collected'
  desc 'Changes to system administration scope (sudoers) should be collected.'
  describe auditd do
    its('lines') { should include '-w /etc/sudoers -p wa -k scope' }
    its('lines') { should include '-w /etc/sudoers.d/ -p wa -k scope' }
  end
end

# 126. Ensure system administrator actions (sudolog) are collected
control 'rhel7-system-administrator-actions-collected' do
  impact 1.0
  title 'Ensure system administrator actions (sudolog) are collected'
  desc 'System administrator actions (sudolog) should be collected.'
  describe auditd do
    its('lines') { should include '-w /var/log/sudo.log -p wa -k actions' }
  end
end

# 127. Ensure root PATH Integrity
control 'rhel7-root-path-integrity' do
  impact 1.0
  title 'Ensure root PATH Integrity'
  desc 'Root PATH Integrity should be ensured.'
  describe command('echo $PATH') do
    its('stdout') { should_not match(/::/) }
    its('stdout') { should_not match(/:$/) }
  end
end

# 128. Ensure the audit configuration is immutable
control 'rhel7-audit-configuration-immutable' do
  impact 1.0
  title 'Ensure the audit configuration is immutable'
  desc 'The audit configuration should be immutable.'
  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^-e 2$/) }
  end
end

# 129. Ensure rsyslog Service is enabled
control 'rhel7-rsyslog-service-enabled' do
  impact 1.0
  title 'Ensure rsyslog Service is enabled'
  desc 'Rsyslog Service should be enabled.'
  describe service('rsyslog') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 130. Ensure all users' home directories exist
control 'rhel7-all-users-home-directories-exist' do
  impact 1.0
  title 'Ensure all users\' home directories exist'
  desc 'All users\' home directories should exist.'
  describe command('cat /etc/passwd | awk -F: \'{ print $6 }\' | xargs -n1 test -d') do
    its('exit_status') { should eq 0 }
  end
end

# 131. Ensure rsyslog is configured to send logs to a remote log host
control 'rhel7-rsyslog-send-logs-remote-log-host' do
  impact 1.0
  title 'Ensure rsyslog is configured to send logs to a remote log host'
  desc 'Rsyslog should be configured to send logs to a remote log host.'
  describe file('/etc/rsyslog.conf') do
    its('content') { should match(/^\*\.\* @remote-log-host:514$/) }
  end
end

# 132. Ensure users' home directories permissions are 750 or more restrictive
control 'rhel7-users-home-directories-permissions-restrictive' do
  impact 1.0
  title 'Ensure users\' home directories permissions are 750 or more restrictive'
  desc 'Users\' home directories permissions should be 750 or more restrictive.'
  describe command('find /home -type d -perm -002') do
    its('stdout') { should eq '' }
  end
end

# 133. Ensure users own their home directories
control 'rhel7-users-own-home-directories' do
  impact 1.0
  title 'Ensure users own their home directories'
  desc 'Users should own their home directories.'
  describe command('find /home -not -user $(ls /home)') do
    its('stdout') { should eq '' }
  end
end

# 134. Ensure users\' dot files are not group or world writable
control 'rhel7-users-dot-files-not-group-world-writable' do
  impact 1.0
  title 'Ensure users\' dot files are not group or world writable'
  desc 'Users\' dot files should not be group or world writable.'
  describe command('find /home -name \'.*\' -perm -002') do
    its('stdout') { should eq '' }
  end
end

# 135. Ensure no users have .forward files
control 'rhel7-no-users-have-forward-files' do
  impact 1.0
  title 'Ensure no users have .forward files'
  desc 'No users should have .forward files.'
  describe command('find /home -name .forward') do
    its('stdout') { should eq '' }
  end
end

# 136. Ensure no users have .netrc files
control 'rhel7-no-users-have-netrc-files' do
  impact 1.0
  title 'Ensure no users have .netrc files'
  desc 'No users should have .netrc files.'
  describe command('find /home -name .netrc') do
    its('stdout') { should eq '' }
  end
end

# 137. Ensure no users have .rhosts files
control 'rhel7-no-users-have-rhosts-files' do
  impact 1.0
  title 'Ensure no users have .rhosts files'
  desc 'No users should have .rhosts files.'
  describe command('find /home -name .rhosts') do
    its('stdout') { should eq '' }
  end
end

# 138. Ensure rsyslog or syslog-ng is installed
control 'rhel7-rsyslog-syslog-ng-installed' do
  impact 1.0
  title 'Ensure rsyslog or syslog-ng is installed'
  desc 'Rsyslog or syslog-ng should be installed.'
  describe.one do
    describe package('rsyslog') do
      it { should be_installed }
    end
    describe package('syslog-ng') do
      it { should be_installed }
    end
  end
end

# 139. Ensure /tmp is configured
control 'rhel7-tmp-configured' do
  impact 1.0
  title 'Ensure /tmp is configured'
  desc '/tmp should be configured.'
  describe mount('/tmp') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
    its('options') { should include 'nosuid' }
    its('options') { should include 'noexec' }
  end
end

# 140. Ensure logrotate is configured
control 'rhel7-logrotate-configured' do
  impact 1.0
  title 'Ensure logrotate is configured'
  desc 'Logrotate should be configured.'
  describe file('/etc/logrotate.conf') do
    its('content') { should match(/^weekly$/) }
    its('content') { should match(/^rotate 4$/) }
  end
end

# 141. Ensure cron daemon is enabled
control 'rhel7-cron-daemon-enabled' do
  impact 1.0
  title 'Ensure cron daemon is enabled'
  desc 'Cron daemon should be enabled.'
  describe service('crond') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 142. Ensure permissions on /etc/crontab are configured
control 'rhel7-permissions-crontab-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/crontab are configured'
  desc 'Permissions on /etc/crontab should be configured.'
  describe file('/etc/crontab') do
    its('mode') { should cmp '0600' }
  end
end

# 143. Ensure permissions on /etc/cron.hourly are configured
control 'rhel7-permissions-cron-hourly-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/cron.hourly are configured'
  desc 'Permissions on /etc/cron.hourly should be configured.'
  describe file('/etc/cron.hourly') do
    its('mode') { should cmp '0700' }
  end
end

# 144. Ensure permissions on /etc/cron.daily are configured
control 'rhel7-permissions-cron-daily-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/cron.daily are configured'
  desc 'Permissions on /etc/cron.daily should be configured.'
  describe file('/etc/cron.daily') do
    its('mode') { should cmp '0700' }
  end
end

# 145. Ensure permissions on /etc/cron.weekly are configured
control 'rhel7-permissions-cron-weekly-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/cron.weekly are configured'
  desc 'Permissions on /etc/cron.weekly should be configured.'
  describe file('/etc/cron.weekly') do
    its('mode') { should cmp '0700' }
  end
end

# 146. Ensure permissions on /etc/cron.monthly are configured
control 'rhel7-permissions-cron-monthly-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/cron.monthly are configured'
  desc 'Permissions on /etc/cron.monthly should be configured.'
  describe file('/etc/cron.monthly') do
    its('mode') { should cmp '0700' }
  end
end

# 147. Ensure permissions on /etc/cron.d are configured
control 'rhel7-permissions-cron-d-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/cron.d are configured'
  desc 'Permissions on /etc/cron.d should be configured.'
  describe file('/etc/cron.d') do
    its('mode') { should cmp '0700' }
  end
end

# 148. Ensure /dev/shm is configured
control 'rhel7-dev-shm-configured' do
  impact 1.0
  title 'Ensure /dev/shm is configured'
  desc '/dev/shm should be configured.'
  describe mount('/dev/shm') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
    its('options') { should include 'nosuid' }
    its('options') { should include 'noexec' }
  end
end

# 149. Ensure permissions on /etc/ssh/sshd_config are configured
control 'rhel7-permissions-sshd-config-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/ssh/sshd_config are configured'
  desc 'Permissions on /etc/ssh/sshd_config should be configured.'
  describe file('/etc/ssh/sshd_config') do
    its('mode') { should cmp '0600' }
  end
end

# 150. Ensure SSH Protocol is set to 2
control 'rhel7-ssh-protocol-set-to-2' do
  impact 1.0
  title 'Ensure SSH Protocol is set to 2'
  desc 'SSH Protocol should be set to 2.'
  describe sshd_config do
    its('Protocol') { should eq '2' }
  end
end

# 151. Ensure SSH LogLevel is set to INFO
control 'rhel7-ssh-loglevel-set-to-info' do
  impact 1.0
  title 'Ensure SSH LogLevel is set to INFO'
  desc 'SSH LogLevel should be set to INFO.'
  describe sshd_config do
    its('LogLevel') { should eq 'INFO' }
  end
end

# 152. Disable USB Storage
control 'rhel7-disable-usb-storage' do
  impact 1.0
  title 'Disable USB Storage'
  desc 'USB Storage should be disabled.'
  describe file('/etc/modprobe.d/usb-storage.conf') do
    its('content') { should match(/^install usb-storage /bin/true$/) }
  end
end

# 153. Ensure last logged in user display is disabled
control 'rhel7-last-logged-in-user-display-disabled' do
  impact 1.0
  title 'Ensure last logged in user display is disabled'
  desc 'Last logged in user display should be disabled.'
  describe file('/etc/gdm/custom.conf') do
    its('content') { should match(/^\[daemon\]\nLastLoggedIn=false$/) }
  end
end

# 154. Ensure XDCMP is not enabled
control 'rhel7-xdcmp-not-enabled' do
  impact 1.0
  title 'Ensure XDCMP is not enabled'
  desc 'XDCMP should not be enabled.'
  describe file('/etc/gdm/custom.conf') do
    its('content') { should_not match(/^Enable=true$/) }
  end
end

# 155. Ensure rsync is not installed or the rsyncd service is masked
control 'rhel7-rsync-not-installed-service-masked' do
  impact 1.0
  title 'Ensure rsync is not installed or the rsyncd service is masked'
  desc 'Rsync should not be installed or the rsyncd service should be masked.'
  describe.one do
    describe package('rsync') do
      it { should_not be_installed }
    end
    describe service('rsyncd') do
      it { should be_masked }
    end
  end
end

# 156. Ensure nonessential services are removed or masked
control 'rhel7-nonessential-services-removed-masked' do
  impact 1.0
  title 'Ensure nonessential services are removed or masked'
  desc 'Nonessential services should be removed or masked.'
  describe command('systemctl list-unit-files | grep enabled') do
    its('stdout') { should eq '' }
  end
end

# 157. Ensure audit logs are not automatically deleted
control 'rhel7-audit-logs-not-automatically-deleted' do
  impact 1.0
  title 'Ensure audit logs are not automatically deleted'
  desc 'Audit logs should not be automatically deleted.'
  describe file('/etc/audit/auditd.conf') do
    its('content') { should match(/^max_log_file_action = keep_logs$/) }
  end
end

# 158. Ensure only approved MAC algorithms are used
control 'rhel7-approved-mac-algorithms-used' do
  impact 1.0
  title 'Ensure only approved MAC algorithms are used'
  desc 'Only approved MAC algorithms should be used.'
  describe sshd_config do
    its('MACs') { should eq 'hmac-sha2-256,hmac-sha2-512' }
  end
end

# 159. Ensure password expiration is set to 45 days
control 'rhel7-password-expiration-set-to-45-days' do
  impact 1.0
  title 'Ensure password expiration is set to 45 days'
  desc 'Password expiration should be set to 45 days.'
  describe file('/etc/login.defs') do
    its('content') { should match(/^PASS_MAX_DAYS 45$/) }
  end
end

# 160. Ensure password expiration warning days is 7 or more
control 'rhel7-password-expiration-warning-days-set' do
  impact 1.0
  title 'Ensure password expiration warning days is 7 or more'
  desc 'Password expiration warning days should be 7 or more.'
  describe file('/etc/login.defs') do
    its('content') { should match(/^PASS_WARN_AGE 7$/) }
  end
end

# 161. Ensure inactive password lock is 7 days or less
control 'rhel7-inactive-password-lock-7-days-or-less' do
  impact 1.0
  title 'Ensure inactive password lock is 7 days or less'
  desc 'Inactive password lock should be 7 days or less.'
  describe file('/etc/default/useradd') do
    its('content') { should match(/^INACTIVE=7$/) }
  end
end

# 162. Ensure all users last password change date is in the past
control 'rhel7-users-last-password-change-date-in-past' do
  impact 1.0
  title 'Ensure all users last password change date is in the past'
  desc 'All users last password change date should be in the past.'
  describe command('chage -l $(cut -d: -f1 /etc/passwd) | grep "Last password change"') do
    its('stdout') { should_not match(/never/) }
  end
end

# 163. Ensure auditd service is enabled and running
control 'rhel7-auditd-service-enabled-running' do
  impact 1.0
  title 'Ensure auditd service is enabled and running'
  desc 'Auditd service should be enabled and running.'
  describe service('auditd') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 164. Ensure default group for the root account is GID 0
control 'rhel7-default-group-root-account-gid-0' do
  impact 1.0
  title 'Ensure default group for the root account is GID 0'
  desc 'Default group for the root account should be GID 0.'
  describe user('root') do
    its('gid') { should eq 0 }
  end
end

# 165. Ensure default user umask is 022 or more restrictive
control 'rhel7-default-user-umask-022-or-more-restrictive' do
  impact 1.0
  title 'Ensure default user umask is 022 or more restrictive'
  desc 'Default user umask should be 022 or more restrictive.'
  describe file('/etc/profile') do
    its('content') { should match(/^umask 022$/) }
  end
end

# 166. Ensure default user shell timeout is set to 600 seconds
control 'rhel7-default-user-shell-timeout-600-seconds' do
  impact 1.0
  title 'Ensure default user shell timeout is set to 600 seconds'
  desc 'Default user shell timeout should be set to 600 seconds.'
  describe file('/etc/profile') do
    its('content') { should match(/^TMOUT=600$/) }
  end
end

# 167. Ensure rsyslog Service is enabled and running
control 'rhel7-rsyslog-service-enabled-running' do
  impact 1.0
  title 'Ensure rsyslog Service is enabled and running'
  desc 'Rsyslog Service should be enabled and running.'
  describe service('rsyslog') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 168. Ensure access to the su command is restricted
control 'rhel7-access-su-command-restricted' do
  impact 1.0
  title 'Ensure access to the su command is restricted'
  desc 'Access to the su command should be restricted.'
  describe file('/etc/pam.d/su') do
    its('content') { should match(/^auth required pam_wheel.so use_uid$/) }
  end
end

# 169. Ensure sudo is installed
control 'rhel7-sudo-installed' do
  impact 1.0
  title 'Ensure sudo is installed'
  desc 'Sudo should be installed.'
  describe package('sudo') do
    it { should be_installed }
  end
end

# 170. Ensure permissions on /etc/passwd are configured
control 'rhel7-permissions-passwd-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/passwd are configured'
  desc 'Permissions on /etc/passwd should be configured.'
  describe file('/etc/passwd') do
    its('mode') { should cmp '0644' }
  end
end

# 171. Ensure permissions on /etc/shadow are configured
control 'rhel7-permissions-shadow-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/shadow are configured'
  desc 'Permissions on /etc/shadow should be configured.'
  describe file('/etc/shadow') do
    its('mode') { should cmp '0600' }
  end
end

# 172. Ensure permissions on /etc/group are configured
control 'rhel7-permissions-group-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/group are configured'
  desc 'Permissions on /etc/group should be configured.'
  describe file('/etc/group') do
    its('mode') { should cmp '0644' }
  end
end

# 173. Ensure permissions on /etc/gshadow are configured
control 'rhel7-permissions-gshadow-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/gshadow are configured'
  desc 'Permissions on /etc/gshadow should be configured.'
  describe file('/etc/gshadow') do
    its('mode') { should cmp '0600' }
  end
end

# 174. Ensure permissions on /etc/passwd- are configured
control 'rhel7-permissions-passwd-backup-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/passwd- are configured'
  desc 'Permissions on /etc/passwd- should be configured.'
  describe file('/etc/passwd-') do
    its('mode') { should cmp '0644' }
  end
end

# 175. Ensure permissions on /etc/shadow- are configured
control 'rhel7-permissions-shadow-backup-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/shadow- are configured'
  desc 'Permissions on /etc/shadow- should be configured.'
  describe file('/etc/shadow-') do
    its('mode') { should cmp '0600' }
  end
end

# 176. Ensure permissions on /etc/group- are configured
control 'rhel7-permissions-group-backup-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/group- are configured'
  desc 'Permissions on /etc/group- should be configured.'
  describe file('/etc/group-') do
    its('mode') { should cmp '0644' }
  end
end

# 177. Ensure permissions on /etc/gshadow- are configured
control 'rhel7-permissions-gshadow-backup-configured' do
  impact 1.0
  title 'Ensure permissions on /etc/gshadow- are configured'
  desc 'Permissions on /etc/gshadow- should be configured.'
  describe file('/etc/gshadow-') do
    its('mode') { should cmp '0600' }
  end
end

# 178. Ensure sudo commands use pty
control 'rhel7-sudo-commands-use-pty' do
  impact 1.0
  title 'Ensure sudo commands use pty'
  desc 'Sudo commands should use pty.'
  describe file('/etc/sudoers') do
    its('content') { should match(/^Defaults use_pty$/) }
  end
end

# 179. Ensure sudo log file exists
control 'rhel7-sudo-log-file-exists' do
  impact 1.0
  title 'Ensure sudo log file exists'
  desc 'Sudo log file should exist.'
  describe file('/var/log/sudo.log') do
    it { should exist }
  end
end

# 180. Ensure SSH LogLevel is appropriate
control 'rhel7-ssh-loglevel-appropriate' do
  impact 1.0
  title 'Ensure SSH LogLevel is appropriate'
  desc 'SSH LogLevel should be appropriate.'
  describe sshd_config do
    its('LogLevel') { should eq 'INFO' }
  end
end

# 181. Ensure only strong Ciphers are used
control 'rhel7-strong-ciphers-used' do
  impact 1.0
  title 'Ensure only strong Ciphers are used'
  desc 'Only strong Ciphers should be used.'
  describe sshd_config do
    its('Ciphers') { should eq 'aes256-ctr,aes192-ctr,aes128-ctr' }
  end
end

# 182. Ensure only strong MAC algorithms are used
control 'rhel7-strong-mac-algorithms-used' do
  impact 1.0
  title 'Ensure only strong MAC algorithms are used'
  desc 'Only strong MAC algorithms should be used.'
  describe sshd_config do
    its('MACs') { should eq 'hmac-sha2-256,hmac-sha2-512' }
  end
end

# 183. Ensure password fields are not empty
control 'rhel7-password-fields-not-empty' do
  impact 1.0
  title 'Ensure password fields are not empty'
  desc 'Password fields should not be empty.'
  describe command('awk -F: \'{ if ($2 == "") print $1 }\' /etc/shadow') do
    its('stdout') { should eq '' }
  end
end

# 184. Ensure no legacy "+" entries exist in /etc/passwd
control 'rhel7-no-legacy-plus-entries-passwd' do
  impact 1.0
  title 'Ensure no legacy "+" entries exist in /etc/passwd'
  desc 'No legacy "+" entries should exist in /etc/passwd.'
  describe file('/etc/passwd') do
    its('content') { should_not match(/^\+:/) }
  end
end

# 185. Ensure no legacy "+" entries exist in /etc/shadow
control 'rhel7-no-legacy-plus-entries-shadow' do
  impact 1.0
  title 'Ensure no legacy "+" entries exist in /etc/shadow'
  desc 'No legacy "+" entries should exist in /etc/shadow.'
  describe file('/etc/shadow') do
    its('content') { should_not match(/^\+:/) }
  end
end

# 186. Ensure no legacy "+" entries exist in /etc/group
control 'rhel7-no-legacy-plus-entries-group' do
  impact 1.0
  title 'Ensure no legacy "+" entries exist in /etc/group'
  desc 'No legacy "+" entries should exist in /etc/group.'
  describe file('/etc/group') do
    its('content') { should_not match(/^\+:/) }
  end
end

# 187. Ensure root is the only UID 0 account
control 'rhel7-root-only-uid-0-account' do
  impact 1.0
  title 'Ensure root is the only UID 0 account'
  desc 'Root should be the only UID 0 account.'
  describe command('awk -F: \'{ if ($3 == 0) print $1 }\' /etc/passwd') do
    its('stdout') { should eq 'root\n' }
  end
end

# 188. Ensure only strong Key Exchange algorithms are used
control 'rhel7-strong-key-exchange-algorithms-used' do
  impact 1.0
  title 'Ensure only strong Key Exchange algorithms are used'
  desc 'Only strong Key Exchange algorithms should be used.'
  describe sshd_config do
    its('KexAlgorithms') { should eq 'diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256' }
  end
end

# 189. Ensure SSH PAM is enabled
control 'rhel7-ssh-pam-enabled' do
  impact 1.0
  title 'Ensure SSH PAM is enabled'
  desc 'SSH PAM should be enabled.'
  describe sshd_config do
    its('UsePAM') { should eq 'yes' }
  end
end

# 190. Ensure SSH AllowTcpForwarding is disabled
control 'rhel7-ssh-allowtcpforwarding-disabled' do
  impact 1.0
  title 'Ensure SSH AllowTcpForwarding is disabled'
  desc 'SSH AllowTcpForwarding should be disabled.'
  describe sshd_config do
    its('AllowTcpForwarding') { should eq 'no' }
  end
end

# 191. Ensure SSH MaxStartups is configured
control 'rhel7-ssh-maxstartups-configured' do
  impact 1.0
  title 'Ensure SSH MaxStartups is configured'
  desc 'SSH MaxStartups should be configured.'
  describe sshd_config do
    its('MaxStartups') { should eq '10:30:60' }
  end
end

# 192. Ensure SSH MaxSessions is limited
control 'rhel7-ssh-maxsessions-limited' do
  impact 1.0
  title 'Ensure SSH MaxSessions is limited'
  desc 'SSH MaxSessions should be limited.'
  describe sshd_config do
    its('MaxSessions') { should cmp <= 10 }
  end
end

# 193. Ensure minimum days between password changes is configured
control 'rhel7-minimum-days-between-password-changes-configured' do
  impact 1.0
  title 'Ensure minimum days between password changes is configured'
  desc 'Minimum days between password changes should be configured.'
  describe file('/etc/login.defs') do
    its('content') { should match(/^PASS_MIN_DAYS 1$/) }
  end
end

# 194. Ensure shadow group is empty
control 'rhel7-shadow-group-empty' do
  impact 1.0
  title 'Ensure shadow group is empty'
  desc 'Shadow group should be empty.'
  describe command('awk -F: \'{ if ($1 == "shadow") print $4 }\' /etc/group') do
    its('stdout') { should eq '' }
  end
end

# 195. Ensure users\' .netrc Files are not group or world accessible
control 'rhel7-users-netrc-files-not-group-world-accessible' do
  impact 1.0
  title 'Ensure users\' .netrc Files are not group or world accessible'
  desc 'Users\' .netrc Files should not be group or world accessible.'
  describe command('find /home -name .netrc -perm -004') do
    its('stdout') { should eq '' }
  end
end

# 196. Ensure CUPS is not installed
control 'rhel7-cups-not-installed' do
  impact 1.0
  title 'Ensure CUPS is not installed'
  desc 'CUPS should not be installed.'
  describe package('cups') do
    it { should_not be_installed }
  end
end

# 197. Ensure all groups in /etc/passwd exist in /etc/group
control 'rhel7-all-groups-passwd-exist-group' do
  impact 1.0
  title 'Ensure all groups in /etc/passwd exist in /etc/group'
  desc 'All groups in /etc/passwd should exist in /etc/group.'
  describe command('awk -F: \'{ print $4 }\' /etc/passwd | xargs -n1 getent group') do
    its('exit_status') { should eq 0 }
  end
end

# 198. Ensure no duplicate UIDs exist
control 'rhel7-no-duplicate-uids-exist' do
  impact 1.0
  title 'Ensure no duplicate UIDs exist'
  desc 'No duplicate UIDs should exist.'
  describe command('awk -F: \'{ print $3 }\' /etc/passwd | sort | uniq -d') do
    its('stdout') { should eq '' }
  end
end

# 199. Ensure no duplicate GIDs exist
control 'rhel7-no-duplicate-gids-exist' do
  impact 1.0
  title 'Ensure no duplicate GIDs exist'
  desc 'No duplicate GIDs should exist.'
  describe command('awk -F: \'{ print $3 }\' /etc/group | sort | uniq -d') do
    its('stdout') { should eq '' }
  end
end

# 200. Ensure no duplicate user names exist
control 'rhel7-no-duplicate-user-names-exist' do
  impact 1.0
  title 'Ensure no duplicate user names exist'
  desc 'No duplicate user names should exist.'
  describe command('awk -F: \'{ print $1 }\' /etc/passwd | sort | uniq -d') do
    its('stdout') { should eq '' }
  end
end

# 201. Ensure no duplicate group names exist
control 'rhel7-no-duplicate-group-names-exist' do
  impact 1.0
  title 'Ensure no duplicate group names exist'
  desc 'No duplicate group names should exist.'
  describe command('awk -F: \'{ print $1 }\' /etc/group | sort | uniq -d') do
    its('stdout') { should eq '' }
  end
end

# 202. Ensure DHCP Server is not installed
control 'rhel7-dhcp-server-not-installed' do
  impact 1.0
  title 'Ensure DHCP Server is not installed'
  desc 'DHCP Server should not be installed.'
  describe package('dhcp') do
    it { should_not be_installed }
  end
end

# 203. Ensure LDAP server is not installed
control 'rhel7-ldap-server-not-installed' do
  impact 1.0
  title 'Ensure LDAP server is not installed'
  desc 'LDAP server should not be installed.'
  describe package('openldap-servers') do
    it { should_not be_installed }
  end
end

# 204. Ensure DNS Server is not installed
control 'rhel7-dns-server-not-installed' do
  impact 1.0
  title 'Ensure DNS Server is not installed'
  desc 'DNS Server should not be installed.'
  describe package('bind') do
    it { should_not be_installed }
  end
end

# 205. Ensure GNOME Display Manager is removed
control 'rhel7-gnome-display-manager-removed' do
  impact 1.0
  title 'Ensure GNOME Display Manager is removed'
  desc 'GNOME Display Manager should be removed.'
  describe package('gdm') do
    it { should_not be_installed }
  end
end

# 206. Ensure FTP Server is not installed
control 'rhel7-ftp-server-not-installed' do
  impact 1.0
  title 'Ensure FTP Server is not installed'
  desc 'FTP Server should not be installed.'
  describe package('vsftpd') do
    it { should_not be_installed }
  end
end

# 207. Ensure HTTP server is not installed
control 'rhel7-http-server-not-installed' do
  impact 1.0
  title 'Ensure HTTP server is not installed'
  desc 'HTTP server should not be installed.'
  describe package('httpd') do
    it { should_not be_installed }
  end
end

# 208. Ensure IMAP and POP3 server is not installed
control 'rhel7-imap-pop3-server-not-installed' do
  impact 1.0
  title 'Ensure IMAP and POP3 server is not installed'
  desc 'IMAP and POP3 server should not be installed.'
  describe package('dovecot') do
    it { should_not be_installed }
  end
end

# 209. Ensure Samba is not installed
control 'rhel7-samba-not-installed' do
  impact 1.0
  title 'Ensure Samba is not installed'
  desc 'Samba should not be installed.'
  describe package('samba') do
    it { should_not be_installed }
  end
end

# 210. Ensure HTTP Proxy Server is not installed
control 'rhel7-http-proxy-server-not-installed' do
  impact 1.0
  title 'Ensure HTTP Proxy Server is not installed'
  desc 'HTTP Proxy Server should not be installed.'
  describe package('squid') do
    it { should_not be_installed }
  end
end

# 211. Ensure net-snmp is not installed
control 'rhel7-net-snmp-not-installed' do
  impact 1.0
  title 'Ensure net-snmp is not installed'
  desc 'Net-SNMP should not be installed.'
  describe package('net-snmp') do
    it { should_not be_installed }
  end
end

# 212. Ensure NIS server is not installed
control 'rhel7-nis-server-not-installed' do
  impact 1.0
  title 'Ensure NIS server is not installed'
  desc 'NIS server should not be installed.'
  describe package('ypserv') do
    it { should_not be_installed }
  end
end

# 213. Ensure telnet-server is not installed
control 'rhel7-telnet-server-not-installed' do
  impact 1.0
  title 'Ensure telnet-server is not installed'
  desc 'Telnet-server should not be installed.'
  describe package('telnet-server') do
    it { should_not be_installed }
  end
end

# 214. Ensure auditd is installed
control 'rhel7-auditd-installed' do
  impact 1.0
  title 'Ensure auditd is installed'
  desc 'Auditd should be installed.'
  describe package('audit') do
    it { should be_installed }
  end
end

# 215. Ensure cron daemon is enabled and running
control 'rhel7-cron-daemon-enabled-running' do
  impact 1.0
  title 'Ensure cron daemon is enabled and running'
  desc 'Cron daemon should be enabled and running.'
  describe service('crond') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 216. Ensure Avahi Server is not installed
control 'rhel7-avahi-server-not-installed' do
  impact 1.0
  title 'Ensure Avahi Server is not installed'
  desc 'Avahi Server should not be installed.'
  describe package('avahi') do
    it { should_not be_installed }
  end
end

# 217. Ensure xinetd is not installed
control 'rhel7-xinetd-not-installed' do
  impact 1.0
  title 'Ensure xinetd is not installed'
  desc 'Xinetd should not be installed.'
  describe package('xinetd') do
    it { should_not be_installed }
  end
end

# 218. Ensure X11 Server components are not installed
control 'rhel7-x11-server-components-not-installed' do
  impact 1.0
  title 'Ensure X11 Server components are not installed'
  desc 'X11 Server components should not be installed.'
  describe package('xorg-x11-server-common') do
    it { should_not be_installed }
  end
end

# 219. Ensure nodev option set on removable media partitions
control 'rhel7-nodev-on-removable-media-partitions' do
  impact 1.0
  title 'Ensure nodev option set on removable media partitions'
  desc 'Nodev option should be set on removable media partitions.'
  describe mount('/media') do
    its('options') { should include 'nodev' }
  end
end

# 220. Ensure nosuid option set on removable media partitions
control 'rhel7-nosuid-on-removable-media-partitions' do
  impact 1.0
  title 'Ensure nosuid option set on removable media partitions'
  desc 'Nosuid option should be set on removable media partitions.'
  describe mount('/media') do
    its('options') { should include 'nosuid' }
  end
end

# 221. Ensure noexec option set on removable media partitions
control 'rhel7-noexec-on-removable-media-partitions' do
  impact 1.0
  title 'Ensure noexec option set on removable media partitions'
  desc 'Noexec option should be set on removable media partitions.'
  describe mount('/media') do
    its('options') { should include 'noexec' }
  end
end

# 222. Disable the rhnsd Daemon
control 'rhel7-disable-rhnsd-daemon' do
  impact 1.0
  title 'Disable the rhnsd Daemon'
  desc 'The rhnsd Daemon should be disabled.'
  describe service('rhnsd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 223. Ensure no unconfined daemons exist
control 'rhel7-no-unconfined-daemons-exist' do
  impact 1.0
  title 'Ensure no unconfined daemons exist'
  desc 'No unconfined daemons should exist.'
  describe command('ps -eZ | grep unconfined_service_t') do
    its('stdout') { should eq '' }
  end
end

# 224. Ensure nfs-utils is not installed or the nfs-server service is masked
control 'rhel7-nfs-utils-not-installed-service-masked' do
  impact 1.0
  title 'Ensure nfs-utils is not installed or the nfs-server service is masked'
  desc 'Nfs-utils should not be installed or the nfs-server service should be masked.'
  describe.one do
    describe package('nfs-utils') do
      it { should_not be_installed }
    end
    describe service('nfs-server') do
      it { should be_masked }
    end
  end
end

# 225. Ensure rpcbind is not installed or the rpcbind services are masked
control 'rhel7-rpcbind-not-installed-services-masked' do
  impact 1.0
  title 'Ensure rpcbind is not installed or the rpcbind services are masked'
  desc 'Rpcbind should not be installed or the rpcbind services should be masked.'
  describe.one do
    describe package('rpcbind') do
      it { should_not be_installed }
    end
    describe service('rpcbind') do
      it { should be_masked }
    end
  end
end

# 226. Ensure audit log storage size is configured
control 'rhel7-audit-log-storage-size-configured' do
  impact 1.0
  title 'Ensure audit log storage size is configured'
  desc 'Audit log storage size should be configured.'
  describe file('/etc/audit/auditd.conf') do
    its('content') { should match(/^max_log_file = \d+$/) }
  end
end

# 227. Ensure audit_backlog_limit is sufficient
control 'rhel7-audit-backlog-limit-sufficient' do
  impact 1.0
  title 'Ensure audit_backlog_limit is sufficient'
  desc 'Audit_backlog_limit should be sufficient.'
  describe kernel_parameter('audit_backlog_limit') do
    its('value') { should cmp >= 8192 }
  end
end

# 228. Ensure journald is configured to send logs to rsyslog
control 'rhel7-journald-send-logs-to-rsyslog' do
  impact 1.0
  title 'Ensure journald is configured to send logs to rsyslog'
  desc 'Journald should be configured to send logs to rsyslog.'
  describe file('/etc/systemd/journald.conf') do
    its('content') { should match(/^ForwardToSyslog=yes$/) }
  end
end

# 229. Ensure journald is configured to compress large log files
control 'rhel7-journald-compress-large-log-files' do
  impact 1.0
  title 'Ensure journald is configured to compress large log files'
  desc 'Journald should be configured to compress large log files.'
  describe file('/etc/systemd/journald.conf') do
    its('content') { should match(/^Compress=yes$/) }
  end
end

# 230. Ensure at is restricted to authorized users
control 'rhel7-at-restricted-to-authorized-users' do
  impact 1.0
  title 'Ensure at is restricted to authorized users'
  desc 'At should be restricted to authorized users.'
  describe file('/etc/at.allow') do
    it { should exist }
  end
  describe file('/etc/at.deny') do
    it { should_not exist }
  end
end

# 231. Ensure permissions on SSH private host key files are configured
control 'rhel7-permissions-ssh-private-host-key-files-configured' do
  impact 1.0
  title 'Ensure permissions on SSH private host key files are configured'
  desc 'Permissions on SSH private host key files should be configured.'
  describe file('/etc/ssh/ssh_host_rsa_key') do
    its('mode') { should cmp '0600' }
  end
end

# 232. Ensure permissions on SSH public host key files are configured
control 'rhel7-permissions-ssh-public-host-key-files-configured' do
  impact 1.0
  title 'Ensure permissions on SSH public host key files are configured'
  desc 'Permissions on SSH public host key files should be configured.'
  describe file('/etc/ssh/ssh_host_rsa_key.pub') do
    its('mode') { should cmp '0644' }
  end
end

# 233. Ensure system accounts are non-login
control 'rhel7-system-accounts-non-login' do
  impact 1.0
  title 'Ensure system accounts are non-login'
  desc 'System accounts should be non-login.'
  describe command('awk -F: \'{ if ($3 < 1000 && $7 != "/sbin/nologin") print $1 }\' /etc/passwd') do
    its('stdout') { should eq '' }
  end
end

# 234. Ensure system accounts are secured
control 'rhel7-system-accounts-secured' do
  impact 1.0
  title 'Ensure system accounts are secured'
  desc 'System accounts should be secured.'
  describe command('awk -F: \'{ if ($3 < 1000 && $7 != "/sbin/nologin") print $1 }\' /etc/passwd') do
    its('stdout') { should eq '' }
  end
end

# 235. Ensure default user shell timeout is configured
control 'rhel7-default-user-shell-timeout-configured' do
  impact 1.0
  title 'Ensure default user shell timeout is configured'
  desc 'Default user shell timeout should be configured.'
  describe file('/etc/profile') do
    its('content') { should match(/^TMOUT=600$/) }
  end
end

# 236. Ensure default user umask is configured
control 'rhel7-default-user-umask-configured' do
  impact 1.0
  title 'Ensure default user umask is configured'
  desc 'Default user umask should be configured.'
  describe file('/etc/profile') do
    its('content') { should match(/^umask 027$/) }
  end
end

# 237. Ensure accounts in /etc/passwd use shadowed passwords
control 'rhel7-accounts-passwd-use-shadowed-passwords' do
  impact 1.0
  title 'Ensure accounts in /etc/passwd use shadowed passwords'
  desc 'Accounts in /etc/passwd should use shadowed passwords.'
  describe command('awk -F: \'{ if ($2 != "x") print $1 }\' /etc/passwd') do
    its('stdout') { should eq '' }
  end
end

# 238. Ensure /etc/shadow password fields are not empty
control 'rhel7-shadow-password-fields-not-empty' do
  impact 1.0
  title 'Ensure /etc/shadow password fields are not empty'
  desc '/etc/shadow password fields should not be empty.'
  describe command('awk -F: \'{ if ($2 == "") print $1 }\' /etc/shadow') do
    its('stdout') { should eq '' }
  end
end

# 239. Ensure nodev option set on /var partition
control 'rhel7-nodev-on-var-partition' do
  impact 1.0
  title 'Ensure nodev option set on /var partition'
  desc 'Nodev option should be set on /var partition.'
  describe mount('/var') do
    its('options') { should include 'nodev' }
  end
end

# 240. Ensure ptrace_scope is restricted
control 'rhel7-ptrace-scope-restricted' do
  impact 1.0
  title 'Ensure ptrace_scope is restricted'
  desc 'Ptrace_scope should be restricted.'
  describe kernel_parameter('kernel.yama.ptrace_scope') do
    its('value') { should cmp >= 1 }
  end
end

# 241. Ensure core dump backtraces are disabled
control 'rhel7-core-dump-backtraces-disabled' do
  impact 1.0
  title 'Ensure core dump backtraces are disabled'
  desc 'Core dump backtraces should be disabled.'
  describe file('/etc/systemd/coredump.conf') do
    its('content') { should match(/^ProcessSizeMax=0$/) }
  end
end

# 242. Ensure core dump storage is disabled
control 'rhel7-core-dump-storage-disabled' do
  impact 1.0
  title 'Ensure core dump storage is disabled'
  desc 'Core dump storage should be disabled.'
  describe file('/etc/systemd/coredump.conf') do
    its('content') { should match(/^Storage=none$/) }
  end
end

# 243. Ensure dnsmasq services are not in use
control 'rhel7-dnsmasq-services-not-in-use' do
  impact 1.0
  title 'Ensure dnsmasq services are not in use'
  desc 'Dnsmasq services should not be in use.'
  describe service('dnsmasq') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 244. Ensure message access server services are not in use
control 'rhel7-message-access-server-services-not-in-use' do
  impact 1.0
  title 'Ensure message access server services are not in use'
  desc 'Message access server services should not be in use.'
  describe service('dovecot') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 245. Ensure GDM disable-user-list option is enabled
control 'rhel7-gdm-disable-user-list-option-enabled' do
  impact 1.0
  title 'Ensure GDM disable-user-list option is enabled'
  desc 'GDM disable-user-list option should be enabled.'
  describe file('/etc/gdm/custom.conf') do
    its('content') { should match(/^\[daemon\]\nDisableUserList=true$/) }
  end
end

# 246. Ensure GDM screen locks when the user is idle
control 'rhel7-gdm-screen-locks-when-user-idle' do
  impact 1.0
  title 'Ensure GDM screen locks when the user is idle'
  desc 'GDM screen locks should be enabled when the user is idle.'
  describe file('/etc/dconf/db/gdm.d/00-security-settings') do
    its('content') { should match(/^\[org\/gnome\/desktop\/screensaver\]\nlock-enabled=true$/) }
  end
end

# 247. Ensure GDM screen locks cannot be overridden
control 'rhel7-gdm-screen-locks-cannot-be-overridden' do
  impact 1.0
  title 'Ensure GDM screen locks cannot be overridden'
  desc 'GDM screen locks should not be overridden.'
  describe file('/etc/dconf/db/gdm.d/00-security-settings') do
    its('content') { should match(/^\[org\/gnome\/desktop\/screensaver\]\nlock-delay=0$/) }
  end
end

# 248. Ensure GDM automatic mounting of removable media is disabled
control 'rhel7-gdm-automatic-mounting-removable-media-disabled' do
  impact 1.0
  title 'Ensure GDM automatic mounting of removable media is disabled'
  desc 'GDM automatic mounting of removable media should be disabled.'
  describe file('/etc/dconf/db/gdm.d/00-security-settings') do
    its('content') { should match(/^\[org\/gnome\/desktop\/media-handling\]\nautomount=false$/) }
  end
end

# 249. Ensure GDM disabling automatic mounting of removable media is not overridden
control 'rhel7-gdm-disabling-automatic-mounting-not-overridden' do
  impact 1.0
  title 'Ensure GDM disabling automatic mounting of removable media is not overridden'
  desc 'GDM disabling automatic mounting of removable media should not be overridden.'
  describe file('/etc/dconf/db/gdm.d/00-security-settings') do
    its('content') { should match(/^\[org\/gnome\/desktop\/media-handling\]\nautomount-open=false$/) }
  end
end

# 250. Ensure GDM autorun-never is enabled
control 'rhel7-gdm-autorun-never-enabled' do
  impact 1.0
  title 'Ensure GDM autorun-never is enabled'
  desc 'GDM autorun-never should be enabled.'
  describe file('/etc/dconf/db/gdm.d/00-security-settings') do
    its('content') { should match(/^\[org\/gnome\/desktop\/media-handling\]\nautorun-never=true$/) }
  end
end

# 251. Ensure GDM autorun-never is not overridden
control 'rhel7-gdm-autorun-never-not-overridden' do
  impact 1.0
  title 'Ensure GDM autorun-never is not overridden'
  desc 'GDM autorun-never should not be overridden.'
  describe file('/etc/dconf/db/gdm.d/00-security-settings') do
    its('content') { should match(/^\[org\/gnome\/desktop\/media-handling\]\nautorun-never=false$/) }
  end
end

# 252. Ensure chrony is not run as the root user
control 'rhel7-chrony-not-run-as-root-user' do
  impact 1.0
  title 'Ensure chrony is not run as the root user'
  desc 'Chrony should not be run as the root user.'
  describe file('/etc/chrony/chrony.conf') do
    its('content') { should match(/^user chrony$/) }
  end
end

# 253. Ensure bluetooth services are not in use
control 'rhel7-bluetooth-services-not-in-use' do
  impact 1.0
  title 'Ensure bluetooth services are not in use'
  desc 'Bluetooth services should not be in use.'
  describe service('bluetooth') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 254. Ensure ftp client is not installed
control 'rhel7-ftp-client-not-installed' do
  impact 1.0
  title 'Ensure ftp client is not installed'
  desc 'FTP client should not be installed.'
  describe package('ftp') do
    it { should_not be_installed }
  end
end

# 255. Ensure tftp client is not installed
control 'rhel7-tftp-client-not-installed' do
  impact 1.0
  title 'Ensure tftp client is not installed'
  desc 'TFTP client should not be installed.'
  describe package('tftp') do
    it { should_not be_installed }
  end
end

# 256. Ensure crontab is restricted to authorized users
control 'rhel7-crontab-restricted-to-authorized-users' do
  impact 1.0
  title 'Ensure crontab is restricted to authorized users'
  desc 'Crontab should be restricted to authorized users.'
  describe file('/etc/cron.allow') do
    it { should exist }
  end
  describe file('/etc/cron.deny') do
    it { should_not exist }
  end
end

# 257. Ensure all logfiles have appropriate access configured
control 'rhel7-logfiles-appropriate-access-configured' do
  impact 1.0
  title 'Ensure all logfiles have appropriate access configured'
  desc 'All logfiles should have appropriate access configured.'
  describe command('find /var/log -type f -exec ls -l {} \;') do
    its('stdout') { should match(/^-rw-------/) }
  end
end

# 258. Ensure rsyslog is not configured to receive logs from a remote client
control 'rhel7-rsyslog-not-configured-receive-logs-remote-client' do
  impact 1.0
  title 'Ensure rsyslog is not configured to receive logs from a remote client'
  desc 'Rsyslog should not be configured to receive logs from a remote client.'
  describe file('/etc/rsyslog.conf') do
    its('content') { should_not match(/^\$ModLoad imtcp$/) }
    its('content') { should_not match(/^\$InputTCPServerRun 514$/) }
  end
end

# 259. Ensure journald service is enabled
control 'rhel7-journald-service-enabled' do
  impact 1.0
  title 'Ensure journald service is enabled'
  desc 'Journald service should be enabled.'
  describe service('systemd-journald') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 260. Ensure journald log rotation is configured per site policy
control 'rhel7-journald-log-rotation-configured' do
  impact 1.0
  title 'Ensure journald log rotation is configured per site policy'
  desc 'Journald log rotation should be configured per site policy.'
  describe file('/etc/systemd/journald.conf') do
    its('content') { should match(/^SystemMaxUse=\d+$/) }
  end
end

# 261. Ensure systemd-journal-remote is installed
control 'rhel7-systemdjournal-remote-installed' do
  impact 1.0
  title 'Ensure systemd-journal-remote is installed'
  desc 'Systemdjournal-remote should be installed.'
  describe package('systemd-journal-remote') do
    it { should be_installed }
  end
end

# 262. Ensure systemd-journal-remote is configured
control 'rhel7-systemdjournal-remote-configured' do
  impact 1.0
  title 'Ensure systemd-journal-remote is configured'
  desc 'Systemdjournal-remote should be configured.'
  describe file('/etc/systemd/journal-remote.conf') do
    it { should exist }
    its('content') { should match /[Configuration]/ }
  end
end

# 263. Ensure systemd-journal-remote is enabled
control 'rhel7-systemdjournal-remote-enabled' do
  impact 1.0
  title 'Ensure systemd-journal-remote is enabled'
  desc 'Systemdjournal-remote should be enabled.'
  describe service('systemd-journal-remote') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 264. Ensure journald is not configured to receive logs from a remote client
control 'rhel7-journald-not-configured-receive-logs-remote-client' do
  impact 1.0
  title 'Ensure journald is not configured to receive logs from a remote client'
  desc 'Journald should not be configured to receive logs from a remote client.'
  describe file('/etc/systemd/journald.conf') do
    its('content') { should_not match(/^ForwardToSyslog=yes$/) }
  end
end

# 265. Ensure system warns when audit logs are low on space
control 'rhel7-system-warns-audit-logs-low-space' do
  impact 1.0
  title 'Ensure system warns when audit logs are low on space'
  desc 'System should warn when audit logs are low on space.'
  describe file('/etc/audit/auditd.conf') do
    its('content') { should match /space_left_action = email/ }
    its('content') { should match /action_mail_acct = root/ }
  end
end

# 266. Ensure sshd GSSAPIAuthentication is disabled
control 'rhel7-sshd-gssapiauthentication-disabled' do
  impact 1.0
  title 'Ensure sshd GSSAPIAuthentication is disabled'
  desc 'SSHD GSSAPIAuthentication should be disabled.'
  describe sshd_config do
    its('GSSAPIAuthentication') { should eq 'no' }
  end
end

# 267. Ensure users must provide password for escalation
control 'rhel7-users-provide-password-escalation' do
  impact 1.0
  title 'Ensure users must provide password for escalation'
  desc 'Users should provide password for escalation.'
  describe file('/etc/sudoers') do
    its('content') { should_not match /NOPASSWD/ }
  end
end

# 268. Ensure re-authentication for privilege escalation is not disabled globally
control 'rhel7-re-authentication-privilege-escalation-not-disabled' do
  impact 1.0
  title 'Ensure re-authentication for privilege escalation is not disabled globally'
  desc 'Re-authentication for privilege escalation should not be disabled globally.'
  describe file('/etc/sudoers') do
    its('content') { should_not match /!authenticate/ }
  end
end

# 269. Ensure sudo authentication timeout is configured correctly
control 'rhel7-sudo-authentication-timeout-configured' do
  impact 1.0
  title 'Ensure sudo authentication timeout is configured correctly'
  desc 'Sudo authentication timeout should be configured correctly.'
  describe file('/etc/sudoers') do
    its('content') { should match /timestamp_timeout=5/ }
  end
end

# 270. Ensure libpwquality is installed
control 'rhel7-libpwquality-installed' do
  impact 1.0
  title 'Ensure libpwquality is installed'
  desc 'Libpwquality should be installed.'
  describe package('libpwquality') do
    it { should be_installed }
  end
end

# 271. Ensure pam_faillock module is enabled
control 'rhel7-pam-faillock-module-enabled' do
  impact 1.0
  title 'Ensure pam_faillock module is enabled'
  desc 'Pam_faillock module should be enabled.'
  describe file('/etc/security/faillock.conf') do
    its('content') { should match /deny = [0-9]+/ }
  end
end

# 272. Ensure password failed attempts lockout includes root account
control 'rhel7-password-failed-attempts-lockout-includes-root' do
  impact 1.0
  title 'Ensure password failed attempts lockout includes root account'
  desc 'Password failed attempts lockout should include root account.'
  describe file('/etc/security/faillock.conf') do
    its('content') { should match /root_unlock_time = [0-9]+/ }
  end
end

# 273. Ensure pam_pwquality module is enabled
control 'rhel7-pam-pwquality-module-enabled' do
  impact 1.0
  title 'Ensure pam_pwquality module is enabled'
  desc 'Pam_pwquality module should be enabled.'
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /minlen = [0-9]+/ }
  end
end

# 274. Ensure password number of changed characters is configured
control 'rhel7-password-number-changed-characters-configured' do
  impact 1.0
  title 'Ensure password number of changed characters is configured'
  desc 'Password number of changed characters should be configured.'
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /difok = [0-9]+/ }
  end
end

# 275. Ensure password complexity is configured
control 'rhel7-password-complexity-configured' do
  impact 1.0
  title 'Ensure password complexity is configured'
  desc 'Password complexity should be configured.'
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /minclass = [0-9]+/ }
  end
end

# 276. Ensure successful and unsuccessful attempts to use the chcon command are recorded
control 'rhel7-chcon-command-attempts-recorded' do
  impact 1.0
  title 'Ensure successful and unsuccessful attempts to use the chcon command are recorded'
  desc 'Successful and unsuccessful attempts to use the chcon command should be recorded.'
  describe auditd_rules do
    its('lines') { should include '-a always,exit -F arch=b64 -S chcon -F auid>=1000 -F auid!=4294967295 -k privileged' }
  end
end

# 277. Ensure successful and unsuccessful attempts to use the setfacl command are recorded
control 'rhel7-setfacl-command-attempts-recorded' do
  impact 1.0
  title 'Ensure successful and unsuccessful attempts to use the setfacl command are recorded'
  desc 'Successful and unsuccessful attempts to use the setfacl command should be recorded.'
  describe auditd_rules do
    its('lines') { should include '-a always,exit -F arch=b64 -S setfacl -F auid>=1000 -F auid!=4294967295 -k privileged' }
  end
end

# 278. Ensure successful and unsuccessful attempts to use the chacl command are recorded
control 'rhel7-chacl-command-attempts-recorded' do
  impact 1.0
  title 'Ensure successful and unsuccessful attempts to use the chacl command are recorded'
  desc 'Successful and unsuccessful attempts to use the chacl command should be recorded.'
  describe auditd_rules do
    its('lines') { should include '-a always,exit -F arch=b64 -S chacl -F auid>=1000 -F auid!=4294967295 -k privileged' }
  end
end

# 279. Ensure successful and unsuccessful attempts to use the usermod command are recorded
control 'rhel7-usermod-command-attempts-recorded' do
  impact 1.0
  title 'Ensure successful and unsuccessful attempts to use the usermod command are recorded'
  desc 'Successful and unsuccessful attempts to use the usermod command should be recorded.'
  describe auditd_rules do
    its('lines') { should include '-a always,exit -F arch=b64 -S usermod -F auid>=1000 -F auid!=4294967295 -k privileged' }
  end
end

# 280. Ensure kernel module loading unloading and modification is collected
control 'rhel7-kernel-module-loading-unloading-modification-collected' do
  impact 1.0
  title 'Ensure kernel module loading unloading and modification is collected'
  desc 'Kernel module loading unloading and modification should be collected.'
  describe auditd_rules do
    its('lines') { should include '-a always,exit -F arch=b64 -S init_module -S delete_module -F auid>=1000 -F auid!=4294967295 -k module-change' }
  end
end

# 281. Ensure the running and on disk configuration is the same
control '281' do
  title 'Ensure the running and on disk configuration is the same'
  describe command('auditctl -l') do
    its('stdout') { should eq file('/etc/audit/audit.rules').content }
  end
end

# 282. Ensure the audit log directory is 0750 or more restrictive
control '282' do
  title 'Ensure the audit log directory is 0750 or more restrictive'
  describe file('/var/log/audit') do
    it { should exist }
    it { should be_directory }
    its('mode') { should cmp '0750' }
  end
end

# 283. Ensure password same consecutive characters is configured
control '283' do
  title 'Ensure password same consecutive characters is configured'
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /maxrepeat = [0-9]+/ }
  end
end

# 284. Ensure password maximum sequential characters is configured
control '284' do
  title 'Ensure password maximum sequential characters is configured'
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /maxsequence = [0-9]+/ }
  end
end

# 285. Ensure password dictionary check is enabled
control '285' do
  title 'Ensure password dictionary check is enabled'
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /dictcheck = 1/ }
  end
end

# 286. Ensure password history remember is configured
control '286' do
  title 'Ensure password history remember is configured'
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /remember = [0-9]+/ }
  end
end

# 287. Ensure password history is enforced for the root user
control '287' do
  title 'Ensure password history is enforced for the root user'
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match /root_remember = [0-9]+/ }
  end
end

# 288. Ensure pam_unix does not include nullok
control '288' do
  title 'Ensure pam_unix does not include nullok'
  describe file('/etc/pam.d/system-auth') do
    its('content') { should_not match /nullok/ }
  end
end

# 289. Ensure pam_unix does not include remember
control '289' do
  title 'Ensure pam_unix does not include remember'
  describe file('/etc/pam.d/system-auth') do
    its('content') { should_not match /remember/ }
  end
end

# 290. Ensure pam_unix includes a strong password hashing algorithm
control '290' do
  title 'Ensure pam_unix includes a strong password hashing algorithm'
  describe file('/etc/pam.d/system-auth') do
    its('content') { should match /sha512/ }
  end
end

# 291. Ensure pam_unix includes use_authtok
control '291' do
  title 'Ensure pam_unix includes use_authtok'
  describe file('/etc/pam.d/system-auth') do
    its('content') { should match /use_authtok/ }
  end
end

# 292. Ensure strong password hashing algorithm is configured
control '292' do
  title 'Ensure strong password hashing algorithm is configured'
  describe file('/etc/login.defs') do
    its('content') { should match /ENCRYPT_METHOD SHA512/ }
  end
end

# 293. Ensure root user umask is configured
control '293' do
  title 'Ensure root user umask is configured'
  describe file('/etc/profile') do
    its('content') { should match /umask 077/ }
  end
end

# 294. Ensure root password is set
control '294' do
  title 'Ensure root password is set'
  describe shadow.where(user: 'root') do
    its('password') { should_not eq '*' }
    its('password') { should_not eq '!' }
  end
end

# 295. Ensure nologin is not listed in /etc/shells
control '295' do
  title 'Ensure nologin is not listed in /etc/shells'
  describe file('/etc/shells') do
    its('content') { should_not match /nologin/ }
  end
end

# 296. Ensure only authorized users own audit log files
control '296' do
  title 'Ensure only authorized users own audit log files'
  describe file('/var/log/audit/audit.log') do
    its('owner') { should eq 'root' }
  end
end

# 297. Ensure only authorized groups are assigned ownership of audit log files
control '297' do
  title 'Ensure only authorized groups are assigned ownership of audit log files'
  describe file('/var/log/audit/audit.log') do
    its('group') { should eq 'root' }
  end
end

# 298. Ensure audit configuration files are 640 or more restrictive
control '298' do
  title 'Ensure audit configuration files are 640 or more restrictive'
  describe file('/etc/audit/audit.rules') do
    its('mode') { should cmp '0640' }
  end
end

# 299. Ensure audit configuration files are owned by root
control '299' do
  title 'Ensure audit configuration files are owned by root'
  describe file('/etc/audit/audit.rules') do
    its('owner') { should eq 'root' }
  end
end

# 300. Ensure audit configuration files belong to group root
control '300' do
  title 'Ensure audit configuration files belong to group root'
  describe file('/etc/audit/audit.rules') do
    its('group') { should eq 'root' }
  end
end

# 301. Ensure audit tools belong to group root
control '301' do
  title 'Ensure audit tools belong to group root'
  describe file('/sbin/auditctl') do
    its('group') { should eq 'root' }
  end
end

# 302. Ensure permissions on /etc/shells are configured
control '302' do
  title 'Ensure permissions on /etc/shells are configured'
  describe file('/etc/shells') do
    its('mode') { should cmp '0644' }
  end
end

# 303. Ensure permissions on /etc/security/opasswd are configured
control '303' do
  title 'Ensure permissions on /etc/security/opasswd are configured'
  describe file('/etc/security/opasswd') do
    its('mode') { should cmp '0640' }
  end
end

# 304. Ensure local interactive user home directories are configured
control '304' do
  title 'Ensure local interactive user home directories are configured'
  describe file('/etc/login.defs') do
    its('content') { should match /CREATE_HOME yes/ }
  end
end

# 305. Ensure default encryption scheme is not used for password storage
control '305' do
  title 'Ensure default encryption scheme is not used for password storage'
  describe file('/etc/login.defs') do
    its('content') { should_not match /ENCRYPT_METHOD DES/ }
  end
end

# 306. Ensure active User IDs which were not logged in for more than 90 days or never is to be disabled
control '306' do
  title 'Ensure active User IDs which were not logged in for more than 90 days or never is to be disabled'
  describe command('lastlog') do
    its('stdout') { should_not match /Never logged in/ }
  end
end

# 307. Ensure Hidden files permissions is set to 640
control '307' do
  title 'Ensure Hidden files permissions is set to 640'
  describe command('find / -type f -name ".*"') do
    its('stdout') { should match /.*640.*/ }
  end
end

# 308. Ensure no users to be part of wheel group
control '308' do
  title 'Ensure no users to be part of wheel group'
  describe command('getent group wheel') do
    its('stdout') { should eq '' }
  end
end

# 309. Ensure Users should not be added with full privileges in sudoers file.
control '309' do
  title 'Ensure Users should not be added with full privileges in sudoers file.'
  describe file('/etc/sudoers') do
    its('content') { should_not match /ALL=(ALL) ALL/ }
  end
end

# 310. Ensure interactive login is disabled for default system accounts
control '310' do
  title 'Ensure interactive login is disabled for default system accounts'
  describe file('/etc/passwd') do
    its('content') { should_not match /nologin/ }
  end
end

