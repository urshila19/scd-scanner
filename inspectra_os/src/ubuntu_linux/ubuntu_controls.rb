# Security controls for Ubuntu

# 1. Ensure mounting of cramfs filesystems is disabled
control 'ubuntu-cramfs-disabled' do
  impact 1.0
  title 'Ensure mounting of cramfs filesystems is disabled'
  desc 'The cramfs filesystem should not be mountable.'
  describe file('/etc/modprobe.d/cramfs.conf') do
    its('content') { should match(/^install cramfs /bin/true$/) }
  end
end

# 2. Ensure mounting of freevxfs filesystems is disabled
control 'ubuntu-freevxfs-disabled' do
  impact 1.0
  title 'Ensure mounting of freevxfs filesystems is disabled'
  desc 'The freevxfs filesystem should not be mountable.'
  describe file('/etc/modprobe.d/freevxfs.conf') do
    its('content') { should match(/^install freevxfs /bin/true$/) }
  end
end

# 3. Ensure mounting of jffs2 filesystems is disabled
control 'ubuntu-jffs2-disabled' do
  impact 1.0
  title 'Ensure mounting of jffs2 filesystems is disabled'
  desc 'The jffs2 filesystem should not be mountable.'
  describe file('/etc/modprobe.d/jffs2.conf') do
    its('content') { should match(/^install jffs2 /bin/true$/) }
  end
end

# 4. Ensure mounting of hfs filesystems is disabled
control 'ubuntu-hfs-disabled' do
  impact 1.0
  title 'Ensure mounting of hfs filesystems is disabled'
  desc 'The hfs filesystem should not be mountable.'
  describe file('/etc/modprobe.d/hfs.conf') do
    its('content') { should match(/^install hfs /bin/true$/) }
  end
end

# 5. Ensure mounting of hfsplus filesystems is disabled
control 'ubuntu-hfsplus-disabled' do
  impact 1.0
  title 'Ensure mounting of hfsplus filesystems is disabled'
  desc 'The hfsplus filesystem should not be mountable.'
  describe file('/etc/modprobe.d/hfsplus.conf') do
    its('content') { should match(/^install hfsplus /bin/true$/) }
  end
end

# 6. Ensure mounting of squashfs filesystems is disabled
control 'ubuntu-squashfs-disabled' do
  impact 1.0
  title 'Ensure mounting of squashfs filesystems is disabled'
  desc 'The squashfs filesystem should not be mountable.'
  describe file('/etc/modprobe.d/squashfs.conf') do
    its('content') { should match(/^install squashfs /bin/true$/) }
  end
end

# 7. Ensure mounting of udf filesystems is disabled
control 'ubuntu-udf-disabled' do
  impact 1.0
  title 'Ensure mounting of udf filesystems is disabled'
  desc 'The udf filesystem should not be mountable.'
  describe file('/etc/modprobe.d/udf.conf') do
    its('content') { should match(/^install udf /bin/true$/) }
  end
end

# 8. Ensure mounting of FAT filesystems is limited
control 'ubuntu-fat-limited' do
  impact 1.0
  title 'Ensure mounting of FAT filesystems is limited'
  desc 'The FAT filesystem should have limited mounting options.'
  describe file('/etc/modprobe.d/fat.conf') do
    its('content') { should match(/^install fat /bin/true$/) }
  end
end

# 9. Ensure /tmp is configured
control 'ubuntu-tmp-configured' do
  impact 1.0
  title 'Ensure /tmp is configured'
  desc 'The /tmp directory should be properly configured.'
  describe mount('/tmp') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
    its('options') { should include 'nosuid' }
    its('options') { should include 'noexec' }
  end
end

# 10. Ensure separate partition exists for /var
control 'ubuntu-var-partition-exists' do
  impact 1.0
  title 'Ensure separate partition exists for /var'
  desc 'The /var directory should have a separate partition.'
  describe mount('/var') do
    it { should be_mounted }
  end
end

# 11. Ensure separate partition exists for /home
control 'ubuntu-home-partition-exists' do
  impact 1.0
  title 'Ensure separate partition exists for /home'
  desc 'The /home directory should have a separate partition.'
  describe mount('/home') do
    it { should be_mounted }
  end
end

# 12. Ensure nodev option set on /dev/shm partition
control 'ubuntu-nodev-on-dev-shm' do
  impact 1.0
  title 'Ensure nodev option set on /dev/shm partition'
  desc 'The nodev option should be set on /dev/shm.'
  describe mount('/dev/shm') do
    its('options') { should include 'nodev' }
  end
end

# 13. Ensure nosuid option set on /dev/shm partition
control 'ubuntu-nosuid-on-dev-shm' do
  impact 1.0
  title 'Ensure nosuid option set on /dev/shm partition'
  desc 'The nosuid option should be set on /dev/shm.'
  describe mount('/dev/shm') do
    its('options') { should include 'nosuid' }
  end
end

# 14. Ensure noexec option set on /dev/shm partition
control 'ubuntu-noexec-on-dev-shm' do
  impact 1.0
  title 'Ensure noexec option set on /dev/shm partition'
  desc 'The noexec option should be set on /dev/shm.'
  describe mount('/dev/shm') do
    its('options') { should include 'noexec' }
  end
end

# 15. Ensure nodev option set on removable media partitions
control 'ubuntu-nodev-on-removable-media' do
  impact 1.0
  title 'Ensure nodev option set on removable media partitions'
  desc 'The nodev option should be set on removable media partitions.'
  describe mount('/media') do
    its('options') { should include 'nodev' }
  end
end

# 16. Ensure nosuid option set on removable media partitions
control 'ubuntu-nosuid-on-removable-media' do
  impact 1.0
  title 'Ensure nosuid option set on removable media partitions'
  desc 'The nosuid option should be set on removable media partitions.'
  describe mount('/media') do
    its('options') { should include 'nosuid' }
  end
end

# 17. Ensure noexec option set on removable media partitions
control 'ubuntu-noexec-on-removable-media' do
  impact 1.0
  title 'Ensure noexec option set on removable media partitions'
  desc 'The noexec option should be set on removable media partitions.'
  describe mount('/media') do
    its('options') { should include 'noexec' }
  end
end

# 18. Ensure sticky bit is set on all world-writable directories
control 'ubuntu-sticky-bit-set' do
  impact 1.0
  title 'Ensure sticky bit is set on all world-writable directories'
  desc 'The sticky bit should be set on all world-writable directories.'
  command('find / -type d -perm -002').stdout.split.each do |dir|
    describe file(dir) do
      its('mode') { should cmp '01777' }
    end
  end
end

# 19. Disable Automounting
control 'ubuntu-disable-automounting' do
  impact 1.0
  title 'Disable Automounting'
  desc 'Automounting should be disabled.'
  describe file('/etc/systemd/system.conf') do
    its('content') { should match(/^automount=no$/) }
  end
end

# 20. Disable USB Storage
control 'ubuntu-disable-usb-storage' do
  impact 1.0
  title 'Disable USB Storage'
  desc 'USB storage should be disabled.'
  describe file('/etc/modprobe.d/usb-storage.conf') do
    its('content') { should match(/^install usb-storage /bin/true$/) }
  end
end

# 21. Ensure GPG keys are configured
control 'ubuntu-gpg-keys-configured' do
  impact 1.0
  title 'Ensure GPG keys are configured'
  desc 'GPG keys should be properly configured.'
  describe file('/etc/apt/trusted.gpg') do
    it { should exist }
  end
end

# 22. Ensure sudo is installed
control 'ubuntu-sudo-installed' do
  impact 1.0
  title 'Ensure sudo is installed'
  desc 'The sudo package should be installed.'
  describe package('sudo') do
    it { should be_installed }
  end
end

# 23. Ensure sudo commands use pty
control 'ubuntu-sudo-commands-pty' do
  impact 1.0
  title 'Ensure sudo commands use pty'
  desc 'Sudo commands should use a pseudo-terminal.'
  describe file('/etc/sudoers') do
    its('content') { should match(/^Defaults\s+!requiretty$/) }
  end
end

# 24. Ensure sudo log file exists
control 'ubuntu-sudo-log-file' do
  impact 1.0
  title 'Ensure sudo log file exists'
  desc 'A log file for sudo commands should exist.'
  describe file('/var/log/sudo.log') do
    it { should exist }
  end
end

# 25. Ensure AIDE is installed
control 'ubuntu-aide-installed' do
  impact 1.0
  title 'Ensure AIDE is installed'
  desc 'The AIDE package should be installed.'
  describe package('aide') do
    it { should be_installed }
  end
end

# 26. Ensure filesystem integrity is regularly checked
control 'ubuntu-filesystem-integrity-check' do
  impact 1.0
  title 'Ensure filesystem integrity is regularly checked'
  desc 'Filesystem integrity should be checked regularly.'
  describe cron do
    its('commands') { should include '/usr/bin/aide --check' }
  end
end

# 27. Ensure permissions on bootloader config are configured
control 'ubuntu-bootloader-permissions' do
  impact 1.0
  title 'Ensure permissions on bootloader config are configured'
  desc 'Permissions on bootloader configuration files should be properly set.'
  describe file('/boot/grub/grub.cfg') do
    it { should be_owned_by 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# 28. Ensure interactive boot is not enabled
control 'ubuntu-interactive-boot-disabled' do
  impact 1.0
  title 'Ensure interactive boot is not enabled'
  desc 'Interactive boot should be disabled.'
  describe file('/etc/default/grub') do
    its('content') { should_not match(/GRUB_CMDLINE_LINUX=.*single/) }
  end
end

# 29. Ensure XD/NX support is enabled
control 'ubuntu-xd-nx-enabled' do
  impact 1.0
  title 'Ensure XD/NX support is enabled'
  desc 'XD/NX support should be enabled.'
  describe kernel_parameter('noexec') do
    its('value') { should eq 'on' }
  end
end

# 30. Ensure address space layout randomization (ASLR) is enabled
control 'ubuntu-aslr-enabled' do
  impact 1.0
  title 'Ensure address space layout randomization (ASLR) is enabled'
  desc 'ASLR should be enabled.'
  describe kernel_parameter('randomize_va_space') do
    its('value') { should eq '2' }
  end
end

# 31. Ensure prelink is disabled
control 'ubuntu-prelink-disabled' do
  impact 1.0
  title 'Ensure prelink is disabled'
  desc 'Prelink should be disabled.'
  describe package('prelink') do
    it { should_not be_installed }
  end
end

# 32. Ensure core dumps are restricted
control 'ubuntu-core-dumps-restricted' do
  impact 1.0
  title 'Ensure core dumps are restricted'
  desc 'Core dumps should be restricted.'
  describe file('/etc/security/limits.conf') do
    its('content') { should match(/\*\s+hard\s+core\s+0/) }
  end
end

# 33. Ensure AppArmor is installed
control 'ubuntu-apparmor-installed' do
  impact 1.0
  title 'Ensure AppArmor is installed'
  desc 'The AppArmor package should be installed.'
  describe package('apparmor') do
    it { should be_installed }
  end
end

# 34. Ensure AppArmor is enabled in the bootloader configuration
control 'ubuntu-apparmor-enabled-bootloader' do
  impact 1.0
  title 'Ensure AppArmor is enabled in the bootloader configuration'
  desc 'AppArmor should be enabled in the bootloader configuration.'
  describe file('/etc/default/grub') do
    its('content') { should match(/GRUB_CMDLINE_LINUX=.*apparmor=1/) }
  end
end

# 35. Ensure all AppArmor Profiles are in enforce or complain mode
control 'ubuntu-apparmor-profiles-mode' do
  impact 1.0
  title 'Ensure all AppArmor Profiles are in enforce or complain mode'
  desc 'All AppArmor profiles should be in enforce or complain mode.'
  describe command('apparmor_status') do
    its('stdout') { should match(/profiles are in enforce mode|profiles are in complain mode/) }
  end
end

# 36. Ensure all AppArmor Profiles are enforcing
control 'ubuntu-apparmor-profiles-enforcing' do
  impact 1.0
  title 'Ensure all AppArmor Profiles are enforcing'
  desc 'All AppArmor profiles should be enforcing.'
  describe command('apparmor_status') do
    its('stdout') { should match(/profiles are in enforce mode/) }
  end
end

# 37. Ensure message of the day is configured properly
control 'ubuntu-motd-configured' do
  impact 1.0
  title 'Ensure message of the day is configured properly'
  desc 'The message of the day should be properly configured.'
  describe file('/etc/motd') do
    its('content') { should match(/Authorized users only/) }
  end
end

# 38. Ensure local login warning banner is configured properly
control 'ubuntu-local-login-banner' do
  impact 1.0
  title 'Ensure local login warning banner is configured properly'
  desc 'The local login warning banner should be properly configured.'
  describe file('/etc/issue') do
    its('content') { should match(/Authorized users only/) }
  end
end

# 39. Ensure remote login warning banner is configured properly
control 'ubuntu-remote-login-banner' do
  impact 1.0
  title 'Ensure remote login warning banner is configured properly'
  desc 'The remote login warning banner should be properly configured.'
  describe file('/etc/issue.net') do
    its('content') { should match(/Authorized users only/) }
  end
end

# 40. Ensure permissions on /etc/motd are configured
control 'ubuntu-motd-permissions' do
  impact 1.0
  title 'Ensure permissions on /etc/motd are configured'
  desc 'Permissions on /etc/motd should be properly configured.'
  describe file('/etc/motd') do
    it { should be_owned_by 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# 41. Ensure permissions on /etc/issue are configured
control 'ubuntu-issue-permissions' do
  impact 1.0
  title 'Ensure permissions on /etc/issue are configured'
  desc 'Permissions on /etc/issue should be properly configured.'
  describe file('/etc/issue') do
    it { should be_owned_by 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# 42. Ensure permissions on /etc/issue.net are configured
control 'ubuntu-issue-net-permissions' do
  impact 1.0
  title 'Ensure permissions on /etc/issue.net are configured'
  desc 'Permissions on /etc/issue.net should be properly configured.'
  describe file('/etc/issue.net') do
    it { should be_owned_by 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# 43. Ensure GDM login banner is configured
control 'ubuntu-gdm-login-banner' do
  impact 1.0
  title 'Ensure GDM login banner is configured'
  desc 'The GDM login banner should be properly configured.'
  describe file('/etc/gdm3/greeter.dconf-defaults') do
    its('content') { should match(/banner-message-enable=true/) }
    its('content') { should match(/banner-message-text=/) }
  end
end

# 44. Ensure xinetd is not installed
control 'ubuntu-xinetd-not-installed' do
  impact 1.0
  title 'Ensure xinetd is not installed'
  desc 'The xinetd package should not be installed.'
  describe package('xinetd') do
    it { should_not be_installed }
  end
end

# 45. Ensure openbsd-inetd is not installed
control 'ubuntu-openbsd-inetd-not-installed' do
  impact 1.0
  title 'Ensure openbsd-inetd is not installed'
  desc 'The openbsd-inetd package should not be installed.'
  describe package('openbsd-inetd') do
    it { should_not be_installed }
  end
end

# 46. Ensure time synchronization is in use
control 'ubuntu-time-synchronization' do
  impact 1.0
  title 'Ensure time synchronization is in use'
  desc 'Time synchronization should be enabled.'
  describe service('systemd-timesyncd') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 47. Ensure systemd-timesyncd is configured
control 'ubuntu-systemd-timesyncd-configured' do
  impact 1.0
  title 'Ensure systemd-timesyncd is configured'
  desc 'The systemd-timesyncd service should be properly configured.'
  describe file('/etc/systemd/timesyncd.conf') do
    its('content') { should match(/NTP=/) }
    its('content') { should match(/FallbackNTP=/) }
  end
end

# 48. Ensure chrony is configured
control 'ubuntu-chrony-configured' do
  impact 1.0
  title 'Ensure chrony is configured'
  desc 'The chrony service should be properly configured.'
  describe file('/etc/chrony/chrony.conf') do
    its('content') { should match(/server/) }
  end
end

# 49. Ensure ntp is configured
control 'ubuntu-ntp-configured' do
  impact 1.0
  title 'Ensure ntp is configured'
  desc 'The ntp service should be properly configured.'
  describe file('/etc/ntp.conf') do
    its('content') { should match(/server/) }
  end
end

# 50. Ensure X Window System is not installed
control 'ubuntu-x-window-system-not-installed' do
  impact 1.0
  title 'Ensure X Window System is not installed'
  desc 'The X Window System should not be installed.'
  describe package('xserver-xorg') do
    it { should_not be_installed }
  end
end

# 51. Ensure Avahi Server is not enabled
control 'ubuntu-avahi-server-not-enabled' do
  impact 1.0
  title 'Ensure Avahi Server is not enabled'
  desc 'The Avahi Server should not be enabled.'
  describe service('avahi-daemon') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 52. Ensure CUPS is not enabled
control 'ubuntu-cups-not-enabled' do
  impact 1.0
  title 'Ensure CUPS is not enabled'
  desc 'The CUPS service should not be enabled.'
  describe service('cups') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 53. Ensure DHCP Server is not enabled
control 'ubuntu-dhcp-server-not-enabled' do
  impact 1.0
  title 'Ensure DHCP Server is not enabled'
  desc 'The DHCP Server should not be enabled.'
  describe service('isc-dhcp-server') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 54. Ensure LDAP server is not enabled
control 'ubuntu-ldap-server-not-enabled' do
  impact 1.0
  title 'Ensure LDAP server is not enabled'
  desc 'The LDAP server should not be enabled.'
  describe service('slapd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 55. Ensure NFS and RPC are not enabled
control 'ubuntu-nfs-rpc-not-enabled' do
  impact 1.0
  title 'Ensure NFS and RPC are not enabled'
  desc 'The NFS and RPC services should not be enabled.'
  describe service('nfs-server') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
  describe service('rpcbind') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 56. Ensure DNS Server is not enabled
control 'ubuntu-dns-server-not-enabled' do
  impact 1.0
  title 'Ensure DNS Server is not enabled'
  desc 'The DNS Server should not be enabled.'
  describe service('bind9') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 57. Ensure FTP Server is not enabled
control 'ubuntu-ftp-server-not-enabled' do
  impact 1.0
  title 'Ensure FTP Server is not enabled'
  desc 'The FTP Server should not be enabled.'
  describe service('vsftpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 58. Ensure HTTP server is not enabled
control 'ubuntu-http-server-not-enabled' do
  impact 1.0
  title 'Ensure HTTP server is not enabled'
  desc 'The HTTP server should not be enabled.'
  describe service('apache2') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 59. Ensure email services are not enabled
control 'ubuntu-email-services-not-enabled' do
  impact 1.0
  title 'Ensure email services are not enabled'
  desc 'Email services should not be enabled.'
  describe service('postfix') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 60. Ensure Samba is not enabled
control 'ubuntu-samba-not-enabled' do
  impact 1.0
  title 'Ensure Samba is not enabled'
  desc 'The Samba service should not be enabled.'
  describe service('smbd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 61. Ensure HTTP Proxy Server is not enabled
control 'ubuntu-http-proxy-server-not-enabled' do
  impact 1.0
  title 'Ensure HTTP Proxy Server is not enabled'
  desc 'The HTTP Proxy Server should not be enabled.'
  describe service('squid') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 62. Ensure SNMP Server is not enabled
control 'ubuntu-snmp-server-not-enabled' do
  impact 1.0
  title 'Ensure SNMP Server is not enabled'
  desc 'The SNMP Server should not be enabled.'
  describe service('snmpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 63. Ensure mail transfer agent is configured for local-only mode
control 'ubuntu-mail-transfer-agent-local-only' do
  impact 1.0
  title 'Ensure mail transfer agent is configured for local-only mode'
  desc 'The mail transfer agent should be configured for local-only mode.'
  describe file('/etc/postfix/main.cf') do
    its('content') { should match(/^inet_interfaces = loopback-only$/) }
  end
end

# 64. Ensure rsync service is not enabled
control 'ubuntu-rsync-service-not-enabled' do
  impact 1.0
  title 'Ensure rsync service is not enabled'
  desc 'The rsync service should not be enabled.'
  describe service('rsync') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 65. Ensure NIS Server is not enabled
control 'ubuntu-nis-server-not-enabled' do
  impact 1.0
  title 'Ensure NIS Server is not enabled'
  desc 'The NIS Server should not be enabled.'
  describe service('ypserv') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 66. Ensure NIS Client is not installed
control 'ubuntu-nis-client-not-installed' do
  impact 1.0
  title 'Ensure NIS Client is not installed'
  desc 'The NIS Client should not be installed.'
  describe package('nis') do
    it { should_not be_installed }
  end
end

# 67. Ensure rsh client is not installed
control 'ubuntu-rsh-client-not-installed' do
  impact 1.0
  title 'Ensure rsh client is not installed'
  desc 'The rsh client should not be installed.'
  describe package('rsh-client') do
    it { should_not be_installed }
  end
end

# 68. Ensure talk client is not installed
control 'ubuntu-talk-client-not-installed' do
  impact 1.0
  title 'Ensure talk client is not installed'
  desc 'The talk client should not be installed.'
  describe package('talk') do
    it { should_not be_installed }
  end
end

# 69. Ensure LDAP client is not installed
control 'ubuntu-ldap-client-not-installed' do
  impact 1.0
  title 'Ensure LDAP client is not installed'
  desc 'The LDAP client should not be installed.'
  describe package('ldap-utils') do
    it { should_not be_installed }
  end
end

# 70. Ensure packet redirect sending is disabled
control 'ubuntu-packet-redirect-disabled' do
  impact 1.0
  title 'Ensure packet redirect sending is disabled'
  desc 'Packet redirect sending should be disabled.'
  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.send_redirects') do
    its('value') { should eq 0 }
  end
end

# 71. Ensure IP forwarding is disabled
control 'ubuntu-ip-forwarding-disabled' do
  impact 1.0
  title 'Ensure IP forwarding is disabled'
  desc 'IP forwarding should be disabled.'
  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv6.conf.all.forwarding') do
    its('value') { should eq 0 }
  end
end

# 72. Ensure source routed packets are not accepted
control 'ubuntu-source-routed-packets-not-accepted' do
  impact 1.0
  title 'Ensure source routed packets are not accepted'
  desc 'Source routed packets should not be accepted.'
  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.accept_source_route') do
    its('value') { should eq 0 }
  end
end

# 73. Ensure ICMP redirects are not accepted
control 'ubuntu-icmp-redirects-not-accepted' do
  impact 1.0
  title 'Ensure ICMP redirects are not accepted'
  desc 'ICMP redirects should not be accepted.'
  describe kernel_parameter('net.ipv4.conf.all.accept_redirects') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.accept_redirects') do
    its('value') { should eq 0 }
  end
end

# 74. Ensure secure ICMP redirects are not accepted
control 'ubuntu-secure-icmp-redirects-not-accepted' do
  impact 1.0
  title 'Ensure secure ICMP redirects are not accepted'
  desc 'Secure ICMP redirects should not be accepted.'
  describe kernel_parameter('net.ipv4.conf.all.secure_redirects') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.secure_redirects') do
    its('value') { should eq 0 }
  end
end

# 75. Ensure suspicious packets are logged
control 'ubuntu-suspicious-packets-logged' do
  impact 1.0
  title 'Ensure suspicious packets are logged'
  desc 'Suspicious packets should be logged.'
  describe kernel_parameter('net.ipv4.conf.all.log_martians') do
    its('value') { should eq 1 }
  end
end

# 76. Ensure broadcast ICMP requests are ignored
control 'ubuntu-broadcast-icmp-requests-ignored' do
  impact 1.0
  title 'Ensure broadcast ICMP requests are ignored'
  desc 'Broadcast ICMP requests should be ignored.'
  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should eq 1 }
  end
end

# 77. Ensure bogus ICMP responses are ignored
control 'ubuntu-bogus-icmp-responses-ignored' do
  impact 1.0
  title 'Ensure bogus ICMP responses are ignored'
  desc 'Bogus ICMP responses should be ignored.'
  describe kernel_parameter('net.ipv4.icmp_ignore_bogus_error_responses') do
    its('value') { should eq 1 }
  end
end

# 78. Ensure Reverse Path Filtering is enabled
control 'ubuntu-reverse-path-filtering-enabled' do
  impact 1.0
  title 'Ensure Reverse Path Filtering is enabled'
  desc 'Reverse Path Filtering should be enabled.'
  describe kernel_parameter('net.ipv4.conf.all.rp_filter') do
    its('value') { should eq 1 }
  end
  describe kernel_parameter('net.ipv4.conf.default.rp_filter') do
    its('value') { should eq 1 }
  end
end

# 79. Ensure TCP SYN Cookies is enabled
control 'ubuntu-tcp-syn-cookies-enabled' do
  impact 1.0
  title 'Ensure TCP SYN Cookies is enabled'
  desc 'TCP SYN Cookies should be enabled.'
  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should eq 1 }
  end
end

# 80. Ensure IPv6 router advertisements are not accepted
control 'ubuntu-ipv6-router-advertisements-not-accepted' do
  impact 1.0
  title 'Ensure IPv6 router advertisements are not accepted'
  desc 'IPv6 router advertisements should not be accepted.'
  describe kernel_parameter('net.ipv6.conf.all.accept_ra') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv6.conf.default.accept_ra') do
    its('value') { should eq 0 }
  end
end

# 81. Ensure TCP Wrappers is installed
control 'ubuntu-tcp-wrappers-installed' do
  impact 1.0
  title 'Ensure TCP Wrappers is installed'
  desc 'TCP Wrappers should be installed.'
  describe package('tcpd') do
    it { should be_installed }
  end
end

# 82. Ensure permissions on /etc/hosts.allow are configured
control 'ubuntu-hosts-allow-permissions' do
  impact 1.0
  title 'Ensure permissions on /etc/hosts.allow are configured'
  desc 'Permissions on /etc/hosts.allow should be properly configured.'
  describe file('/etc/hosts.allow') do
    it { should be_owned_by 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# 83. Ensure permissions on /etc/hosts.deny are configured
control 'ubuntu-hosts-deny-permissions' do
  impact 1.0
  title 'Ensure permissions on /etc/hosts.deny are configured'
  desc 'Permissions on /etc/hosts.deny should be properly configured.'
  describe file('/etc/hosts.deny') do
    it { should be_owned_by 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# 84. Ensure DCCP is disabled
control 'ubuntu-dccp-disabled' do
  impact 1.0
  title 'Ensure DCCP is disabled'
  desc 'DCCP should be disabled.'
  describe kernel_module('dccp') do
    it { should_not be_loaded }
  end
end

# 85. Ensure SCTP is disabled
control 'ubuntu-sctp-disabled' do
  impact 1.0
  title 'Ensure SCTP is disabled'
  desc 'SCTP should be disabled.'
  describe kernel_module('sctp') do
    it { should_not be_loaded }
  end
end

# 86. Ensure RDS is disabled
control 'ubuntu-rds-disabled' do
  impact 1.0
  title 'Ensure RDS is disabled'
  desc 'RDS should be disabled.'
  describe kernel_module('rds') do
    it { should_not be_loaded }
  end
end

# 87. Ensure TIPC is disabled
control 'ubuntu-tipc-disabled' do
  impact 1.0
  title 'Ensure TIPC is disabled'
  desc 'TIPC should be disabled.'
  describe kernel_module('tipc') do
    it { should_not be_loaded }
  end
end

# 88. Ensure wireless interfaces are disabled
control 'ubuntu-wireless-interfaces-disabled' do
  impact 1.0
  title 'Ensure wireless interfaces are disabled'
  desc 'Wireless interfaces should be disabled.'
  describe command('nmcli radio wifi') do
    its('stdout') { should match(/disabled/) }
  end
end

# 89. Ensure auditd is installed
control 'ubuntu-auditd-installed' do
  impact 1.0
  title 'Ensure auditd is installed'
  desc 'The auditd package should be installed.'
  describe package('auditd') do
    it { should be_installed }
  end
end

# 90. Ensure auditd service is enabled
control 'ubuntu-auditd-service-enabled' do
  impact 1.0
  title 'Ensure auditd service is enabled'
  desc 'The auditd service should be enabled.'
  describe service('auditd') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 91. Ensure auditing for processes that start prior to auditd is enabled
control 'ubuntu-auditd-prior-processes-enabled' do
  impact 1.0
  title 'Ensure auditing for processes that start prior to auditd is enabled'
  desc 'Auditing for processes that start prior to auditd should be enabled.'
  describe kernel_parameter('audit=1') do
    its('value') { should eq 1 }
  end
end

# 92. Ensure audit_backlog_limit is sufficient
control 'ubuntu-audit-backlog-limit-sufficient' do
  impact 1.0
  title 'Ensure audit_backlog_limit is sufficient'
  desc 'The audit_backlog_limit should be sufficient.'
  describe kernel_parameter('audit_backlog_limit') do
    its('value') { should be >= 8192 }
  end
end

# 93. Ensure audit log storage size is configured
control 'ubuntu-audit-log-storage-size-configured' do
  impact 1.0
  title 'Ensure audit log storage size is configured'
  desc 'Audit log storage size should be configured.'
  describe file('/etc/audit/auditd.conf') do
    its('content') { should match(/^max_log_file = \d+/) }
  end
end

# 94. Ensure audit logs are not automatically deleted
control 'ubuntu-audit-logs-not-deleted' do
  impact 1.0
  title 'Ensure audit logs are not automatically deleted'
  desc 'Audit logs should not be automatically deleted.'
  describe file('/etc/audit/auditd.conf') do
    its('content') { should match(/^max_log_file_action = keep_logs$/) }
  end
end

# 95. Ensure events that modify date and time information are collected
control 'ubuntu-audit-date-time-modification-events' do
  impact 1.0
  title 'Ensure events that modify date and time information are collected'
  desc 'Events that modify date and time information should be collected.'
  describe auditd_rules do
    its('lines') { should include('-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change') }
    its('lines') { should include('-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change') }
  end
end

# 96. Ensure events that modify user/group information are collected
control 'ubuntu-audit-user-group-modification-events' do
  impact 1.0
  title 'Ensure events that modify user/group information are collected'
  desc 'Events that modify user/group information should be collected.'
  describe auditd_rules do
    its('lines') { should include('-w /etc/group -p wa -k identity') }
    its('lines') { should include('-w /etc/passwd -p wa -k identity') }
    its('lines') { should include('-w /etc/gshadow -p wa -k identity') }
  end
end

# 97. Ensure events that modify the system's network environment are collected
control 'ubuntu-audit-network-environment-modification-events' do
  impact 1.0
  title 'Ensure events that modify the system's network environment are collected'
  desc 'Events that modify the system's network environment should be collected.'
  describe auditd_rules do
    its('lines') { should include('-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network-modify') }
    its('lines') { should include('-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network-modify') }
  end
end

# 98. Ensure events that modify the system's Mandatory Access Controls are collected
control 'ubuntu-audit-mac-modification-events' do
  impact 1.0
  title 'Ensure events that modify the system's Mandatory Access Controls are collected'
  desc 'Events that modify the system's Mandatory Access Controls should be collected.'
  describe auditd_rules do
    its('lines') { should include('-w /etc/selinux/ -p wa -k MAC-policy') }
  end
end

# 99. Ensure login and logout events are collected
control 'ubuntu-audit-login-logout-events' do
  impact 1.0
  title 'Ensure login and logout events are collected'
  desc 'Login and logout events should be collected.'
  describe auditd_rules do
    its('lines') { should include('-w /var/log/faillog -p wa -k logins') }
    its('lines') { should include('-w /var/log/lastlog -p wa -k logins') }
  end
end

# 100. Ensure session initiation information is collected
control 'ubuntu-audit-session-initiation-events' do
  impact 1.0
  title 'Ensure session initiation information is collected'
  desc 'Session initiation information should be collected.'
  describe auditd_rules do
    its('lines') { should include('-w /var/run/utmp -p wa -k session') }
    its('lines') { should include('-w /var/log/wtmp -p wa -k session') }
  end
end

# 101. Ensure discretionary access control permission modification events are collected
control 'ubuntu-audit-dac-permission-modification-events' do
  impact 1.0
  title 'Ensure discretionary access control permission modification events are collected'
  desc 'Discretionary access control permission modification events should be collected.'
  describe auditd_rules do
    its('lines') { should include('-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod') }
    its('lines') { should include('-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k perm_mod') }
  end
end

# 102. Ensure unsuccessful unauthorized file access attempts are collected
control 'ubuntu-audit-unsuccessful-file-access-events' do
  impact 1.0
  title 'Ensure unsuccessful unauthorized file access attempts are collected'
  desc 'Unsuccessful unauthorized file access attempts should be collected.'
  describe auditd_rules do
    its('lines') { should include('-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -F exit=-EPERM -k access') }
    its('lines') { should include('-a always,exit -F arch=b32 -S open -S openat -F exit=-EACCES -F exit=-EPERM -k access') }
  end
end

# 103. Ensure use of privileged commands is collected
control 'ubuntu-audit-privileged-commands' do
  impact 1.0
  title 'Ensure use of privileged commands is collected'
  desc 'Use of privileged commands should be collected.'
  describe auditd_rules do
    its('lines') { should include('-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged') }
  end
end

# 104. Ensure successful file system mounts are collected
control 'ubuntu-audit-successful-mount-events' do
  impact 1.0
  title 'Ensure successful file system mounts are collected'
  desc 'Successful file system mounts should be collected.'
  describe auditd_rules do
    its('lines') { should include('-a always,exit -F arch=b64 -S mount -k mounts') }
    its('lines') { should include('-a always,exit -F arch=b32 -S mount -k mounts') }
  end
end

# 105. Ensure file deletion events by users are collected
control 'ubuntu-audit-file-deletion-events' do
  impact 1.0
  title 'Ensure file deletion events by users are collected'
  desc 'File deletion events by users should be collected.'
  describe auditd_rules do
    its('lines') { should include('-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete') }
    its('lines') { should include('-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k delete') }
  end
end

# 106. Ensure changes to system administration scope (sudoers) is collected
control 'ubuntu-audit-sudoers-changes' do
  impact 1.0
  title 'Ensure changes to system administration scope (sudoers) is collected'
  desc 'Changes to system administration scope (sudoers) should be collected.'
  describe auditd_rules do
    its('lines') { should include('-w /etc/sudoers -p wa -k scope') }
  end
end

# 107. Ensure system administrator actions (sudolog) are collected
control 'ubuntu-audit-sudolog-actions' do
  impact 1.0
  title 'Ensure system administrator actions (sudolog) are collected'
  desc 'System administrator actions (sudolog) should be collected.'
  describe auditd_rules do
    its('lines') { should include('-w /var/log/sudo.log -p wa -k actions') }
  end
end

# 108. Ensure kernel module loading and unloading is collected
control 'ubuntu-audit-kernel-module-events' do
  impact 1.0
  title 'Ensure kernel module loading and unloading is collected'
  desc 'Kernel module loading and unloading should be collected.'
  describe auditd_rules do
    its('lines') { should include('-a always,exit -F arch=b64 -S init_module -S delete_module -k modules') }
    its('lines') { should include('-a always,exit -F arch=b32 -S init_module -S delete_module -k modules') }
  end
end

# 109. Ensure the audit configuration is immutable
control 'ubuntu-audit-configuration-immutable' do
  impact 1.0
  title 'Ensure the audit configuration is immutable'
  desc 'The audit configuration should be immutable.'
  describe auditd_rules do
    its('lines') { should include('-e 2') }
  end
end

# 110. Ensure rsyslog is installed
control 'ubuntu-rsyslog-installed' do
  impact 1.0
  title 'Ensure rsyslog is installed'
  desc 'The rsyslog package should be installed.'
  describe package('rsyslog') do
    it { should be_installed }
  end
end

# 111. Ensure rsyslog Service is enabled
control 'ubuntu-rsyslog-service-enabled' do
  impact 1.0
  title 'Ensure rsyslog Service is enabled'
  desc 'The rsyslog service should be enabled.'
  describe service('rsyslog') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 112. Ensure logging is configured
control 'ubuntu-logging-configured' do
  impact 1.0
  title 'Ensure logging is configured'
  desc 'Logging should be properly configured.'
  describe file('/etc/rsyslog.conf') do
    its('content') { should match(/\*.\* @remote-log-host/) }
  end
end

# 113. Ensure rsyslog default file permissions configured
control 'ubuntu-rsyslog-default-permissions-configured' do
  impact 1.0
  title 'Ensure rsyslog default file permissions configured'
  desc 'Rsyslog default file permissions should be configured.'
  describe file('/etc/rsyslog.conf') do
    its('content') { should match(/\$FileCreateMode 0640/) }
  end
end

# 114. Ensure rsyslog is configured to send logs to a remote log host
control 'ubuntu-rsyslog-remote-log-host-configured' do
  impact 1.0
  title 'Ensure rsyslog is configured to send logs to a remote log host'
  desc 'Rsyslog should be configured to send logs to a remote log host.'
  describe file('/etc/rsyslog.conf') do
    its('content') { should match(/\*.\* @remote-log-host/) }
  end
end

# 115. Ensure remote rsyslog messages are only accepted on designated log hosts
control 'ubuntu-rsyslog-remote-messages-designated-hosts' do
  impact 1.0
  title 'Ensure remote rsyslog messages are only accepted on designated log hosts'
  desc 'Remote rsyslog messages should only be accepted on designated log hosts.'
  describe file('/etc/rsyslog.conf') do
    its('content') { should match(/\$AllowedSender TCP, 127.0.0.1/) }
  end
end

# 116. Ensure journald is configured to send logs to rsyslog
control 'ubuntu-journald-send-logs-to-rsyslog' do
  impact 1.0
  title 'Ensure journald is configured to send logs to rsyslog'
  desc 'Journald should be configured to send logs to rsyslog.'
  describe file('/etc/systemd/journald.conf') do
    its('content') { should match(/ForwardToSyslog=yes/) }
  end
end

# 117. Ensure journald is configured to compress large log files
control 'ubuntu-journald-compress-large-logs' do
  impact 1.0
  title 'Ensure journald is configured to compress large log files'
  desc 'Journald should be configured to compress large log files.'
  describe file('/etc/systemd/journald.conf') do
    its('content') { should match(/Compress=yes/) }
  end
end

# 118. Ensure permissions on all logfiles are configured
control 'ubuntu-logfile-permissions-configured' do
  impact 1.0
  title 'Ensure permissions on all logfiles are configured'
  desc 'Permissions on all logfiles should be properly configured.'
  describe command('find /var/log -type f') do
    its('stdout') { should_not match(/\S+\s+\S+\s+\S+\s+w/) }
  end
end

# 119. Ensure logrotate is configured
control 'ubuntu-logrotate-configured' do
  impact 1.0
  title 'Ensure logrotate is configured'
  desc 'Logrotate should be properly configured.'
  describe file('/etc/logrotate.conf') do
    its('content') { should match(/rotate \d+/) }
  end
end

# 120. Ensure cron daemon is enabled
control 'ubuntu-cron-daemon-enabled' do
  impact 1.0
  title 'Ensure cron daemon is enabled'
  desc 'The cron daemon should be enabled.'
  describe service('cron') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 121. Ensure permissions on /etc/crontab are configured
control 'ubuntu-crontab-permissions' do
  impact 1.0
  title 'Ensure permissions on /etc/crontab are configured'
  desc 'Permissions on /etc/crontab should be properly configured.'
  describe file('/etc/crontab') do
    it { should be_owned_by 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# 122. Ensure permissions on /etc/cron.hourly are configured
control 'ubuntu-cron-hourly-permissions' do
  impact 1.0
  title 'Ensure permissions on /etc/cron.hourly are configured'
  desc 'Permissions on /etc/cron.hourly should be properly configured.'
  describe file('/etc/cron.hourly') do
    it { should be_owned_by 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# 123. Ensure permissions on /etc/cron.daily are configured
control 'ubuntu-cron-daily-permissions' do
  impact 1.0
  title 'Ensure permissions on /etc/cron.daily are configured'
  desc 'Permissions on /etc/cron.daily should be properly configured.'
  describe file('/etc/cron.daily') do
    it { should be_owned_by 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# 124. Ensure permissions on /etc/cron.weekly are configured
control 'ubuntu-cron-weekly-permissions' do
  impact 1.0
  title 'Ensure permissions on /etc/cron.weekly are configured'
  desc 'Permissions on /etc/cron.weekly should be properly configured.'
  describe file('/etc/cron.weekly') do
    it { should be_owned_by 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# 125. Ensure permissions on /etc/cron.monthly are configured
control 'ubuntu-cron-monthly-permissions' do
  impact 1.0
  title 'Ensure permissions on /etc/cron.monthly are configured'
  desc 'Permissions on /etc/cron.monthly should be properly configured.'
  describe file('/etc/cron.monthly') do
    it { should be_owned_by 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# 126. Ensure permissions on /etc/cron.d are configured
control 'ubuntu-cron-d-permissions' do
  impact 1.0
  title 'Ensure permissions on /etc/cron.d are configured'
  desc 'Permissions on /etc/cron.d should be properly configured.'
  describe file('/etc/cron.d') do
    it { should be_owned_by 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# 127. Ensure at/cron is restricted to authorized users
control 'ubuntu-at-cron-restricted' do
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

# 128. Ensure at is restricted to authorized users
control 'ubuntu-at-restricted' do
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

# 129. Ensure permissions on /etc/ssh/sshd_config are configured
control 'ubuntu-sshd-config-permissions' do
  impact 1.0
  title 'Ensure permissions on /etc/ssh/sshd_config are configured'
  desc 'Permissions on /etc/ssh/sshd_config should be properly configured.'
  describe file('/etc/ssh/sshd_config') do
    it { should be_owned_by 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# 130. Ensure permissions on SSH private host key files are configured
control 'ubuntu-ssh-private-key-permissions' do
  impact 1.0
  title 'Ensure permissions on SSH private host key files are configured'
  desc 'Permissions on SSH private host key files should be properly configured.'
  describe command('find /etc/ssh -type f -name "*key"') do
    its('stdout') { should_not match(/\S+\s+\S+\s+\S+\s+w/) }
  end
end

# 131. Ensure permissions on SSH public host key files are configured
control 'ubuntu-ssh-public-key-permissions' do
  impact 1.0
  title 'Ensure permissions on SSH public host key files are configured'
  desc 'Permissions on SSH public host key files should be properly configured.'
  describe command('find /etc/ssh -type f -name "*.pub"') do
    its('stdout') { should_not match(/\S+\s+\S+\s+\S+\s+w/) }
  end
end

# 132. Ensure SSH Protocol is not set to 1
control 'ubuntu-ssh-protocol-not-1' do
  impact 1.0
  title 'Ensure SSH Protocol is not set to 1'
  desc 'SSH Protocol should not be set to 1.'
  describe sshd_config do
    its('Protocol') { should_not eq '1' }
  end
end

# 133. Ensure SSH LogLevel is appropriate
control 'ubuntu-ssh-loglevel-appropriate' do
  impact 1.0
  title 'Ensure SSH LogLevel is appropriate'
  desc 'SSH LogLevel should be appropriate.'
  describe sshd_config do
    its('LogLevel') { should eq 'INFO' }
  end
end

# 134. Ensure SSH X11 forwarding is disabled
control 'ubuntu-ssh-x11-forwarding-disabled' do
  impact 1.0
  title 'Ensure SSH X11 forwarding is disabled'
  desc 'SSH X11 forwarding should be disabled.'
  describe sshd_config do
    its('X11Forwarding') { should eq 'no' }
  end
end

# 135. Ensure SSH MaxAuthTries is set to 4 or less
control 'ubuntu-ssh-maxauthtries-configured' do
  impact 1.0
  title 'Ensure SSH MaxAuthTries is set to 4 or less'
  desc 'SSH MaxAuthTries should be set to 4 or less.'
  describe sshd_config do
    its('MaxAuthTries') { should be <= 4 }
  end
end

# 136. Ensure SSH IgnoreRhosts is enabled
control 'ubuntu-ssh-ignorerhosts-enabled' do
  impact 1.0
  title 'Ensure SSH IgnoreRhosts is enabled'
  desc 'SSH IgnoreRhosts should be enabled.'
  describe sshd_config do
    its('IgnoreRhosts') { should eq 'yes' }
  end
end

# 137. Ensure SSH HostbasedAuthentication is disabled
control 'ubuntu-ssh-hostbasedauthentication-disabled' do
  impact 1.0
  title 'Ensure SSH HostbasedAuthentication is disabled'
  desc 'SSH HostbasedAuthentication should be disabled.'
  describe sshd_config do
    its('HostbasedAuthentication') { should eq 'no' }
  end
end

# 138. Ensure SSH PermitEmptyPasswords is disabled
control 'ubuntu-ssh-permitemptypasswords-disabled' do
  impact 1.0
  title 'Ensure SSH PermitEmptyPasswords is disabled'
  desc 'SSH PermitEmptyPasswords should be disabled.'
  describe sshd_config do
    its('PermitEmptyPasswords') { should eq 'no' }
  end
end

# 139. Ensure SSH PermitUserEnvironment is disabled
control 'ubuntu-ssh-permituserenvironment-disabled' do
  impact 1.0
  title 'Ensure SSH PermitUserEnvironment is disabled'
  desc 'SSH PermitUserEnvironment should be disabled.'
  describe sshd_config do
    its('PermitUserEnvironment') { should eq 'no' }
  end
end

# 140. Ensure only strong Ciphers are used
control 'ubuntu-ssh-strong-ciphers' do
  impact 1.0
  title 'Ensure only strong Ciphers are used'
  desc 'Only strong Ciphers should be used.'
  describe sshd_config do
    its('Ciphers') { should match(/aes256-ctr,aes192-ctr,aes128-ctr/) }
  end
end

# 141. Ensure only strong MAC algorithms are used
control 'ubuntu-ssh-strong-mac-algorithms' do
  impact 1.0
  title 'Ensure only strong MAC algorithms are used'
  desc 'Only strong MAC algorithms should be used.'
  describe sshd_config do
    its('MACs') { should match(/hmac-sha2-512,hmac-sha2-256,hmac-ripemd160/) }
  end
end

# 142. Ensure only strong Key Exchange algorithms are used
control 'ubuntu-ssh-strong-key-exchange-algorithms' do
  impact 1.0
  title 'Ensure only strong Key Exchange algorithms are used'
  desc 'Only strong Key Exchange algorithms should be used.'
  describe sshd_config do
    its('KexAlgorithms') { should match(/diffie-hellman-group-exchange-sha256/) }
  end
end

# 143. Ensure SSH Idle Timeout Interval is configured
control 'ubuntu-ssh-idle-timeout-configured' do
  impact 1.0
  title 'Ensure SSH Idle Timeout Interval is configured'
  desc 'SSH Idle Timeout Interval should be configured.'
  describe sshd_config do
    its('ClientAliveInterval') { should be <= 300 }
    its('ClientAliveCountMax') { should be <= 3 }
  end
end

# 144. Ensure SSH LoginGraceTime is set to one minute or less
control 'ubuntu-ssh-logingracetime-configured' do
  impact 1.0
  title 'Ensure SSH LoginGraceTime is set to one minute or less'
  desc 'SSH LoginGraceTime should be set to one minute or less.'
  describe sshd_config do
    its('LoginGraceTime') { should be <= 60 }
  end
end

# 145. Ensure SSH warning banner is configured
control 'ubuntu-ssh-warning-banner-configured' do
  impact 1.0
  title 'Ensure SSH warning banner is configured'
  desc 'SSH warning banner should be configured.'
  describe sshd_config do
    its('Banner') { should eq '/etc/issue.net' }
  end
end

# 146. Ensure SSH PAM is enabled
control 'ubuntu-ssh-pam-enabled' do
  impact 1.0
  title 'Ensure SSH PAM is enabled'
  desc 'SSH PAM should be enabled.'
  describe sshd_config do
    its('UsePAM') { should eq 'yes' }
  end
end

# 147. Ensure SSH AllowTcpForwarding is disabled
control 'ubuntu-ssh-allowtcpforwarding-disabled' do
  impact 1.0
  title 'Ensure SSH AllowTcpForwarding is disabled'
  desc 'SSH AllowTcpForwarding should be disabled.'
  describe sshd_config do
    its('AllowTcpForwarding') { should eq 'no' }
  end
end

# 148. Ensure SSH MaxStartups is configured
control 'ubuntu-ssh-maxstartups-configured' do
  impact 1.0
  title 'Ensure SSH MaxStartups is configured'
  desc 'SSH MaxStartups should be configured.'
  describe sshd_config do
    its('MaxStartups') { should eq '10:30:60' }
  end
end

# 149. Ensure password creation requirements are configured
control 'ubuntu-password-creation-requirements-configured' do
  impact 1.0
  title 'Ensure password creation requirements are configured'
  desc 'Password creation requirements should be configured.'
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match(/minlen = 14/) }
    its('content') { should match(/dcredit = -1/) }
    its('content') { should match(/ucredit = -1/) }
    its('content') { should match(/ocredit = -1/) }
    its('content') { should match(/lcredit = -1/) }
  end
end

# 150. Ensure lockout for failed password attempts is configured
control 'ubuntu-password-lockout-configured' do
  impact 1.0
  title 'Ensure lockout for failed password attempts is configured'
  desc 'Lockout for failed password attempts should be configured.'
  describe file('/etc/security/faillock.conf') do
    its('content') { should match(/deny = 5/) }
    its('content') { should match(/unlock_time = 900/) }
  end
end

# 151. Ensure password reuse is limited
control 'ubuntu-password-reuse-limited' do
  impact 1.0
  title 'Ensure password reuse is limited'
  desc 'Password reuse should be limited to prevent security risks.'
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match(/remember = 5/) }
  end
end

# 152. Ensure password hashing algorithm is SHA-512
control 'ubuntu-password-hashing-sha512' do
  impact 1.0
  title 'Ensure password hashing algorithm is SHA-512'
  desc 'Password hashing algorithm should be SHA-512.'
  describe file('/etc/login.defs') do
    its('content') { should match(/ENCRYPT_METHOD SHA512/) }
  end
end

# 153. Ensure password expiration is set to 45 days
control 'ubuntu-password-expiration-45-days' do
  impact 1.0
  title 'Ensure password expiration is set to 45 days'
  desc 'Password expiration should be set to 45 days.'
  describe file('/etc/login.defs') do
    its('content') { should match(/PASS_MAX_DAYS 45/) }
  end
end

# 154. Ensure minimum days between password changes is configured
control 'ubuntu-password-min-days-configured' do
  impact 1.0
  title 'Ensure minimum days between password changes is configured'
  desc 'Minimum days between password changes should be configured.'
  describe file('/etc/login.defs') do
    its('content') { should match(/PASS_MIN_DAYS 1/) }
  end
end

# 155. Ensure password expiration warning days is 7 or more
control 'ubuntu-password-expiration-warning-7-days' do
  impact 1.0
  title 'Ensure password expiration warning days is 7 or more'
  desc 'Password expiration warning days should be 7 or more.'
  describe file('/etc/login.defs') do
    its('content') { should match(/PASS_WARN_AGE 7/) }
  end
end

# 156. Ensure inactive password lock is 30 days or less
control 'ubuntu-password-inactive-lock-30-days' do
  impact 1.0
  title 'Ensure inactive password lock is 30 days or less'
  desc 'Inactive password lock should be 30 days or less.'
  describe file('/etc/default/useradd') do
    its('content') { should match(/INACTIVE=30/) }
  end
end

# 157. Ensure all users last password change date is in the past
control 'ubuntu-password-last-change-date' do
  impact 1.0
  title 'Ensure all users last password change date is in the past'
  desc 'All users last password change date should be in the past.'
  describe command('chage -l root') do
    its('stdout') { should match(/Last password change/) }
  end
end

# 158. Ensure system accounts are secured
control 'ubuntu-system-accounts-secured' do
  impact 1.0
  title 'Ensure system accounts are secured'
  desc 'System accounts should be secured.'
  describe passwd do
    its('users') { should_not include 'nobody' }
  end
end

# 159. Ensure default group for the root account is GID 0
control 'ubuntu-root-default-group-gid-0' do
  impact 1.0
  title 'Ensure default group for the root account is GID 0'
  desc 'Default group for the root account should be GID 0.'
  describe passwd do
    its('gid') { should eq 0 }
  end
end

# 160. Ensure default user umask is 027 or more restrictive
control 'ubuntu-default-user-umask-027' do
  impact 1.0
  title 'Ensure default user umask is 027 or more restrictive'
  desc 'Default user umask should be 027 or more restrictive.'
  describe file('/etc/login.defs') do
    its('content') { should match(/UMASK 027/) }
  end
end

# 161. Ensure default user shell timeout is 900 seconds or less
control 'ubuntu-default-user-shell-timeout-900-seconds' do
  impact 1.0
  title 'Ensure default user shell timeout is 900 seconds or less'
  desc 'Default user shell timeout should be 900 seconds or less.'
  describe file('/etc/profile') do
    its('content') { should match(/TMOUT=900/) }
  end
end

# 162. Ensure access to the su command is restricted
control 'ubuntu-su-command-restricted' do
  impact 1.0
  title 'Ensure access to the su command is restricted'
  desc 'Access to the su command should be restricted.'
  describe file('/etc/pam.d/su') do
    its('content') { should match(/auth required pam_wheel.so use_uid/) }
  end
end

# 163. Ensure permissions on /etc/passwd are configured
control 'ubuntu-permissions-etc-passwd' do
  impact 1.0
  title 'Ensure permissions on /etc/passwd are configured'
  desc 'Permissions on /etc/passwd should be configured.'
  describe file('/etc/passwd') do
    it { should be_readable.by('owner') }
    it { should be_readable.by('group') }
    it { should_not be_readable.by('others') }
  end
end

# 164. Ensure permissions on /etc/gshadow- are configured
control 'ubuntu-permissions-etc-gshadow' do
  impact 1.0
  title 'Ensure permissions on /etc/gshadow- are configured'
  desc 'Permissions on /etc/gshadow- should be configured.'
  describe file('/etc/gshadow-') do
    it { should be_readable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_readable.by('others') }
  end
end

# 165. Ensure permissions on /etc/shadow are configured
control 'ubuntu-permissions-etc-shadow' do
  impact 1.0
  title 'Ensure permissions on /etc/shadow are configured'
  desc 'Permissions on /etc/shadow should be configured.'
  describe file('/etc/shadow') do
    it { should be_readable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_readable.by('others') }
  end
end

# 166. Ensure permissions on /etc/group are configured
control 'ubuntu-permissions-etc-group' do
  impact 1.0
  title 'Ensure permissions on /etc/group are configured'
  desc 'Permissions on /etc/group should be configured.'
  describe file('/etc/group') do
    it { should be_readable.by('owner') }
    it { should be_readable.by('group') }
    it { should_not be_readable.by('others') }
  end
end

# 167. Ensure no world writable files exist
control 'ubuntu-no-world-writable-files' do
  impact 1.0
  title 'Ensure no world writable files exist'
  desc 'No world writable files should exist.'
  describe command('find / -xdev -type f -perm -0002') do
    its('stdout') { should eq '' }
  end
end

# 168. Ensure no unowned files or directories exist
control 'ubuntu-no-unowned-files-directories' do
  impact 1.0
  title 'Ensure no unowned files or directories exist'
  desc 'No unowned files or directories should exist.'
  describe command('find / -xdev -nouser') do
    its('stdout') { should eq '' }
  end
end

# 169. Ensure no ungrouped files or directories exist
control 'ubuntu-no-ungrouped-files-directories' do
  impact 1.0
  title 'Ensure no ungrouped files or directories exist'
  desc 'No ungrouped files or directories should exist.'
  describe command('find / -xdev -nogroup') do
    its('stdout') { should eq '' }
  end
end

# 170. Audit SUID executables
control 'ubuntu-audit-suid-executables' do
  impact 1.0
  title 'Audit SUID executables'
  desc 'SUID executables should be audited.'
  describe command('find / -xdev -type f -perm -4000') do
    its('stdout') { should_not eq '' }
  end
end

# 171. Audit SGID executables
control 'ubuntu-audit-sgid-executables' do
  impact 1.0
  title 'Audit SGID executables'
  desc 'SGID executables should be audited.'
  describe command('find / -xdev -type f -perm -2000') do
    its('stdout') { should_not eq '' }
  end
end

# 172. Ensure password fields are not empty
control 'ubuntu-password-fields-not-empty' do
  impact 1.0
  title 'Ensure password fields are not empty'
  desc 'Password fields should not be empty.'
  describe passwd do
    its('users') { should_not include '' }
  end
end

# 173. Ensure no legacy "+" entries exist in /etc/passwd
control 'ubuntu-no-legacy-entries-passwd' do
  impact 1.0
  title 'Ensure no legacy "+" entries exist in /etc/passwd'
  desc 'No legacy "+" entries should exist in /etc/passwd.'
  describe file('/etc/passwd') do
    its('content') { should_not match(/\+/) }
  end
end

# 174. Ensure all users' home directories exist
control 'ubuntu-users-home-directories-exist' do
  impact 1.0
  title 'Ensure all users home directories exist'
  desc 'All users home directories should exist.'
  describe passwd do
    its('users') { should_not include nil }
  end
end

# 175. Ensure no legacy "+" entries exist in /etc/shadow
control 'ubuntu-no-legacy-entries-shadow' do
  impact 1.0
  title 'Ensure no legacy "+" entries exist in /etc/shadow'
  desc 'No legacy "+" entries should exist in /etc/shadow.'
  describe file('/etc/shadow') do
    its('content') { should_not match(/\+/) }
  end
end

# 176. Ensure no legacy "+" entries exist in /etc/group
control 'ubuntu-no-legacy-entries-group' do
  impact 1.0
  title 'Ensure no legacy "+" entries exist in /etc/group'
  desc 'No legacy "+" entries should exist in /etc/group.'
  describe file('/etc/group') do
    its('content') { should_not match(/\+/) }
  end
end

# 177. Ensure root is the only UID 0 account
control 'ubuntu-root-only-uid-0-account' do
  impact 1.0
  title 'Ensure root is the only UID 0 account'
  desc 'Root should be the only UID 0 account.'
  describe passwd do
    its('users') { should include 'root' }
    its('uids') { should_not include 0 }
  end
end

# 178. Ensure root PATH Integrity
control 'ubuntu-root-path-integrity' do
  impact 1.0
  title 'Ensure root PATH Integrity'
  desc 'Root PATH integrity should be ensured.'
  describe file('/root/.bashrc') do
    its('content') { should_not match(/\./) }
  end
end

# 179. Ensure users home directories permissions are 750 or more restrictive
control 'ubuntu-users-home-directories-permissions-750' do
  impact 1.0
  title 'Ensure users home directories permissions are 750 or more restrictive'
  desc 'Users home directories permissions should be 750 or more restrictive.'
  describe passwd do
    its('users') { should_not include nil }
  end
end

# 180. Ensure users own their home directories
control 'ubuntu-users-own-home-directories' do
  impact 1.0
  title 'Ensure users own their home directories'
  desc 'Users should own their home directories.'
  describe passwd do
    its('users') { should_not include nil }
  end
end

# 181. Ensure users dot files are not group or world writable
control 'ubuntu-users-dot-files-not-writable' do
  impact 1.0
  title 'Ensure users dot files are not group or world writable'
  desc 'Users dot files should not be group or world writable.'
  describe passwd do
    its('users') { should_not include nil }
  end
end

# 182. Ensure no users have .forward files
control 'ubuntu-no-users-forward-files' do
  impact 1.0
  title 'Ensure no users have .forward files'
  desc 'No users should have .forward files.'
  describe passwd do
    its('users') { should_not include nil }
  end
end

# 183. Ensure no users have .netrc files
control 'ubuntu-no-users-netrc-files' do
  impact 1.0
  title 'Ensure no users have .netrc files'
  desc 'No users should have .netrc files.'
  describe passwd do
    its('users') { should_not include nil }
  end
end

# 184. Ensure users .netrc Files are not group or world accessible
control 'ubuntu-users-netrc-files-not-accessible' do
  impact 1.0
  title 'Ensure users .netrc Files are not group or world accessible'
  desc 'Users .netrc Files should not be group or world accessible.'
  describe passwd do
    its('users') { should_not include nil }
  end
end

# 185. Ensure no users have .rhosts files
control 'ubuntu-no-users-rhosts-files' do
  impact 1.0
  title 'Ensure no users have .rhosts files'
  desc 'No users should have .rhosts files.'
  describe passwd do
    its('users') { should_not include nil }
  end
end

# 186. Ensure all groups in /etc/passwd exist in /etc/group
control 'ubuntu-groups-passwd-exist-group' do
  impact 1.0
  title 'Ensure all groups in /etc/passwd exist in /etc/group'
  desc 'All groups in /etc/passwd should exist in /etc/group.'
  describe passwd do
    its('users') { should_not include nil }
  end
end

# 187. Ensure no duplicate UIDs exist
control 'ubuntu-no-duplicate-uids' do
  impact 1.0
  title 'Ensure no duplicate UIDs exist'
  desc 'No duplicate UIDs should exist.'
  describe passwd do
    its('users') { should_not include nil }
  end
end

# 188. Ensure no duplicate GIDs exist
control 'ubuntu-no-duplicate-gids' do
  impact 1.0
  title 'Ensure no duplicate GIDs exist'
  desc 'No duplicate GIDs should exist.'
  describe passwd do
    its('users') { should_not include nil }
  end
end

# 189. Ensure no duplicate user names exist
control 'ubuntu-no-duplicate-user-names' do
  impact 1.0
  title 'Ensure no duplicate user names exist'
  desc 'No duplicate user names should exist.'
  describe passwd do
    its('users') { should_not include nil }
  end
end

# 190. Ensure no duplicate group names exist
control 'ubuntu-no-duplicate-group-names' do
  impact 1.0
  title 'Ensure no duplicate group names exist'
  desc 'No duplicate group names should exist.'
  describe passwd do
    its('users') { should_not include nil }
  end
end

# 191. Ensure shadow group is empty
control 'ubuntu-shadow-group-empty' do
  impact 1.0
  title 'Ensure shadow group is empty'
  desc 'The shadow group should be empty to prevent unauthorized access.'
  describe group('shadow') do
    its('members') { should be_empty }
  end
end

# 192. Ensure rsync service is not installed
control 'ubuntu-rsync-service-not-installed' do
  impact 1.0
  title 'Ensure rsync service is not installed'
  desc 'The rsync service should not be installed.'
  describe package('rsync') do
    it { should_not be_installed }
  end
end

# 193. Ensure nonessential services are removed or masked
control 'ubuntu-nonessential-services-removed-masked' do
  impact 1.0
  title 'Ensure nonessential services are removed or masked'
  desc 'Nonessential services should be removed or masked.'
  describe service('bluetooth') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 194. Ensure logrotate assigns appropriate permissions
control 'ubuntu-logrotate-permissions' do
  impact 1.0
  title 'Ensure logrotate assigns appropriate permissions'
  desc 'Logrotate should assign appropriate permissions to log files.'
  describe file('/etc/logrotate.conf') do
    its('content') { should match(/create 0640 root adm/) }
  end
end

# 195. Ensure system administrator command executions (sudo) are collected
control 'ubuntu-sudo-command-executions-collected' do
  impact 1.0
  title 'Ensure system administrator command executions (sudo) are collected'
  desc 'System administrator command executions should be collected.'
  describe auditd_rules do
    its('lines') { should include('-w /var/log/sudo.log -p wa -k actions') }
  end
end

# 196. Ensure permissions on bootloader config are not overridden
control 'ubuntu-bootloader-config-permissions' do
  impact 1.0
  title 'Ensure permissions on bootloader config are not overridden'
  desc 'Permissions on bootloader config should not be overridden.'
  describe file('/boot/grub/grub.cfg') do
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# 197. Ensure GNOME Display Manager is removed
control 'ubuntu-gnome-display-manager-removed' do
  impact 1.0
  title 'Ensure GNOME Display Manager is removed'
  desc 'GNOME Display Manager should be removed.'
  describe package('gdm') do
    it { should_not be_installed }
  end
end

# 198. Ensure disable-user-list is enabled
control 'ubuntu-disable-user-list-enabled' do
  impact 1.0
  title 'Ensure disable-user-list is enabled'
  desc 'Disable-user-list should be enabled.'
  describe file('/etc/gdm3/greeter.dconf-defaults') do
    its('content') { should match(/disable-user-list=true/) }
  end
end

# 199. Ensure XDCMP is not enabled
control 'ubuntu-xdcmp-not-enabled' do
  impact 1.0
  title 'Ensure XDCMP is not enabled'
  desc 'XDCMP should not be enabled.'
  describe file('/etc/gdm3/custom.conf') do
    its('content') { should match(/Enable=false/) }
  end
end

# 200. Ensure accounts in /etc/passwd use shadowed passwords
control 'ubuntu-shadowed-passwords' do
  impact 1.0
  title 'Ensure accounts in /etc/passwd use shadowed passwords'
  desc 'Accounts in /etc/passwd should use shadowed passwords.'
  describe passwd do
    its('users') { should_not include nil }
  end
end

# 201. Ensure IMAP and POP3 server are not installed
control 'ubuntu-imap-pop3-not-installed' do
  impact 1.0
  title 'Ensure IMAP and POP3 server are not installed'
  desc 'IMAP and POP3 server should not be installed.'
  describe package('dovecot') do
    it { should_not be_installed }
  end
end

# 202. Ensure access to SSH key files is configured
control 'ubuntu-ssh-key-files-access-configured' do
  impact 1.0
  title 'Ensure access to SSH key files is configured'
  desc 'Access to SSH key files should be configured.'
  describe file('/etc/ssh/ssh_host_rsa_key') do
    it { should_not be_readable.by('others') }
  end
end

# 203. Ensure sshd DisableForwarding is enabled
control 'ubuntu-sshd-disableforwarding-enabled' do
  impact 1.0
  title 'Ensure sshd DisableForwarding is enabled'
  desc 'sshd DisableForwarding should be enabled.'
  describe sshd_config do
    its('DisableForwarding') { should eq 'yes' }
  end
end

# 204. Ensure sshd GSSAPIAuthentication is disabled
control 'ubuntu-sshd-gssapiauthentication-disabled' do
  impact 1.0
  title 'Ensure sshd GSSAPIAuthentication is disabled'
  desc 'sshd GSSAPIAuthentication should be disabled.'
  describe sshd_config do
    its('GSSAPIAuthentication') { should eq 'no' }
  end
end

# 205. Ensure users must provide password for privilege escalation
control 'ubuntu-password-privilege-escalation' do
  impact 1.0
  title 'Ensure users must provide password for privilege escalation'
  desc 'Users must provide password for privilege escalation.'
  describe file('/etc/sudoers') do
    its('content') { should match(/Defaults !authenticate/) }
  end
end

# 206. Ensure re-authentication for privilege escalation is not disabled globally
control 'ubuntu-reauthentication-not-disabled' do
  impact 1.0
  title 'Ensure re-authentication for privilege escalation is not disabled globally'
  desc 'Re-authentication for privilege escalation should not be disabled globally.'
  describe file('/etc/sudoers') do
    its('content') { should_not match(/Defaults !authenticate/) }
  end
end

# 207. Ensure sudo authentication timeout is configured correctly
control 'ubuntu-sudo-authentication-timeout' do
  impact 1.0
  title 'Ensure sudo authentication timeout is configured correctly'
  desc 'Sudo authentication timeout should be configured correctly.'
  describe file('/etc/sudoers') do
    its('content') { should match(/Defaults timestamp_timeout=15/) }
  end
end

# 208. Ensure the number of changed characters in a new password is configured
control 'ubuntu-password-changed-characters-configured' do
  impact 1.0
  title 'Ensure the number of changed characters in a new password is configured'
  desc 'The number of changed characters in a new password should be configured.'
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match(/difok=4/) }
  end
end

# 209. Ensure password dictionary check is enabled
control 'ubuntu-password-dictionary-check-enabled' do
  impact 1.0
  title 'Ensure password dictionary check is enabled'
  desc 'Password dictionary check should be enabled.'
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match(/dictcheck=1/) }
  end
end

# 210. Ensure nosuid option set on /home partition
control 'ubuntu-nosuid-home-partition' do
  impact 1.0
  title 'Ensure nosuid option set on /home partition'
  desc 'Nosuid option should be set on /home partition.'
  describe mount('/home') do
    its('options') { should include 'nosuid' }
  end
end

# 211. Ensure nologin is not listed in /etc/shells
control 'ubuntu-nologin-not-listed-shells' do
  impact 1.0
  title 'Ensure nologin is not listed in /etc/shells'
  desc 'Nologin should not be listed in /etc/shells.'
  describe file('/etc/shells') do
    its('content') { should_not match(/nologin/) }
  end
end

# 212. Ensure maximum number of same consecutive characters in a password is configured
control 'ubuntu-password-consecutive-characters-configured' do
  impact 1.0
  title 'Ensure maximum number of same consecutive characters in a password is configured'
  desc 'Maximum number of same consecutive characters in a password should be configured.'
  describe file('/etc/security/pwquality.conf') do
    its('content') { should match(/maxrepeat=3/) }
  end
end

# 213. Ensure autofs is not installed or the autofs service is disabled
control 'ubuntu-autofs-not-installed-disabled' do
  impact 1.0
  title 'Ensure autofs is not installed or the autofs service is disabled'
  desc 'Autofs should not be installed or the autofs service should be disabled.'
  describe package('autofs') do
    it { should_not be_installed }
  end
end

# 214. Ensure systemd-journal-remote is installed
control 'ubuntu-systemd-journal-remote-installed' do
  impact 1.0
  title 'Ensure systemd-journal-remote is installed'
  desc 'Systemd-journal-remote should be installed.'
  describe package('systemd-journal-remote') do
    it { should be_installed }
  end
end

# 215. Ensure systemd-journal-remote is configured
control 'ubuntu-systemd-journal-remote-configured' do
  impact 1.0
  title 'Ensure systemd-journal-remote is configured'
  desc 'Systemd-journal-remote should be configured.'
  describe file('/etc/systemd/journal-remote.conf') do
    its('content') { should match(/Server=/) }
  end
end

# 216. Ensure ptrace_scope is restricted
control 'ubuntu-ptrace-scope-restricted' do
  impact 1.0
  title 'Ensure ptrace_scope is restricted'
  desc 'Ptrace_scope should be restricted.'
  describe file('/proc/sys/kernel/yama/ptrace_scope') do
    its('content') { should eq '1' }
  end
end

# 217. Ensure systemd-journal-remote is enabled
control 'ubuntu-systemd-journal-remote-enabled' do
  impact 1.0
  title 'Ensure systemd-journal-remote is enabled'
  desc 'Systemd-journal-remote should be enabled.'
  describe service('systemd-journal-remote') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 218. Ensure journald is not configured to receive logs from a remote client
control 'ubuntu-journald-not-receive-remote-logs' do
  impact 1.0
  title 'Ensure journald is not configured to receive logs from a remote client'
  desc 'Journald should not be configured to receive logs from a remote client.'
  describe file('/etc/systemd/journald.conf') do
    its('content') { should match(/ForwardToSyslog=no/) }
  end
end

# 219. Ensure journald service is enabled
control 'ubuntu-journald-service-enabled' do
  impact 1.0
  title 'Ensure journald service is enabled'
  desc 'Journald service should be enabled.'
  describe service('systemd-journald') do
    it { should be_enabled }
    it { should be_running }
  end
end

# 220. Ensure journald is not configured to send logs to rsyslog
control 'ubuntu-journald-not-send-logs-rsyslog' do
  impact 1.0
  title 'Ensure journald is not configured to send logs to rsyslog'
  desc 'Journald should not be configured to send logs to rsyslog.'
  describe file('/etc/systemd/journald.conf') do
    its('content') { should match(/ForwardToSyslog=no/) }
  end
end

# 221. Ensure journald log rotation is configured per site policy
control 'ubuntu-journald-log-rotation-configured' do
  impact 1.0
  title 'Ensure journald log rotation is configured per site policy'
  desc 'Journald log rotation should be configured per site policy.'
  describe file('/etc/systemd/journald.conf') do
    its('content') { should match(/SystemMaxUse=/) }
  end
end

# 222. Ensure Automatic Error Reporting is not enabled
control 'ubuntu-automatic-error-reporting-disabled' do
  impact 1.0
  title 'Ensure Automatic Error Reporting is not enabled'
  desc 'Automatic Error Reporting should not be enabled.'
  describe file('/etc/default/apport') do
    its('content') { should match(/enabled=0/) }
  end
end

# 223. Ensure journald default file permissions configured
control 'ubuntu-journald-default-file-permissions-configured' do
  impact 1.0
  title 'Ensure journald default file permissions configured'
  desc 'Journald default file permissions should be configured.'
  describe file('/etc/systemd/journald.conf') do
    its('content') { should match(/Umask=027/) }
  end
end

# 224. Ensure rsyslog is not configured to receive logs from a remote client
control 'ubuntu-rsyslog-not-receive-remote-logs' do
  impact 1.0
  title 'Ensure rsyslog is not configured to receive logs from a remote client'
  desc 'Rsyslog should not be configured to receive logs from a remote client.'
  describe file('/etc/rsyslog.conf') do
    its('content') { should_not match(/ModLoad imtcp/) }
  end
end

# 225. Ensure all logfiles have appropriate access configured
control 'ubuntu-logfiles-access-configured' do
  impact 1.0
  title 'Ensure all logfiles have appropriate access configured'
  desc 'All logfiles should have appropriate access configured.'
  describe command('find /var/log -type f -perm /o+w') do
    its('stdout') { should eq '' }
  end
end

# 226. Ensure successful and unsuccessful attempts to use the chcon command are recorded
control 'ubuntu-audit-chcon-command' do
  impact 1.0
  title 'Ensure successful and unsuccessful attempts to use the chcon command are recorded'
  desc 'Successful and unsuccessful attempts to use the chcon command should be recorded.'
  describe auditd_rules do
    its('lines') { should include('-a always,exit -F arch=b64 -S chcon -F auid>=1000 -F auid!=4294967295 -k privileged') }
  end
end

# 227. Ensure successful and unsuccessful attempts to use the setfacl command are recorded
control 'ubuntu-audit-setfacl-command' do
  impact 1.0
  title 'Ensure successful and unsuccessful attempts to use the setfacl command are recorded'
  desc 'Successful and unsuccessful attempts to use the setfacl command should be recorded.'
  describe auditd_rules do
    its('lines') { should include('-a always,exit -F arch=b64 -S setfacl -F auid>=1000 -F auid!=4294967295 -k privileged') }
  end
end

# 228. Ensure successful and unsuccessful attempts to use the chacl command are recorded
control 'ubuntu-audit-chacl-command' do
  impact 1.0
  title 'Ensure successful and unsuccessful attempts to use the chacl command are recorded'
  desc 'Successful and unsuccessful attempts to use the chacl command should be recorded.'
  describe auditd_rules do
    its('lines') { should include('-a always,exit -F arch=b64 -S chacl -F auid>=1000 -F auid!=4294967295 -k privileged') }
  end
end

# 229. Ensure GDM screen locks when the user is idle
control 'ubuntu-gdm-screen-locks-idle' do
  impact 1.0
  title 'Ensure GDM screen locks when the user is idle'
  desc 'GDM screen should lock when the user is idle.'
  describe file('/etc/gdm3/greeter.dconf-defaults') do
    its('content') { should match(/idle-delay=300/) }
  end
end

# 230. Ensure GDM screen locks cannot be overridden
control 'ubuntu-gdm-screen-locks-not-overridden' do
  impact 1.0
  title 'Ensure GDM screen locks cannot be overridden'
  desc 'GDM screen locks should not be overridden.'
  describe file('/etc/gdm3/greeter.dconf-defaults') do
    its('content') { should match(/lock-enabled=true/) }
  end
end

# 231. Ensure GDM automatic mounting of removable media is disabled
control 'ubuntu-gdm-automatic-mounting-disabled' do
  impact 1.0
  title 'Ensure GDM automatic mounting of removable media is disabled'
  desc 'GDM automatic mounting of removable media should be disabled.'
  describe file('/etc/gdm3/greeter.dconf-defaults') do
    its('content') { should match(/automount=false/) }
  end
end

# 232. Ensure GDM disabling automatic mounting of removable media is not overridden
control 'ubuntu-gdm-automatic-mounting-not-overridden' do
  impact 1.0
  title 'Ensure GDM disabling automatic mounting of removable media is not overridden'
  desc 'GDM disabling automatic mounting of removable media should not be overridden.'
  describe file('/etc/gdm3/greeter.dconf-defaults') do
    its('content') { should match(/automount=false/) }
  end
end

# 233. Ensure GDM autorunnever is enabled
control 'ubuntu-gdm-autorunnever-enabled' do
  impact 1.0
  title 'Ensure GDM autorunnever is enabled'
  desc 'GDM autorunnever should be enabled.'
  describe file('/etc/gdm3/greeter.dconf-defaults') do
    its('content') { should match(/autorunnever=true/) }
  end
end

# 234. Ensure GDM autorunnever is not overridden
control 'ubuntu-gdm-autorunnever-not-overridden' do
  impact 1.0
  title 'Ensure GDM autorunnever is not overridden'
  desc 'GDM autorunnever should not be overridden.'
  describe file('/etc/gdm3/greeter.dconf-defaults') do
    its('content') { should match(/autorunnever=true/) }
  end
end

# 235. Ensure successful and unsuccessful attempts to use the usermod command are recorded
control 'ubuntu-audit-usermod-command' do
  impact 1.0
  title 'Ensure successful and unsuccessful attempts to use the usermod command are recorded'
  desc 'Successful and unsuccessful attempts to use the usermod command should be recorded.'
  describe auditd_rules do
    its('lines') { should include('-a always,exit -F arch=b64 -S usermod -F auid>=1000 -F auid!=4294967295 -k privileged') }
  end
end

# 236. Ensure kernel module loading unloading and modification is collected
control 'ubuntu-audit-kernel-module-loading' do
  impact 1.0
  title 'Ensure kernel module loading unloading and modification is collected'
  desc 'Kernel module loading, unloading, and modification should be collected.'
  describe auditd_rules do
    its('lines') { should include('-w /sbin/insmod -p x -k modules') }
    its('lines') { should include('-w /sbin/rmmod -p x -k modules') }
    its('lines') { should include('-w /sbin/modprobe -p x -k modules') }
  end
end

# 237. Ensure actions as another user are always logged
control 'ubuntu-audit-actions-another-user' do
  impact 1.0
  title 'Ensure actions as another user are always logged'
  desc 'Actions as another user should always be logged.'
  describe auditd_rules do
    its('lines') { should include('-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k actions') }
  end
end

# 238. Ensure the running and on disk configuration is the same
control 'ubuntu-running-on-disk-config-same' do
  impact 1.0
  title 'Ensure the running and on disk configuration is the same'
  desc 'The running and on disk configuration should be the same.'
  describe command('diff /etc/audit/audit.rules /proc/self/audit') do
    its('stdout') { should eq '' }
  end
end

# 239. Ensure events that modify the sudo log file are collected
control 'ubuntu-audit-sudo-log-file-modification' do
  impact 1.0
  title 'Ensure events that modify the sudo log file are collected'
  desc 'Events that modify the sudo log file should be collected.'
  describe auditd_rules do
    its('lines') { should include('-w /var/log/sudo.log -p wa -k actions') }
  end
end

# 240. Ensure unsuccessful file access attempts are collected
control 'ubuntu-audit-unsuccessful-file-access' do
  impact 1.0
  title 'Ensure unsuccessful file access attempts are collected'
  desc 'Unsuccessful file access attempts should be collected.'
  describe auditd_rules do
    its('lines') { should include('-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access') }
  end
end

# 241. Ensure ntp is running as user ntp
control 'ubuntu-ntp-running-user-ntp' do
  impact 1.0
  title 'Ensure ntp is running as user ntp'
  desc 'NTP should be running as user ntp.'
  describe processes('ntpd') do
    its('users') { should include 'ntp' }
  end
end

# 242. Ensure audit log files are mode 0640 or less permissive
control 'ubuntu-audit-log-files-mode-0640' do
  impact 1.0
  title 'Ensure audit log files are mode 0640 or less permissive'
  desc 'Audit log files should be mode 0640 or less permissive.'
  describe file('/var/log/audit/audit.log') do
    its('mode') { should cmp '0640' }
  end
end

# 243. Ensure audit tools belong to group root
control 'ubuntu-audit-tools-group-root' do
  impact 1.0
  title 'Ensure audit tools belong to group root'
  desc 'Audit tools should belong to group root.'
  describe file('/sbin/auditctl') do
    its('group') { should eq 'root' }
  end
end

# 244. Ensure cryptographic mechanisms are used to protect the integrity of audit tools
control 'ubuntu-audit-tools-cryptographic-integrity' do
  impact 1.0
  title 'Ensure cryptographic mechanisms are used to protect the integrity of audit tools'
  desc 'Cryptographic mechanisms should be used to protect the integrity of audit tools.'
  describe file('/sbin/auditctl') do
    its('content') { should match(/sha256/) }
  end
end

# 245. Ensure dnsmasq is not installed
control 'ubuntu-dnsmasq-not-installed' do
  impact 1.0
  title 'Ensure dnsmasq is not installed'
  desc 'Dnsmasq should not be installed.'
  describe package('dnsmasq') do
    it { should_not be_installed }
  end
end

# 246. Ensure only authorized users own audit log files
control 'ubuntu-audit-log-files-authorized-users' do
  impact 1.0
  title 'Ensure only authorized users own audit log files'
  desc 'Only authorized users should own audit log files.'
  describe file('/var/log/audit/audit.log') do
    its('owner') { should eq 'root' }
  end
end

# 247. Ensure only authorized groups are assigned ownership of audit log files
control 'ubuntu-audit-log-files-authorized-groups' do
  impact 1.0
  title 'Ensure only authorized groups are assigned ownership of audit log files'
  desc 'Only authorized groups should be assigned ownership of audit log files.'
  describe file('/var/log/audit/audit.log') do
    its('group') { should eq 'root' }
  end
end

# 248. Ensure the audit log directory is 0750 or more restrictive
control 'ubuntu-audit-log-directory-0750' do
  impact 1.0
  title 'Ensure the audit log directory is 0750 or more restrictive'
  desc 'The audit log directory should be 0750 or more restrictive.'
  describe file('/var/log/audit') do
    its('mode') { should cmp '0750' }
  end
end

# 249. Ensure audit configuration files are 640 or more restrictive
control 'ubuntu-audit-config-files-640' do
  impact 1.0
  title 'Ensure audit configuration files are 640 or more restrictive'
  desc 'Audit configuration files should be 640 or more restrictive.'
  describe file('/etc/audit/audit.rules') do
    its('mode') { should cmp '0640' }
  end
end

# 250. Ensure audit configuration files are owned by root
control 'ubuntu-audit-config-files-owned-root' do
  impact 1.0
  title 'Ensure audit configuration files are owned by root'
  desc 'Audit configuration files should be owned by root.'
  describe file('/etc/audit/audit.rules') do
    its('owner') { should eq 'root' }
  end
end

# 251. Ensure audit configuration files belong to group root
control 'ubuntu-audit-config-files-group-root' do
  impact 1.0
  title 'Ensure audit configuration files belong to group root'
  desc 'Audit configuration files should belong to group root.'
  describe file('/etc/audit/audit.rules') do
    its('group') { should eq 'root' }
  end
end

# 252. Ensure bluetooth services are not in use
control 'ubuntu-bluetooth-services-not-in-use' do
  impact 1.0
  title 'Ensure bluetooth services are not in use'
  desc 'Bluetooth services should not be in use.'
  describe service('bluetooth') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

# 253. Ensure audit tools are 755 or more restrictive
control 'ubuntu-audit-tools-755-restrictive' do
  impact 1.0
  title 'Ensure audit tools are 755 or more restrictive'
  desc 'Audit tools should be 755 or more restrictive.'
  describe file('/sbin/auditctl') do
    its('mode') { should cmp '0755' }
  end
end

# 254. Ensure audit tools are owned by root
control 'ubuntu-audit-tools-owned-root' do
  impact 1.0
  title 'Ensure audit tools are owned by root'
  desc 'Audit tools should be owned by root.'
  describe file('/sbin/auditctl') do
    its('owner') { should eq 'root' }
  end
end

# 255. Ensure no files or directories without an owner and a group exist
control 'ubuntu-no-files-directories-without-owner-group' do
  impact 1.0
  title 'Ensure no files or directories without an owner and a group exist'
  desc 'No files or directories without an owner and a group should exist.'
  describe command('find / -xdev -nouser -nogroup') do
    its('stdout') { should eq '' }
  end
end

# 256. Ensure permissions on /etc/shells are configured
control 'ubuntu-permissions-etc-shells' do
  impact 1.0
  title 'Ensure permissions on /etc/shells are configured'
  desc 'Permissions on /etc/shells should be configured.'
  describe file('/etc/shells') do
    its('mode') { should cmp '0644' }
  end
end

# 257. Ensure permissions on /etc/security/opasswd are configured
control 'ubuntu-permissions-etc-security-opasswd' do
  impact 1.0
  title 'Ensure permissions on /etc/security/opasswd are configured'
  desc 'Permissions on /etc/security/opasswd should be configured.'
  describe file('/etc/security/opasswd') do
    its('mode') { should cmp '0640' }
  end
end

# 258. Ensure local interactive user dot files access is configured
control 'ubuntu-local-interactive-user-dot-files-access' do
  impact 1.0
  title 'Ensure local interactive user dot files access is configured'
  desc 'Local interactive user dot files access should be configured.'
  describe command('find /home -type f -name ".*" -perm /o+w') do
    its('stdout') { should eq '' }
  end
end

# 259. Ensure /etc/shadow password fields are not empty
control 'ubuntu-shadow-password-fields-not-empty' do
  impact 1.0
  title 'Ensure /etc/shadow password fields are not empty'
  desc '/etc/shadow password fields should not be empty.'
  describe shadow do
    its('users') { should_not include '' }
  end
end

# 260. Ensure local interactive user home directories are configured
control 'ubuntu-local-interactive-user-home-directories-configured' do
  impact 1.0
  title 'Ensure local interactive user home directories are configured'
  desc 'Local interactive user home directories should be configured.'
  describe command('find /home -type d -perm /o+w') do
    its('stdout') { should eq '' }
  end
end

# 261. Ensure sshd MaxSessions is configured
control 'ubuntu-sshd-maxsessions-configured' do
  impact 1.0
  title 'Ensure sshd MaxSessions is configured'
  desc 'sshd MaxSessions should be configured.'
  describe sshd_config do
    its('MaxSessions') { should eq '10' }
  end
end

# 262. Ensure all current passwords use the configured hashing algorithm
control 'ubuntu-current-passwords-hashing-algorithm' do
  impact 1.0
  title 'Ensure all current passwords use the configured hashing algorithm'
  desc 'All current passwords should use the configured hashing algorithm.'
  describe shadow do
    its('passwords') { should all(match(/^\$6\$/)) }
  end
end

# 263. Ensure permissions on /etc/passwd- are configured
control 'ubuntu-permissions-etc-passwd-' do
  impact 1.0
  title 'Ensure permissions on /etc/passwd- are configured'
  desc 'Permissions on /etc/passwd- should be configured.'
  describe file('/etc/passwd-') do
    its('mode') { should cmp '0644' }
  end
end

# 264. Ensure permissions on /etc/group- are configured
control 'ubuntu-permissions-etc-group-' do
  impact 1.0
  title 'Ensure permissions on /etc/group- are configured'
  desc 'Permissions on /etc/group- should be configured.'
  describe file('/etc/group-') do
    its('mode') { should cmp '0644' }
  end
end

# 265. Ensure permissions on /etc/shadow- are configured
control 'ubuntu-permissions-etc-shadow-' do
  impact 1.0
  title 'Ensure permissions on /etc/shadow- are configured'
  desc 'Permissions on /etc/shadow- should be configured.'
  describe file('/etc/shadow-') do
    its('mode') { should cmp '0640' }
  end
end

# 266. Ensure permissions on /etc/gshadow- are configured
control 'ubuntu-permissions-etc-gshadow-' do
  impact 1.0
  title 'Ensure permissions on /etc/gshadow- are configured'
  desc 'Permissions on /etc/gshadow- should be configured.'
  describe file('/etc/gshadow-') do
    its('mode') { should cmp '0640' }
  end
end

# 267. Ensure default encryption scheme is not used for password storage
control 'ubuntu-default-encryption-scheme-not-used' do
  impact 1.0
  title 'Ensure default encryption scheme is not used for password storage'
  desc 'Default encryption scheme should not be used for password storage.'
  describe shadow do
    its('passwords') { should all(match(/^\$6\$/)) }
  end
end

# 268. Ensure active User IDs which were not logged in for more than 90 days or never are disabled
control 'ubuntu-active-user-ids-disabled' do
  impact 1.0
  title 'Ensure active User IDs which were not logged in for more than 90 days or never are disabled'
  desc 'Active User IDs which were not logged in for more than 90 days or never should be disabled.'
  describe command('lastlog | awk \'$4 > 90 {print $1}\'') do
    its('stdout') { should eq '' }
  end
end

# 269. Ensure hidden files permissions are set to 640
control 'ubuntu-hidden-files-permissions-640' do
  impact 1.0
  title 'Ensure hidden files permissions are set to 640'
  desc 'Hidden files permissions should be set to 640.'
  describe command('find /home -type f -name ".*" -perm /o+w') do
    its('stdout') { should eq '' }
  end
end

# 270. Ensure no users are part of wheel group
control 'ubuntu-no-users-wheel-group' do
  impact 1.0
  title 'Ensure no users are part of wheel group'
  desc 'No users should be part of wheel group.'
  describe group('wheel') do
    its('members') { should be_empty }
  end
end

# 271. Ensure users are not added with full privileges in sudoers file
control 'ubuntu-users-not-full-privileges-sudoers' do
  impact 1.0
  title 'Ensure users are not added with full privileges in sudoers file'
  desc 'Users should not be added with full privileges in sudoers file.'
  describe file('/etc/sudoers') do
    its('content') { should_not match(/ALL=(ALL) ALL/) }
  end
end

# 272. Ensure interactive login is disabled for default system accounts
control 'ubuntu-interactive-login-disabled-system-accounts' do
  impact 1.0
  title 'Ensure interactive login is disabled for default system accounts'
  desc 'Interactive login should be disabled for default system accounts.'
  describe passwd do
    its('shells') { should_not include '/bin/bash' }
  end
end

