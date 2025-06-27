# IBM HTTP Server InSpec Controls
# Place this file in ibm-httpd-profile/controls/ibm_httpd_controls.rb

DOCUMENT_ROOT = '/Users/KMBL400649/Documents/Config_Check_Project/ibm-httpd-profile/config/htdocs'
CONFIG_FILES = [
  '/Users/KMBL400649/Documents/Config_Check_Project/ibm-httpd-profile/config/httpd.conf',
  '/Users/KMBL400649/Documents/Config_Check_Project/ibm-httpd-profile/config/ssl.conf'
]
LOG_DIR = '/Users/KMBL400649/Documents/Config_Check_Project/ibm-httpd-profile/config/logs'
CGI_BIN = '/Users/KMBL400649/Documents/Config_Check_Project/ibm-httpd-profile/config/cgi-bin'

# 1. Weak permissions on files in the Document Root
control 'ibm-httpd-01' do
  impact 1.0
  title 'Weak permissions on files in the Document Root'
  desc 'Files in the document root should not be world-writable or owned by root.'
  describe command("find #{DOCUMENT_ROOT} -type f -perm /o+w") do
    its('stdout') { should eq "" }
  end
  describe command("find #{DOCUMENT_ROOT} -type f -user root") do
    its('stdout') { should eq "" }
  end
end

# 2. Weak permissions on Server Configuration files
control 'ibm-httpd-02' do
  impact 1.0
  title 'Weak permissions on Server Configuration files'
  desc 'Config files should not be world-readable or writable.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      it { should_not be_writable.by('group') }
      it { should_not be_writable.by('other') }
      it { should_not be_readable.by('other') }
    end
  end
end

# 3. Weak permissions on Log files
control 'ibm-httpd-03' do
  impact 1.0
  title 'Weak permissions on Log files'
  desc 'Log files should not be world-readable or writable.'
  describe command("find #{LOG_DIR} -type f -perm /o+w -o -perm /o+r") do
    its('stdout') { should eq "" }
  end
end

# 4. Server version information parameters are turned on
control 'ibm-httpd-04' do
  impact 1.0
  title 'Server version information parameters are turned on'
  desc 'ServerTokens and ServerSignature should be set to minimal.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/^ServerTokens Prod/i) }
      its('content') { should match(/^ServerSignature Off/i) }
    end
  end
end

# 5. Logging Directives are not configured securely
control 'ibm-httpd-05' do
  impact 1.0
  title 'Logging Directives are not configured securely'
  desc 'LogLevel should not be debug, and logs should be rotated.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should_not match(/^LogLevel debug/i) }
      its('content') { should match(/^CustomLog\s+\S+\s+combined/i) }
    end
  end
  describe file('/Users/KMBL400649/Documents/Config_Check_Project/ibm-httpd-profile/config/logrotate.d/ibm-httpd') do
    it { should exist }
  end
end

# 6. Insecure directory access permissions
control 'ibm-httpd-06' do
  impact 1.0
  title 'Insecure directory access permissions'
  desc 'No directory should have Options Indexes or FollowSymLinks enabled.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should_not match(/Options\s+.*Indexes/i) }
      its('content') { should_not match(/Options\s+.*FollowSymLinks/i) }
    end
  end
end

# 7. Cgi-bin directory is not disabled
control 'ibm-httpd-07' do
  impact 1.0
  title 'Cgi-bin directory is not disabled'
  desc 'cgi-bin should be disabled if not needed.'
  describe file(CONFIG_FILES[0]) do
    its('content') { should_not match(%r{ScriptAlias\s+/cgi-bin/\s+#{CGI_BIN}}) }
  end
end

# 8. Insecure User Oriented Directives
control 'ibm-httpd-08' do
  impact 1.0
  title 'Insecure User Oriented Directives'
  desc 'UserDir and related directives should be disabled.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/^UserDir\s+disabled/i) }
    end
  end
end

# 9. High timeout value
control 'ibm-httpd-09' do
  impact 0.5
  title 'High timeout value'
  desc 'Timeout should not be set too high.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/^Timeout\s+([1-9][0-9]{0,2}|1000)$/i) }
    end
  end
end

# 10. Keep Alive setting is not configured
control 'ibm-httpd-10' do
  impact 0.5
  title 'Keep Alive setting is not configured'
  desc 'KeepAlive should be On.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/^KeepAlive On/i) }
    end
  end
end

# 11. Keep Alive Timeout setting is not configured
control 'ibm-httpd-11' do
  impact 0.5
  title 'Keep Alive Timeout setting is not configured'
  desc 'KeepAliveTimeout should be set to a reasonable value.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/^KeepAliveTimeout\s+([1-9][0-9]?|100)$/i) }
    end
  end
end

# 12. MaxKeepAliveRequests parameter not set
control 'ibm-httpd-12' do
  impact 0.5
  title 'MaxKeepAliveRequests parameter not set'
  desc 'MaxKeepAliveRequests should be set.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/^MaxKeepAliveRequests\s+\d+/i) }
    end
  end
end

# 13. StartServers parameter not set
control 'ibm-httpd-13' do
  impact 0.5
  title 'StartServers parameter not set'
  desc 'StartServers should be set.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/^StartServers\s+\d+/i) }
    end
  end
end

# 14. MinSpareThreads parameter not set
control 'ibm-httpd-14' do
  impact 0.5
  title 'MinSpareThreads parameter not set'
  desc 'MinSpareThreads should be set.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/^MinSpareThreads\s+\d+/i) }
    end
  end
end

# 15. MaxSpareThreads parameter not set
control 'ibm-httpd-15' do
  impact 0.5
  title 'MaxSpareThreads parameter not set'
  desc 'MaxSpareThreads should be set.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/^MaxSpareThreads\s+\d+/i) }
    end
  end
end

# 16. MaxClients parameter not set
control 'ibm-httpd-16' do
  impact 0.5
  title 'MaxClients parameter not set'
  desc 'MaxClients should be set.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/^MaxClients\s+\d+/i) }
    end
  end
end

# 17. Use HTTPS from the browser
control 'ibm-httpd-17' do
  impact 1.0
  title 'Use HTTPS from the browser'
  desc 'Redirect HTTP to HTTPS.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/RewriteRule .*https:\/\//i) }
    end
  end
end

# 18. Web User Account not locked down
control 'ibm-httpd-18' do
  impact 1.0
  title 'Web User Account not locked down'
  desc 'The web server should not run as root.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/^User\s+(?!root)\w+/i) }
    end
  end
end

# 19. Non-Essential modules are enabled
control 'ibm-httpd-19' do
  impact 0.5
  title 'Non-Essential modules are enabled'
  desc 'Only required modules should be loaded.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should_not match(/^LoadModule\s+(status|autoindex|info|userdir|proxy_ftp|proxy_connect|proxy_ajp|proxy_balancer|proxy|cgi|dav|dav_fs|dav_lock|include|logio|speling|usertrack|vhost_alias)_module/i) }
    end
  end
end

# 20. HTTP Methods not Limited
control 'ibm-httpd-20' do
  impact 1.0
  title 'HTTP Methods not Limited'
  desc 'Limit HTTP methods to only those required.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<LimitExcept\s+GET POST HEAD>/i) }
    end
  end
end

# 21. Buffer Overflow protection on configured
control 'ibm-httpd-21' do
  impact 1.0
  title 'Buffer Overflow protection not configured'
  desc 'Check for mod_buffer or similar protection.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/^LoadModule\s+buffer_module/i) }
    end
  end
end

# 22. Check for the version
control 'ibm-httpd-22' do
  impact 0.5
  title 'Check for the version'
  desc 'Check IBM HTTP Server version string in config files.'
  CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/IBM_HTTP_Server\/[\d.]+/) }
    end
  end
end

# 23. Configure SSL between the IBM HTTP Server Administration Server and the deployment manager
control 'ibm-httpd-23' do
  impact 1.0
  title 'Configure SSL between the IBM HTTP Server Administration Server and the deployment manager'
  desc 'SSL should be enabled for admin server.'
  describe file('/Users/KMBL400649/Documents/Config_Check_Project/ibm-httpd-profile/config/ssl.conf') do
    its('content') { should match(/^SSLEnable\s+admin/i) }
  end
end

# 24. Configuring IBM HTTP Server to use nCipher and Rainbow accelerator devices and PKCS11 devices
control 'ibm-httpd-24' do
  impact 0.5
  title 'Configuring IBM HTTP Server to use nCipher and Rainbow accelerator devices and PKCS11 devices'
  desc 'Check for PKCS11 configuration.'
  describe file('/Users/KMBL400649/Documents/Config_Check_Project/ibm-httpd-profile/config/ssl.conf') do
    its('content') { should match(/PKCS11/i) }
  end
end

# 25. Securing with SSL communications
control 'ibm-httpd-25' do
  impact 1.0
  title 'Securing with SSL communications'
  desc 'SSL should be enabled.'
  describe file('/Users/KMBL400649/Documents/Config_Check_Project/ibm-httpd-profile/config/ssl.conf') do
    its('content') { should match(/^SSLProtocol\s+.*TLS.*/i) }
    its('content') { should match(/^SSLEnable/i) }
  end
end

# 26. Managing keys with the IKEYMAN graphical interface (Distributed systems)
control 'ibm-httpd-26' do
  impact 0.5
  title 'Managing keys with the IKEYMAN graphical interface (Distributed systems)'
  desc 'Check for IKEYMAN usage in documentation or config.'
  describe file('/Users/KMBL400649/Documents/Config_Check_Project/ibm-httpd-profile/config/ssl.conf') do
    its('content') { should match(/ikeyman/i) }
  end
end
