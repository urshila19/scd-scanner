# IBM WebSphere Security Controls - Config Check Only

WEBSPHERE_CONFIG_FILES = [
  '/Users/KMBL400649/Documents/Config_Check_Project/ibm-websphere-profile/config/security.xml',
  '/Users/KMBL400649/Documents/Config_Check_Project/ibm-websphere-profile/config/server.xml',
  '/Users/KMBL400649/Documents/Config_Check_Project/ibm-websphere-profile/config/resources.xml',
  '/Users/KMBL400649/Documents/Config_Check_Project/ibm-websphere-profile/config/variables.xml'
]

control 'was-01' do
  impact 1.0
  title 'Passwords should be protected from Standard Input'
  desc 'Ensure passwords are not set via standard input in config files.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should_not match(/password\s*=\s*["']?stdin["']?/) }
    end
  end
end

control 'was-02' do
  impact 1.0
  title 'Password caching should be disabled'
  desc 'Ensure password caching is disabled in security config.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/passwordCachingEnabled\s*=\s*["']?false["']?/) }
    end
  end
end

control 'was-03' do
  impact 1.0
  title 'Administration security should be enabled'
  desc 'Ensure administrative security is enabled.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/adminEnabled\s*=\s*["']?true["']?/) }
    end
  end
end

control 'was-04' do
  impact 0.7
  title 'Current Patches should be applied to the system'
  desc 'Check config for patch/version info (manual review may be required).'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<version>|patch|fixpack/i) }
    end
  end
end

control 'was-05' do
  impact 1.0
  title 'Service Integration Bus should be secured'
  desc 'Ensure SIBus security is enabled.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<SIBus.*securityEnabled=["']?true["']?/) }
    end
  end
end

control 'was-06' do
  impact 1.0
  title 'WAS to LDAP link should be encrypted'
  desc 'Ensure LDAP connections use SSL/TLS.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<ldap.*sslEnabled=["']?true["']?/) }
    end
  end
end

control 'was-07' do
  impact 1.0
  title 'Web Server to Web container link should be encrypted'
  desc 'Ensure HTTPS is used for web server to container communication.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<transport.*protocol=["']?https["']?/) }
    end
  end
end

control 'was-08' do
  impact 1.0
  title 'Distribution and Consistency Services Link should be encrypted'
  desc 'Ensure DCS links are encrypted.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<dcs.*sslEnabled=["']?true["']?/) }
    end
  end
end

control 'was-09' do
  impact 1.0
  title 'WebSphere MQ messaging links should be encrypted'
  desc 'Ensure MQ links use SSL/TLS.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<MQ.*sslEnabled=["']?true["']?/) }
    end
  end
end

control 'was-10' do
  impact 1.0
  title 'Sample applications should be removed from production'
  desc 'Ensure sample apps are not present in config.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should_not match(/<application.*sample/i) }
    end
  end
end

control 'was-11' do
  impact 1.0
  title 'LTPA cookie format should be used'
  desc 'Ensure LTPA is configured for SSO.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<LTPAKeySet|ltpa/i) }
    end
  end
end

control 'was-12' do
  impact 1.0
  title 'Single sign on for HTTP requests should be secured'
  desc 'Ensure SSO is enabled and secure.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<singleSignon.*enabled=["']?true["']?/) }
    end
  end
end

control 'was-13' do
  impact 1.0
  title 'Application security at the global security level should be enabled'
  desc 'Ensure global application security is enabled.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/appEnabled\s*=\s*["']?true["']?/) }
    end
  end
end

control 'was-14' do
  impact 1.0
  title 'Session security integration should be enabled'
  desc 'Ensure session security integration is enabled.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/sessionSecurityIntegration\s*=\s*["']?true["']?/) }
    end
  end
end

control 'was-15' do
  impact 1.0
  title 'Configuration files should be protected'
  desc 'Check config file permissions (manual review may be required).'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      it { should be_readable.by('owner') }
      it { should_not be_writable.by('others') }
    end
  end
end

control 'was-16' do
  impact 1.0
  title 'Java Naming and Directory Interface should be protected'
  desc 'Ensure JNDI security is enabled.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<jndi.*securityEnabled=["']?true["']?/) }
    end
  end
end

control 'was-17' do
  impact 1.0
  title 'File systems should be protected using JAVA 2 security'
  desc 'Ensure Java 2 security is enabled.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/java2SecurityEnabled\s*=\s*["']?true["']?/) }
    end
  end
end

control 'was-18' do
  impact 1.0
  title 'Authorization should be controlled through administrative roles'
  desc 'Ensure admin roles are defined in config.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<role.*name=["']?admin["']?/) }
    end
  end
end

control 'was-19' do
  impact 1.0
  title 'Security auditing feature should be enabled'
  desc 'Ensure security auditing is enabled.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<audit.*enabled=["']?true["']?/) }
    end
  end
end

control 'was-20' do
  impact 1.0
  title 'Creating an authentication alias'
  desc 'Ensure authentication aliases are defined in config.'
  WEBSPHERE_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<authData.*alias=/) }
    end
  end
end
