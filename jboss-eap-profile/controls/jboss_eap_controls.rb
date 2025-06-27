# JBOSS EAP CONTROLS - InSpec Profile Example
# Place this file in jboss-eap-profile/controls/jboss_eap_controls.rb

JBOSS_CONFIG_FILES = [
  '/Users/KMBL400649/Documents/Config_Check_Project/jboss-eap-profile/config/standalone.xml',
  '/Users/KMBL400649/Documents/Config_Check_Project/jboss-eap-profile/config/host.xml'
]

control 'jboss-eap-01' do
  impact 1.0
  title 'Interfaces and Socket Bindings'
  desc 'Check for secure interface and socket binding configuration.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<interface.*security-realm=/) }
      its('content') { should match(/<socket-binding-group/) }
    end
  end
end

control 'jboss-eap-02' do
  impact 1.0
  title 'Legacy Security Subsystem'
  desc 'Ensure legacy security subsystem is enabled.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<subsystem xmlns="urn:jboss:domain:security/) }
    end
  end
end

control 'jboss-eap-03' do
  impact 1.0
  title 'Enabling the security subsystem'
  desc 'Security subsystem should be present.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<subsystem xmlns="urn:jboss:domain:security/) }
    end
  end
end

control 'jboss-eap-04' do
  impact 1.0
  title 'Authentication and socket bindings for management interfaces'
  desc 'Management interfaces should use authentication and secure socket bindings.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<management-interfaces>/) }
      its('content') { should match(/<http-interface.*security-realm=/) }
    end
  end
end

control 'jboss-eap-05' do
  impact 1.0
  title 'HTTPS Listener Reference'
  desc 'HTTPS listener should be configured.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<https-listener/) }
    end
  end
end

control 'jboss-eap-06' do
  impact 1.0
  title 'Disabling the Management Console'
  desc 'Management console should be disabled if not needed.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should_not match(/<console-handler/) }
    end
  end
end

control 'jboss-eap-07' do
  impact 1.0
  title 'Disabling Remote Access to JMX'
  desc 'Remote JMX access should be disabled.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should_not match(/<connector name="jmxrmi"/) }
    end
  end
end

control 'jboss-eap-08' do
  impact 1.0
  title 'Silent Authentication'
  desc 'Silent authentication should be disabled.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should_not match(/silent-authentication-enabled="true"/) }
    end
  end
end

control 'jboss-eap-09' do
  impact 1.0
  title 'One-way SSL/TLS for Management Interfaces'
  desc 'Management interfaces should be configured for one-way SSL/TLS.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<ssl.*key-store/) }
    end
  end
end

control 'jboss-eap-10' do
  impact 1.0
  title 'File Audit Logging'
  desc 'File audit logging should be enabled.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<file-handler/) }
    end
  end
end

control 'jboss-eap-11' do
  impact 1.0
  title 'Periodic Rotating File Audit Logging'
  desc 'Periodic rotating file audit logging should be enabled.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<periodic-rotating-file-handler/) }
    end
  end
end

control 'jboss-eap-12' do
  impact 1.0
  title 'Size Rotating File Audit Logging'
  desc 'Size rotating file audit logging should be enabled.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<size-rotating-file-handler/) }
    end
  end
end

control 'jboss-eap-13' do
  impact 1.0
  title 'Syslog Audit Logging'
  desc 'Syslog audit logging should be enabled.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<syslog-handler/) }
    end
  end
end

control 'jboss-eap-14' do
  impact 1.0
  title 'SSL/TLS for Legacy Core Management Auth'
  desc 'SSL or TLS should be configured for legacy core management authentication.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<ssl.*key-store/) }
    end
  end
end

control 'jboss-eap-15' do
  impact 1.0
  title 'Role-Based Access Control'
  desc 'Role-based access control should be enabled.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<role-mapping/) }
    end
  end
end

control 'jboss-eap-16' do
  impact 1.0
  title 'Permission Combination Policy'
  desc 'Permission combination policy should be set.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<permission-combination-policy/) }
    end
  end
end

control 'jboss-eap-17' do
  impact 1.0
  title 'Credential Store for Standalone Server'
  desc 'Credential store should be configured for standalone server.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<credential-store/) }
    end
  end
end

control 'jboss-eap-18' do
  impact 1.0
  title 'Add Credential to Credential Store'
  desc 'Credential should be added to the credential store.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/<credential name=/) }
    end
  end
end

control 'jboss-eap-19' do
  impact 1.0
  title 'Use Stored Credential in Configuration'
  desc 'Stored credential should be referenced in configuration.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/\$\{VAULT::/) }
    end
  end
end

control 'jboss-eap-20' do
  impact 1.0
  title 'Encrypted Sensitive String in Application'
  desc 'Encrypted sensitive string should be used in application config.'
  JBOSS_CONFIG_FILES.each do |file|
    describe file(file) do
      its('content') { should match(/ENC\(/) }
    end
  end
end
