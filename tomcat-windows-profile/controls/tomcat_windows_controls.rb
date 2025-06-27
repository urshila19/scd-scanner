# Tomcat on Windows Config-Only Security Controls

TOMCAT_HOME = File.expand_path('../config', __dir__)
TOMCAT_CONF_SERVER = File.join(TOMCAT_HOME, 'server.xml')
TOMCAT_CONF_WEB = File.join(TOMCAT_HOME, 'web.xml')
TOMCAT_CONF_CONTEXT = File.join(TOMCAT_HOME, 'context.xml')
TOMCAT_CONF_CATALINA_PROPERTIES = File.join(TOMCAT_HOME, 'catalina.properties')
TOMCAT_CONF_LOGGING = File.join(TOMCAT_HOME, 'logging.properties')
TOMCAT_CONF_USERS = File.join(TOMCAT_HOME, 'tomcat-users.xml')
TOMCAT_APP_DIR = File.expand_path('../webapps', __dir__)

# 1. OLD VERSION USED
control 'tomcat-win-01' do
  impact 1.0
  title 'OLD VERSION USED'
  desc 'Ensure Tomcat is not running an old or unsupported version.'
  describe file(TOMCAT_CONF_SERVER) do
    its('content') { should_not match /Apache Tomcat\/(6|7|8)/ }
  end
end

# 2. IMPROPER FILE PERMISSIONS
control 'tomcat-win-02' do
  impact 1.0
  title 'IMPROPER FILE PERMISSIONS'
  desc 'Ensure Tomcat config files have restrictive Windows ACLs.'
  describe file(TOMCAT_CONF_SERVER) do
    it { should be_owned_by 'tomcat' }
    it { should_not be_readable_by('Everyone') }
  end
end

# 3. RESTRICT ACCESS TO TOMCAT’S CONTROL AND CONNECTOR PORTS
control 'tomcat-win-03' do
  impact 1.0
  title 'RESTRICT ACCESS TO TOMCAT’S CONTROL AND CONNECTOR PORTS'
  desc 'Ensure Tomcat ports are not exposed to untrusted networks.'
  describe port(8005) do
    it { should_not be_listening }
  end
  describe port(8080) do
    it { should be_listening }
  end
end

# 4. USING AN UNPRIVILEGED ACCOUNT FOR RUNNING TOMCAT
control 'tomcat-win-04' do
  impact 1.0
  title 'USING AN UNPRIVILEGED ACCOUNT FOR RUNNING TOMCAT'
  desc 'Ensure Tomcat is running as an unprivileged user.'
  describe processes('tomcat') do
    its('users') { should_not include 'Administrator' }
  end
end

# 5. CRITICAL FILES TO RESTRICT ACCESS
control 'tomcat-win-05' do
  impact 1.0
  title 'CRITICAL FILES TO RESTRICT ACCESS'
  desc 'Ensure critical Tomcat files are not accessible by Everyone.'
  %w[server.xml web.xml context.xml catalina.properties logging.properties tomcat-users.xml].each do |f|
    describe file(File.join(TOMCAT_HOME, f)) do
      it { should_not be_readable_by('Everyone') }
    end
  end
end

# 6. DEFAULT TOMCAT APPLICATIONS NOT REMOVED
control 'tomcat-win-06' do
  impact 1.0
  title 'DEFAULT TOMCAT APPLICATIONS NOT REMOVED'
  desc 'Ensure default Tomcat applications are removed.'
  %w[examples docs manager host-manager].each do |app|
    describe file(File.join(TOMCAT_APP_DIR, app)) do
      it { should_not exist }
    end
  end
end

# 7. PASSWORDS STORED IN PLAIN TEXT
control 'tomcat-win-07' do
  impact 1.0
  title 'PASSWORDS STORED IN PLAIN TEXT'
  desc 'Ensure passwords in tomcat-users.xml are not stored in plain text.'
  describe file(TOMCAT_CONF_USERS) do
    its('content') { should_not match /password="[^"]+"/ }
  end
end

# 8. JAVA SECURITY MANAGER TURNED OFF
control 'tomcat-win-08' do
  impact 1.0
  title 'JAVA SECURITY MANAGER TURNED OFF'
  desc 'Ensure Java Security Manager is enabled.'
  describe file(TOMCAT_CONF_CATALINA_PROPERTIES) do
    its('content') { should match /security\.manager\.enabled=true/ }
  end
end

# 9. TOMCAT NOT SECURED WITH SSL/TLS & WEAK CIPHERS USED
control 'tomcat-win-09' do
  impact 1.0
  title 'TOMCAT NOT SECURED WITH SSL/TLS & WEAK CIPHERS USED'
  desc 'Ensure SSL/TLS is enabled and weak ciphers are not used.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@SSLEnabled']) { should include 'true' }
    its(['//Connector/@sslProtocol']) { should include 'TLS' }
    its(['//Connector/@ciphers']) { should_not match /NULL|RC4|DES|MD5/ }
  end
end

# 10. TOMCAT DEFAULT NAME/BANNER NOT CHANGED
control 'tomcat-win-10' do
  impact 1.0
  title 'TOMCAT DEFAULT NAME/BANNER NOT CHANGED'
  desc 'Ensure Tomcat serverInfo is customized.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Server/@serverInfo']) { should_not match /Apache Tomcat/ }
  end
end

# 11. UNNECESSARY OPEN TOMCAT CONNECTORS
control 'tomcat-win-11' do
  impact 1.0
  title 'UNNECESSARY OPEN TOMCAT CONNECTORS'
  desc 'Ensure unnecessary connectors are disabled.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector[@protocol="AJP/1.3"]/@enabled']) { should_not include 'true' }
  end
end

# 12. WEB SERVER AND/OR OPERATING SYSTEM INFORMATION IS ADVERTISED
control 'tomcat-win-12' do
  impact 1.0
  title 'WEB SERVER AND/OR OPERATING SYSTEM INFORMATION IS ADVERTISED'
  desc 'Ensure server header does not leak OS or server info.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@server']) { should_not match /Apache-Coyote|Windows/ }
  end
end

# 13. HIDE TOMCAT VERSION NUMBER FROM ERROR PAGES
control 'tomcat-win-13' do
  impact 1.0
  title 'HIDE TOMCAT VERSION NUMBER FROM ERROR PAGES'
  desc 'Ensure Tomcat version is not shown in error pages.'
  describe file(TOMCAT_CONF_WEB) do
    its('content') { should_not match /Tomcat\/\d/ }
  end
end

# 14. SESSION TIMEOUT
control 'tomcat-win-14' do
  impact 1.0
  title 'SESSION TIMEOUT'
  desc 'Ensure session timeout is set in web.xml.'
  describe xml(TOMCAT_CONF_WEB) do
    its(['//session-config/session-timeout']) { should_not be_empty }
  end
end

# 15. DISABLE THE SHUTDOWN PORT
control 'tomcat-win-15' do
  impact 1.0
  title 'DISABLE THE SHUTDOWN PORT'
  desc 'Ensure shutdown port is disabled.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Server/@port']) { should cmp '-1' }
  end
end

# 16. Use Lockout realms
control 'tomcat-win-16' do
  impact 1.0
  title 'Use Lockout realms'
  desc 'Ensure LockOutRealm is used.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Realm/@className']) { should include 'org.apache.catalina.realm.LockOutRealm' }
  end
end

# 17. Use secure realms
control 'tomcat-win-17' do
  impact 1.0
  title 'Use secure realms'
  desc 'Ensure secure Realms are used.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Realm/@className']) { should_not include 'org.apache.catalina.realm.MemoryRealm' }
  end
end

# 18. Hide Tomcat server.number String
control 'tomcat-win-18' do
  impact 1.0
  title 'Hide Tomcat server.number String'
  desc 'Ensure server.number is not default.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Server/@serverNumber']) { should_not cmp '9.0.0.0' }
  end
end

# 19. Hide Tomcat server.built Date
control 'tomcat-win-19' do
  impact 1.0
  title 'Hide Tomcat server.built Date'
  desc 'Ensure server.built is not default.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Server/@serverBuilt']) { should_not cmp 'unknown' }
  end
end

# 20. Disable client facing stack traces
control 'tomcat-win-20' do
  impact 1.0
  title 'Disable client facing stack traces'
  desc 'Ensure stack traces are not exposed to clients.'
  describe xml(TOMCAT_CONF_WEB) do
    its(['//error-page/exception-type']) { should_not be_empty }
  end
end

# 21. Turn off TRACE
control 'tomcat-win-21' do
  impact 1.0
  title 'Turn off TRACE'
  desc 'Ensure TRACE HTTP method is disabled.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@allowTrace']) { should_not include 'true' }
  end
end

# 22. Ensure className is set correctly in context.xml
control 'tomcat-win-22' do
  impact 1.0
  title 'Ensure className is set correctly in context.xml'
  desc 'Ensure className is set to org.apache.catalina.core.StandardContext.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@className']) { should include 'org.apache.catalina.core.StandardContext' }
  end
end

# 23. Restrict runtime access to sensitive packages
control 'tomcat-win-23' do
  impact 1.0
  title 'Restrict runtime access to sensitive packages'
  desc 'Ensure package.access and package.definition are set.'
  describe file(TOMCAT_CONF_CATALINA_PROPERTIES) do
    its('content') { should match /^package\.access/ }
    its('content') { should match /^package\.definition/ }
  end
end

# 24. Disabling auto deployment of applications
control 'tomcat-win-24' do
  impact 1.0
  title 'Disabling auto deployment of applications'
  desc 'Ensure autoDeploy is set to false.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Host/@autoDeploy']) { should include 'false' }
  end
end

# 25. Restrict access to the web administration application
control 'tomcat-win-25' do
  impact 1.0
  title 'Restrict access to the web administration application'
  desc 'Ensure web administration is restricted.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Valve/@className']) { should include 'org.apache.catalina.valves.RemoteAddrValve' }
  end
end

# 26. Restrict manager application
control 'tomcat-win-26' do
  impact 1.0
  title 'Restrict manager application'
  desc 'Ensure manager application is restricted.'
  describe file(File.join(TOMCAT_APP_DIR, 'manager')) do
    it { should_not exist }
  end
end

# 27. Force SSL when accessing the manager application via HTTP
control 'tomcat-win-27' do
  impact 1.0
  title 'Force SSL when accessing the manager application via HTTP'
  desc 'Ensure SSL is required for manager application.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@scheme']) { should include 'https' }
  end
end

# 28. Rename the manager application
control 'tomcat-win-28' do
  impact 1.0
  title 'Rename the manager application'
  desc 'Ensure the manager application is renamed from the default.'
  describe file(File.join(TOMCAT_APP_DIR, 'manager')) do
    it { should_not exist }
  end
end

# 29. Enable strict servlet Compliance
control 'tomcat-win-29' do
  impact 1.0
  title 'Enable strict servlet Compliance'
  desc 'Ensure strict servlet compliance is enabled.'
  describe xml(TOMCAT_CONF_WEB) do
    its(['//web-app/@metadata-complete']) { should include 'true' }
  end
end

# 30. Turn off session facade recycling
control 'tomcat-win-30' do
  impact 1.0
  title 'Turn off session facade recycling'
  desc 'Ensure session facade recycling is disabled.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@sessionCookiePathUsesTrailingSlash']) { should include 'false' }
  end
end

# 31. Do not allow additional path delimiters
control 'tomcat-win-31' do
  impact 1.0
  title 'Do not allow additional path delimiters'
  desc 'Ensure allowAdditionalPathDelimiters is false.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@allowAdditionalPathDelimiters']) { should include 'false' }
  end
end

# 32. Configure connectionTimeout
control 'tomcat-win-32' do
  impact 1.0
  title 'Configure connectionTimeout'
  desc 'Ensure connectionTimeout is set.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@connectionTimeout']) { should_not be_empty }
  end
end

# 33. Configure maxHttpHeaderSize
control 'tomcat-win-33' do
  impact 1.0
  title 'Configure maxHttpHeaderSize'
  desc 'Ensure maxHttpHeaderSize is set.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@maxHttpHeaderSize']) { should_not be_empty }
  end
end

# 34. Do not allow symbolic linking
control 'tomcat-win-34' do
  impact 1.0
  title 'Do not allow symbolic linking'
  desc 'Ensure allowLinking is false.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@allowLinking']) { should include 'false' }
  end
end

# 35. Do not allow cross context requests
control 'tomcat-win-35' do
  impact 1.0
  title 'Do not allow cross context requests'
  desc 'Ensure crossContext is false.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@crossContext']) { should include 'false' }
  end
end

# 36. Do not resolve hosts on logging valves
control 'tomcat-win-36' do
  impact 1.0
  title 'Do not resolve hosts on logging valves'
  desc 'Ensure resolveHosts is false on logging valves.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Valve/@resolveHosts']) { should include 'false' }
  end
end

# 37. Enable memory leak listener
control 'tomcat-win-37' do
  impact 1.0
  title 'Enable memory leak listener'
  desc 'Ensure memory leak listener is enabled.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Listener/@className']) { should include 'org.apache.catalina.core.JreMemoryLeakPreventionListener' }
  end
end

# 38. Setting Security Lifecycle Listener
control 'tomcat-win-38' do
  impact 1.0
  title 'Setting Security Lifecycle Listener'
  desc 'Ensure Security Lifecycle Listener is set.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Listener/@className']) { should include 'org.apache.catalina.security.SecurityListener' }
  end
end

# 39. Ensure Manager Application Passwords are Encrypted
control 'tomcat-win-39' do
  impact 1.0
  title 'Ensure Manager Application Passwords are Encrypted'
  desc 'Ensure passwords in tomcat-users.xml are encrypted.'
  describe file(TOMCAT_CONF_USERS) do
    its('content') { should_not match /password="[^"]+"/ }
  end
end
