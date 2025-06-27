# Tomcat 8 Config-Only Security Controls

TOMCAT_HOME = '/Users/KMBL400649/Documents/Config_Check_Project/tomcat8-profile/config'
TOMCAT_CONF_SERVER = File.join(TOMCAT_HOME, 'server.xml')
TOMCAT_CONF_WEB = File.join(TOMCAT_HOME, 'web.xml')
TOMCAT_CONF_CONTEXT = File.join(TOMCAT_HOME, 'context.xml')
TOMCAT_CONF_CATALINA_PROPERTIES = File.join(TOMCAT_HOME, 'catalina.properties')
TOMCAT_CONF_CATALINA_POLICY = File.join(TOMCAT_HOME, 'catalina.policy')
TOMCAT_CONF_LOGGING = File.join(TOMCAT_HOME, 'logging.properties')
TOMCAT_CONF_USERS = File.join(TOMCAT_HOME, 'tomcat-users.xml')
TOMCAT_APP_DIR = '/Users/KMBL400649/Documents/Config_Check_Project/tomcat8-profile/webapps'

# 1. Remove extraneous files and directories
control 'tomcat8-01' do
  impact 0.5
  title 'Remove extraneous files and directories'
  desc 'Ensure extraneous files and directories are not present in Tomcat installation.'
  extraneous = [
    'webapps/examples',
    'webapps/ROOT/admin',
    'webapps/manager',
    'webapps/host-manager',
    'webapps/js-examples',
    'webapps/servlet-example',
    'webapps/webdav',
    'webapps/tomcat-docs',
    'webapps/balancer',
    'conf/Catalina/localhost/host-manager.xml',
    'conf/Catalina/localhost/manager.xml'
  ]
  extraneous.each do |resource|
    describe file(File.join(TOMCAT_HOME, resource)) do
      it { should_not exist }
    end
  end
end

# 2. Disable Unused Connectors
control 'tomcat8-02' do
  impact 0.5
  title 'Disable Unused Connectors'
  desc 'Ensure unused connectors are disabled in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector[@protocol="AJP/1.3"]/@enabled']) { should_not include 'true' }
  end
end

# 3. Alter the Advertised server.info String
control 'tomcat8-03' do
  impact 0.5
  title 'Alter the Advertised server.info String'
  desc 'Ensure the server.info string is customized in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Server/@serverInfo']) { should_not cmp 'Apache Tomcat/8.0.0.0' }
  end
end

# 4. Alter the Advertised server.number String
control 'tomcat8-04' do
  impact 0.5
  title 'Alter the Advertised server.number String'
  desc 'Ensure the server.number string is customized in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Server/@serverNumber']) { should_not cmp '8.0.0.0' }
  end
end

# 5. Alter the Advertised server.built Date
control 'tomcat8-05' do
  impact 0.5
  title 'Alter the Advertised server.built Date'
  desc 'Ensure the server.built date is customized in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Server/@serverBuilt']) { should_not cmp 'unknown' }
  end
end

# 6. Disable X-Powered-By HTTP Header and Rename the Server Value for all Connectors
control 'tomcat8-06' do
  impact 0.5
  title 'Disable X-Powered-By HTTP Header and Rename the Server Value for all Connectors'
  desc 'Ensure X-Powered-By header is disabled and Server value is customized in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@xpoweredBy']) { should_not include 'true' }
    its(['//Connector/@server']) { should_not include 'Apache-Coyote/1.1' }
  end
end

# 7. Disable client facing Stack Traces
control 'tomcat8-07' do
  impact 0.5
  title 'Disable client facing Stack Traces'
  desc 'Ensure stack traces are not exposed to clients in web.xml.'
  describe xml(TOMCAT_CONF_WEB) do
    its(['//error-page/exception-type']) { should_not be_empty }
  end
end

# 8. Turn off TRACE
control 'tomcat8-08' do
  impact 0.5
  title 'Turn off TRACE'
  desc 'Ensure TRACE HTTP method is disabled in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@allowTrace']) { should_not include 'true' }
  end
end

# 9. Ensure Sever Header is Modified To Prevent Information Disclosure
control 'tomcat8-09' do
  impact 0.5
  title 'Ensure Sever Header is Modified To Prevent Information Disclosure'
  desc 'Ensure the Server header is customized in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@server']) { should_not include 'Apache-Coyote/1.1' }
  end
end

# 10. Set a nondeterministic Shutdown command value
control 'tomcat8-10' do
  impact 0.5
  title 'Set a nondeterministic Shutdown command value'
  desc 'Ensure shutdown command is not default in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Server/@shutdown']) { should_not include 'SHUTDOWN' }
  end
end

# 11. Disable the Shutdown port
control 'tomcat8-11' do
  impact 0.5
  title 'Disable the Shutdown port'
  desc 'Ensure shutdown port is disabled in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Server/@port']) { should cmp '-1' }
  end
end

# 12. Restrict access to $CATALINA_HOME
control 'tomcat8-12' do
  impact 0.5
  title 'Restrict access to $CATALINA_HOME'
  desc 'Ensure $CATALINA_HOME is owned by tomcat user and group.'
  describe file(TOMCAT_HOME) do
    it { should be_owned_by 'tomcat' }
    it { should be_grouped_into 'tomcat' }
    its('mode') { should cmp '0750' }
  end
end

# 13. Restrict access to $CATALINA_BASE
control 'tomcat8-13' do
  impact 0.5
  title 'Restrict access to $CATALINA_BASE'
  desc 'Ensure $CATALINA_BASE is owned by tomcat user and group.'
  describe file(TOMCAT_HOME) do
    it { should be_owned_by 'tomcat' }
    it { should be_grouped_into 'tomcat' }
    its('mode') { should cmp '0750' }
  end
end

# 14. Restrict access to Tomcat configuration directory
control 'tomcat8-14' do
  impact 0.5
  title 'Restrict access to Tomcat configuration directory'
  desc 'Ensure conf directory is owned by tomcat user and group.'
  describe file(TOMCAT_HOME) do
    it { should be_owned_by 'tomcat' }
    it { should be_grouped_into 'tomcat' }
    its('mode') { should cmp '0750' }
  end
end

# 15. Restrict access to Tomcat logs directory
control 'tomcat8-15' do
  impact 0.5
  title 'Restrict access to Tomcat logs directory'
  desc 'Ensure logs directory is owned by tomcat user and group.'
  describe file(File.join(TOMCAT_HOME, 'logs')) do
    it { should be_owned_by 'tomcat' }
    it { should be_grouped_into 'tomcat' }
    its('mode') { should cmp '0750' }
  end
end

# 16. Restrict access to Tomcat temp directory
control 'tomcat8-16' do
  impact 0.5
  title 'Restrict access to Tomcat temp directory'
  desc 'Ensure temp directory is owned by tomcat user and group.'
  describe file(File.join(TOMCAT_HOME, 'temp')) do
    it { should be_owned_by 'tomcat' }
    it { should be_grouped_into 'tomcat' }
    its('mode') { should cmp '0750' }
  end
end

# 17. Restrict access to Tomcat binaries directory
control 'tomcat8-17' do
  impact 0.5
  title 'Restrict access to Tomcat binaries directory'
  desc 'Ensure bin directory is owned by tomcat user and group.'
  describe file(File.join(TOMCAT_HOME, 'bin')) do
    it { should be_owned_by 'tomcat' }
    it { should be_grouped_into 'tomcat' }
    its('mode') { should cmp '0750' }
  end
end

# 18. Restrict access to Tomcat web application directory
control 'tomcat8-18' do
  impact 0.5
  title 'Restrict access to Tomcat web application directory'
  desc 'Ensure webapps directory is owned by tomcat user and group.'
  describe file(TOMCAT_APP_DIR) do
    it { should be_owned_by 'tomcat' }
    it { should be_grouped_into 'tomcat' }
    its('mode') { should cmp '0750' }
  end
end

# 19. Restrict access to Tomcat catalina.policy
control 'tomcat8-19' do
  impact 0.5
  title 'Restrict access to Tomcat catalina.policy'
  desc 'Ensure catalina.policy is owned by tomcat user and group.'
  describe file(TOMCAT_CONF_CATALINA_POLICY) do
    it { should be_owned_by 'tomcat' }
    it { should be_grouped_into 'tomcat' }
    its('mode') { should cmp '0640' }
  end
end

# 20. Restrict access to Tomcat catalina.properties
control 'tomcat8-20' do
  impact 0.5
  title 'Restrict access to Tomcat catalina.properties'
  desc 'Ensure catalina.properties is owned by tomcat user and group.'
  describe file(TOMCAT_CONF_CATALINA_PROPERTIES) do
    it { should be_owned_by 'tomcat' }
    it { should be_grouped_into 'tomcat' }
    its('mode') { should cmp '0640' }
  end
end

# 21. Restrict access to Tomcat context.xml
control 'tomcat8-21' do
  impact 0.5
  title 'Restrict access to Tomcat context.xml'
  desc 'Ensure context.xml is owned by tomcat user and group.'
  describe file(TOMCAT_CONF_CONTEXT) do
    it { should be_owned_by 'tomcat' }
    it { should be_grouped_into 'tomcat' }
    its('mode') { should cmp '0640' }
  end
end

# 22. Restrict access to Tomcat logging.properties
control 'tomcat8-22' do
  impact 0.5
  title 'Restrict access to Tomcat logging.properties'
  desc 'Ensure logging.properties is owned by tomcat user and group.'
  describe file(TOMCAT_CONF_LOGGING) do
    it { should be_owned_by 'tomcat' }
    it { should be_grouped_into 'tomcat' }
    its('mode') { should cmp '0640' }
  end
end

# 23. Restrict access to Tomcat server.xml
control 'tomcat8-23' do
  impact 0.5
  title 'Restrict access to Tomcat server.xml'
  desc 'Ensure server.xml is owned by tomcat user and group.'
  describe file(TOMCAT_CONF_SERVER) do
    it { should be_owned_by 'tomcat' }
    it { should be_grouped_into 'tomcat' }
    its('mode') { should cmp '0640' }
  end
end

# 24. Restrict access to Tomcat tomcat-users.xml
control 'tomcat8-24' do
  impact 0.5
  title 'Restrict access to Tomcat tomcat-users.xml'
  desc 'Ensure tomcat-users.xml is owned by tomcat user and group.'
  describe file(TOMCAT_CONF_USERS) do
    it { should be_owned_by 'tomcat' }
    it { should be_grouped_into 'tomcat' }
    its('mode') { should cmp '0640' }
  end
end

# 25. Restrict access to Tomcat web.xml
control 'tomcat8-25' do
  impact 0.5
  title 'Restrict access to Tomcat web.xml'
  desc 'Ensure web.xml is owned by tomcat user and group.'
  describe file(TOMCAT_CONF_WEB) do
    it { should be_owned_by 'tomcat' }
    it { should be_grouped_into 'tomcat' }
    its('mode') { should cmp '0640' }
  end
end

# 26. Use secure Realms
control 'tomcat8-26' do
  impact 0.5
  title 'Use secure Realms'
  desc 'Ensure secure Realms are used in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Realm/@className']) { should_not include 'org.apache.catalina.realm.MemoryRealm' }
  end
end

# 27. Use LockOut Realms
control 'tomcat8-27' do
  impact 0.5
  title 'Use LockOut Realms'
  desc 'Ensure LockOutRealm is used in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Realm/@className']) { should include 'org.apache.catalina.realm.LockOutRealm' }
  end
end

# 28. Setup Client-cert Authentication
control 'tomcat8-28' do
  impact 0.5
  title 'Setup Client-cert Authentication'
  desc 'Ensure client-cert authentication is configured in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@clientAuth']) { should include 'true' }
  end
end

# 29. Ensure SSLEnabled is set to True for Sensitive Connectors
control 'tomcat8-29' do
  impact 0.5
  title 'Ensure SSLEnabled is set to True for Sensitive Connectors'
  desc 'Ensure SSLEnabled is true for secure connectors in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector[@protocol="HTTP/1.1"]/@SSLEnabled']) { should include 'true' }
  end
end

# 30. Ensure scheme is set accurately
control 'tomcat8-30' do
  impact 0.5
  title 'Ensure scheme is set accurately'
  desc 'Ensure scheme is set to https for secure connectors in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector[@SSLEnabled="true"]/@scheme']) { should include 'https' }
  end
end

# 31. Ensure secure is set to true only for SSL-enabled Connectors
control 'tomcat8-31' do
  impact 0.5
  title 'Ensure secure is set to true only for SSL-enabled Connectors'
  desc 'Ensure secure attribute is true only for SSL-enabled connectors in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector[@SSLEnabled="true"]/@secure']) { should include 'true' }
  end
end

# 32. Ensure SSL Protocol is set to TLS for Secure Connectors
control 'tomcat8-32' do
  impact 0.5
  title 'Ensure SSL Protocol is set to TLS for Secure Connectors'
  desc 'Ensure protocol is set to TLS for secure connectors in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector[@SSLEnabled="true"]/@sslProtocol']) { should include 'TLS' }
  end
end

# 33. Control the maximum size of a POST request that will be parsed for parameter
control 'tomcat8-33' do
  impact 0.5
  title 'Control the maximum size of a POST request that will be parsed for parameter'
  desc 'Ensure maxPostSize is set in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@maxPostSize']) { should_not be_empty }
  end
end

# 34. Application specific logging
control 'tomcat8-34' do
  impact 0.5
  title 'Application specific logging'
  desc 'Ensure application-specific logging is configured in logging.properties.'
  describe file(TOMCAT_CONF_LOGGING) do
    its('content') { should match /org\.apache\.catalina\.core\.ContainerBase\.\[Catalina\]\.level/ }
  end
end

# 35. Specify file handler in logging.properties files
control 'tomcat8-35' do
  impact 0.5
  title 'Specify file handler in logging.properties files'
  desc 'Ensure file handler is specified in logging.properties.'
  describe file(TOMCAT_CONF_LOGGING) do
    its('content') { should match /handlers = java\.util\.logging\.FileHandler/ }
  end
end

# 36. Ensure className is set correctly in context.xml
control 'tomcat8-36' do
  impact 0.5
  title 'Ensure className is set correctly in context.xml'
  desc 'Ensure className is set to org.apache.catalina.core.StandardContext in context.xml.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@className']) { should include 'org.apache.catalina.core.StandardContext' }
  end
end

# 37. Ensure directory in context.xml is a secure location
control 'tomcat8-37' do
  impact 0.5
  title 'Ensure directory in context.xml is a secure location'
  desc 'Ensure docBase in context.xml is a secure location.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@docBase']) { should_not include '/tmp' }
  end
end

# 38. Ensure pattern in context.xml is correct
control 'tomcat8-38' do
  impact 0.5
  title 'Ensure pattern in context.xml is correct'
  desc 'Ensure antiResourceLocking is true in context.xml.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@antiResourceLocking']) { should include 'true' }
  end
end

# 39. Ensure directory in logging.properties is a secure location
control 'tomcat8-39' do
  impact 0.5
  title 'Ensure directory in logging.properties is a secure location'
  desc 'Ensure log file directory in logging.properties is not /tmp.'
  describe file(TOMCAT_CONF_LOGGING) do
    its('content') { should_not match %r{java\.util\.logging\.FileHandler\.pattern = /tmp/} }
  end
end

# 40. Restrict runtime access to sensitive packages
control 'tomcat8-40' do
  impact 0.5
  title 'Restrict runtime access to sensitive packages'
  desc 'Ensure package.access and package.definition are set in catalina.properties.'
  describe file(TOMCAT_CONF_CATALINA_PROPERTIES) do
    its('content') { should match /^package\.access/ }
    its('content') { should match /^package\.definition/ }
  end
end

# 41. Starting Tomcat with Security Manager
control 'tomcat8-41' do
  impact 0.5
  title 'Starting Tomcat with Security Manager'
  desc 'Ensure Security Manager is enabled in catalina.properties.'
  describe file(TOMCAT_CONF_CATALINA_PROPERTIES) do
    its('content') { should match /security\.manager\.enabled=true/ }
  end
end

# 42. Disabling auto deployment of applications
control 'tomcat8-42' do
  impact 0.5
  title 'Disabling auto deployment of applications'
  desc 'Ensure autoDeploy is set to false in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Host/@autoDeploy']) { should include 'false' }
  end
end

# 43. Disable deploy on startup of applications
control 'tomcat8-43' do
  impact 0.5
  title 'Disable deploy on startup of applications'
  desc 'Ensure deployOnStartup is set to false in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Host/@deployOnStartup']) { should include 'false' }
  end
end

# 44. Ensure Web content directory is on a separate partition from the Tomcat system files
control 'tomcat8-44' do
  impact 0.0
  title 'Ensure Web content directory is on a separate partition from the Tomcat system files (SKIPPED)'
  desc 'SKIPPED: This control is not applicable in this environment.'
  # No checks; informational only.
end

# 45. Restrict access to the web administration
control 'tomcat8-45' do
  impact 0.5
  title 'Restrict access to the web administration'
  desc 'Ensure web administration is restricted in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Valve/@className']) { should include 'org.apache.catalina.valves.RemoteAddrValve' }
  end
end

# 46. Restrict manager application
control 'tomcat8-46' do
  impact 0.5
  title 'Restrict manager application'
  desc 'Ensure manager application is restricted in context.xml.'
  describe xml(File.join(TOMCAT_APP_DIR, 'manager', 'META-INF', 'context.xml')) do
    its(['//Context/@antiResourceLocking']) { should include 'true' }
  end
end

# 47. Force SSL when accessing the manager application
control 'tomcat8-47' do
  impact 0.5
  title 'Force SSL when accessing the manager application'
  desc 'Ensure SSL is required for manager application in context.xml.'
  describe xml(File.join(TOMCAT_APP_DIR, 'manager', 'META-INF', 'context.xml')) do
    its(['//Context/@useHttpOnly']) { should include 'true' }
  end
end

# 48. Enable strict servlet Compliance
control 'tomcat8-48' do
  impact 0.5
  title 'Enable strict servlet Compliance'
  desc 'Ensure strict servlet compliance is enabled in web.xml.'
  describe xml(TOMCAT_CONF_WEB) do
    its(['//web-app/@metadata-complete']) { should include 'true' }
  end
end

# 49. Turn off session façade recycling
control 'tomcat8-49' do
  impact 0.5
  title 'Turn off session façade recycling'
  desc 'Ensure session facade recycling is disabled in context.xml.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@sessionCookiePathUsesTrailingSlash']) { should include 'false' }
  end
end

# 50. Do not allow additional path delimiters
control 'tomcat8-50' do
  impact 0.5
  title 'Do not allow additional path delimiters'
  desc 'Ensure allowAdditionalPathDelimiters is false in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@allowAdditionalPathDelimiters']) { should include 'false' }
  end
end

# 51. Do not allow custom header status messages
control 'tomcat8-51' do
  impact 0.5
  title 'Do not allow custom header status messages'
  desc 'Ensure allowCustomStatusMsg is false in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@allowCustomStatusMsg']) { should include 'false' }
  end
end

# 52. Configure connectionTimeout
control 'tomcat8-52' do
  impact 0.5
  title 'Configure connectionTimeout'
  desc 'Ensure connectionTimeout is set in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@connectionTimeout']) { should_not be_empty }
  end
end

# 53. Configure maxHttpHeaderSize
control 'tomcat8-53' do
  impact 0.5
  title 'Configure maxHttpHeaderSize'
  desc 'Ensure maxHttpHeaderSize is set in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@maxHttpHeaderSize']) { should_not be_empty }
  end
end

# 54. Force SSL for all applications
control 'tomcat8-54' do
  impact 0.5
  title 'Force SSL for all applications'
  desc 'Ensure all applications require SSL in web.xml.'
  describe xml(TOMCAT_CONF_WEB) do
    its(['//security-constraint/user-data-constraint/transport-guarantee']) { should include 'CONFIDENTIAL' }
  end
end

# 55. Do not allow symbolic linking
control 'tomcat8-55' do
  impact 0.5
  title 'Do not allow symbolic linking'
  desc 'Ensure allowLinking is false in context.xml.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@allowLinking']) { should include 'false' }
  end
end

# 56. Do not run applications as privileged
control 'tomcat8-56' do
  impact 0.5
  title 'Do not run applications as privileged'
  desc 'Ensure privileged is false in context.xml.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@privileged']) { should include 'false' }
  end
end

# 57. Do not allow cross context requests
control 'tomcat8-57' do
  impact 0.5
  title 'Do not allow cross context requests'
  desc 'Ensure crossContext is false in context.xml.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@crossContext']) { should include 'false' }
  end
end

# 58. Do not resolve hosts on logging valves
control 'tomcat8-58' do
  impact 0.5
  title 'Do not resolve hosts on logging valves'
  desc 'Ensure resolveHosts is false on logging valves in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Valve/@resolveHosts']) { should include 'false' }
  end
end

# 59. Enable memory leak listener
control 'tomcat8-59' do
  impact 0.5
  title 'Enable memory leak listener'
  desc 'Ensure memory leak listener is enabled in context.xml.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Listener/@className']) { should include 'org.apache.catalina.core.JreMemoryLeakPreventionListener' }
  end
end

# 60. Setting Security Lifecycle Listener
control 'tomcat8-60' do
  impact 0.5
  title 'Setting Security Lifecycle Listener'
  desc 'Ensure Security Lifecycle Listener is set in context.xml.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Listener/@className']) { should include 'org.apache.catalina.security.SecurityListener' }
  end
end

# 61. use the logEffectiveWebXml and metadata-complete settings for deploying applications in production
control 'tomcat8-61' do
  impact 0.5
  title 'use the logEffectiveWebXml and metadata-complete settings for deploying applications in production'
  desc 'Ensure logEffectiveWebXml and metadata-complete are set in web.xml.'
  describe xml(TOMCAT_CONF_WEB) do
    its(['//web-app/@metadata-complete']) { should include 'true' }
    its(['//web-app/@logEffectiveWebXml']) { should include 'true' }
  end
end

# 62. Limit HTTP Request Methods
control 'tomcat8-62' do
  impact 0.5
  title 'Limit HTTP Request Methods'
  desc 'Ensure HTTP request methods are limited in web.xml.'
  describe file(TOMCAT_CONF_WEB) do
    its('content') { should match /<http-method>POST<\/http-method>/ }
    its('content') { should_not match /<http-method>TRACE<\/http-method>/ }
  end
end

# 63. Rename the manager application
control 'tomcat8-63' do
  impact 0.5
  title 'Rename the manager application'
  desc 'Ensure the manager application is renamed from the default.'
  describe file(File.join(TOMCAT_APP_DIR, 'manager')) do
    it { should_not exist }
  end
end
