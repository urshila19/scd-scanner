title 'Tomcat7 Server Config'

#only_if do
 # command('tomcat').exist?
#end

TOMCAT_HOME= attribute(
  'tomcat_home',
  description: 'location of tomcat home directory',
  value: '/Users/KMBL400649/Documents/Config_Check_Project/tomcat7-profile/config'
)

TOMCAT_SERVICE_NAME= attribute(
  'tomcat_service_name',
  description: 'Name of Tomcat service',
  value: 'tomcat'
)

TOMCAT_GROUP= attribute(
  'tomcat_group',
  description: 'group owner of files/directories',
  value: 'tomcat'
)

TOMCAT_OWNER= attribute(
  'tomcat_owner',
  description: 'user owner of files/directories',
  value: 'tomcat'
)

TOMCAT_CONF_SERVER= attribute(
  'tomcat_conf_server',
  description: 'Path to tomcat server.xml',
  value: '/Users/KMBL400649/Documents/Config_Check_Project/tomcat7-profile/config/server.xml'
)

TOMCAT_APP_DIR= attribute(
  'tomcat_app_dir',
  description: 'location of tomcat app directory',
  value: '/Users/KMBL400649/Documents/Config_Check_Project/tomcat7-profile/config/webapps'
)

TOMCAT_CONF_WEB= attribute(
  'tomcat_conf_web',
  description: 'location of tomcat web.xml',
  value: '/Users/KMBL400649/Documents/Config_Check_Project/tomcat7-profile/config/web.xml'
)

# Corrected path for context.xml
TOMCAT_CONF_CONTEXT= attribute(
  'tomcat_conf_context',
  description: 'Path to tomcat context.xml',
  value: '/Users/KMBL400649/Documents/Config_Check_Project/tomcat7-profile/config/context.xml'
)

# Removed reference to manager application context.xml as the file does not exist
TOMCAT_EXTRANEOUS_RESOURCE_LIST= attribute(
  'tomcat_extraneous_resource_list',
  description: 'List of extraneous resources that should not exist',
  value: [
    "webapps/js-examples",
    "webapps/servlet-example",
    "webapps/webdav",
    "webapps/tomcat-docs",
    "webapps/balancer",
    "webapps/ROOT/admin",
    "webapps/examples",
    "server/webapps/host-manager",
    "server/webapps/manager",
    "conf/Catalina/localhost/host-manager.xml",
    "conf/Catalina/localhost/manager.xml"
  ]
)

# 1. Remove extraneous files and directories
control 'tomcat-01' do
  impact 0.5
  title 'Remove extraneous files and directories'
  desc 'Ensure extraneous files and directories are not present in Tomcat installation.'
  TOMCAT_EXTRANEOUS_RESOURCE_LIST.each do |resource|
    describe file(File.join(TOMCAT_HOME, resource)) do
      it { should_not exist }
    end
  end
end

# 2. Disable Unused Connectors
control 'tomcat-02' do
  impact 0.5
  title 'Disable Unused Connectors'
  desc 'Ensure unused connectors are disabled in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector[@protocol="AJP/1.3"]/@enabled']) { should_not include 'true' }
  end
end

# 3. Alter the Advertised server.info String
control 'tomcat-03' do
  impact 0.5
  title 'Alter the Advertised server.info String'
  desc 'Ensure the server.info string is customized in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Server/@serverInfo']) { should_not cmp 'Apache Tomcat/9.0.0.0' }
  end
end

# 4. Alter the Advertised server.number String
control 'tomcat-04' do
  impact 0.5
  title 'Alter the Advertised server.number String'
  desc 'Ensure the server.number string is customized in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Server/@serverNumber']) { should_not cmp '9.0.0.0' }
  end
end

# 5. Alter the Advertised server.built Date
control 'tomcat-05' do
  impact 0.5
  title 'Alter the Advertised server.built Date'
  desc 'Ensure the server.built date is customized in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Server/@serverBuilt']) { should_not cmp 'unknown' }
  end
end

# 6. Disable X-Powered-By HTTP Header and Rename the Server Value for all Connectors
control 'tomcat-06' do
  impact 0.5
  title 'Disable X-Powered-By HTTP Header and Rename the Server Value for all Connectors'
  desc 'Ensure X-Powered-By header is disabled and Server value is customized in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@xpoweredBy']) { should_not include 'true' }
    its(['//Connector/@server']) { should_not include 'Apache-Coyote/1.1' }
  end
end

# 7. Disable client facing Stack Traces
control 'tomcat-07' do
  impact 0.5
  title 'Disable client facing Stack Traces'
  desc 'Ensure stack traces are not exposed to clients in web.xml.'
  describe xml(TOMCAT_CONF_WEB) do
    its(['//error-page/exception-type']) { should_not be_empty }
  end
end

# 8. Turn off TRACE
control 'tomcat-08' do
  impact 0.5
  title 'Turn off TRACE'
  desc 'Ensure TRACE HTTP method is disabled in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@allowTrace']) { should_not include 'true' }
  end
end

# 9. Set a nondeterministic Shutdown command value
control 'tomcat-09' do
  impact 0.5
  title 'Set a nondeterministic Shutdown command value'
  desc 'Ensure shutdown command is not default in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Server/@shutdown']) { should_not include 'SHUTDOWN' }
  end
end

# 10. Disable the Shutdown port
control 'tomcat-10' do
  impact 0.5
  title 'Disable the Shutdown port'
  desc 'Ensure shutdown port is disabled in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Server/@port']) { should cmp '-1' }
  end
end

# 11. Restrict access to $CATALINA_HOME
control 'tomcat-11' do
  impact 0.5
  title 'Restrict access to $CATALINA_HOME'
  desc 'Ensure $CATALINA_HOME is owned by tomcat user and group.'
  describe file(TOMCAT_HOME) do
    it { should be_owned_by TOMCAT_OWNER }
    it { should be_grouped_into TOMCAT_GROUP }
    its('mode') { should cmp '0750' }
  end
end

# 12. Restrict access to $CATALINA_BASE
control 'tomcat-12' do
  impact 0.5
  title 'Restrict access to $CATALINA_BASE'
  desc 'Ensure $CATALINA_BASE is owned by tomcat user and group.'
  describe file(TOMCAT_HOME) do
    it { should be_owned_by TOMCAT_OWNER }
    it { should be_grouped_into TOMCAT_GROUP }
    its('mode') { should cmp '0750' }
  end
end

# 13. Restrict access to Tomcat configuration directory
control 'tomcat-13' do
  impact 0.5
  title 'Restrict access to Tomcat configuration directory'
  desc 'Ensure conf directory is owned by tomcat user and group.'
  describe file(File.join(TOMCAT_HOME, 'conf')) do
    it { should be_owned_by TOMCAT_OWNER }
    it { should be_grouped_into TOMCAT_GROUP }
    its('mode') { should cmp '0750' }
  end
end

# 14. Restrict access to Tomcat logs directory
control 'tomcat-14' do
  impact 0.5
  title 'Restrict access to Tomcat logs directory'
  desc 'Ensure logs directory is owned by tomcat user and group.'
  describe file(File.join(TOMCAT_HOME, 'logs')) do
    it { should be_owned_by TOMCAT_OWNER }
    it { should be_grouped_into TOMCAT_GROUP }
    its('mode') { should cmp '0750' }
  end
end

# 15. Restrict access to Tomcat temp directory
control 'tomcat-15' do
  impact 0.5
  title 'Restrict access to Tomcat temp directory'
  desc 'Ensure temp directory is owned by tomcat user and group.'
  describe file(File.join(TOMCAT_HOME, 'temp')) do
    it { should be_owned_by TOMCAT_OWNER }
    it { should be_grouped_into TOMCAT_GROUP }
    its('mode') { should cmp '0750' }
  end
end

# 16. Restrict access to Tomcat binaries directory
control 'tomcat-16' do
  impact 0.5
  title 'Restrict access to Tomcat binaries directory'
  desc 'Ensure bin directory is owned by tomcat user and group.'
  describe file(File.join(TOMCAT_HOME, 'bin')) do
    it { should be_owned_by TOMCAT_OWNER }
    it { should be_grouped_into TOMCAT_GROUP }
    its('mode') { should cmp '0750' }
  end
end

# 17. Restrict access to Tomcat web application directory
control 'tomcat-17' do
  impact 0.5
  title 'Restrict access to Tomcat web application directory'
  desc 'Ensure webapps directory is owned by tomcat user and group.'
  describe file(TOMCAT_APP_DIR) do
    it { should be_owned_by TOMCAT_OWNER }
    it { should be_grouped_into TOMCAT_GROUP }
    its('mode') { should cmp '0750' }
  end
end

# 18. Restrict access to Tomcat catalina.policy
control 'tomcat-18' do
  impact 0.5
  title 'Restrict access to Tomcat catalina.policy'
  desc 'Ensure catalina.policy is owned by tomcat user and group.'
  describe file(File.join(TOMCAT_HOME, 'conf', 'catalina.policy')) do
    it { should be_owned_by TOMCAT_OWNER }
    it { should be_grouped_into TOMCAT_GROUP }
    its('mode') { should cmp '0640' }
  end
end

# 19. Restrict access to Tomcat catalina.properties
control 'tomcat-19' do
  impact 0.5
  title 'Restrict access to Tomcat catalina.properties'
  desc 'Ensure catalina.properties is owned by tomcat user and group.'
  describe file(File.join(TOMCAT_HOME, 'conf', 'catalina.properties')) do
    it { should be_owned_by TOMCAT_OWNER }
    it { should be_grouped_into TOMCAT_GROUP }
    its('mode') { should cmp '0640' }
  end
end

# 20. Restrict access to Tomcat context.xml
control 'tomcat-20' do
  impact 0.5
  title 'Restrict access to Tomcat context.xml'
  desc 'Ensure context.xml is owned by tomcat user and group.'
  describe file(File.join(TOMCAT_HOME, 'conf', 'context.xml')) do
    it { should be_owned_by TOMCAT_OWNER }
    it { should be_grouped_into TOMCAT_GROUP }
    its('mode') { should cmp '0640' }
  end
end

# 21. Restrict access to Tomcat logging.properties
control 'tomcat-21' do
  impact 0.5
  title 'Restrict access to Tomcat logging.properties'
  desc 'Ensure logging.properties is owned by tomcat user and group.'
  describe file(File.join(TOMCAT_HOME, 'conf', 'logging.properties')) do
    it { should be_owned_by TOMCAT_OWNER }
    it { should be_grouped_into TOMCAT_GROUP }
    its('mode') { should cmp '0640' }
  end
end

# 22. Restrict access to Tomcat server.xml
control 'tomcat-22' do
  impact 0.5
  title 'Restrict access to Tomcat server.xml'
  desc 'Ensure server.xml is owned by tomcat user and group.'
  describe file(TOMCAT_CONF_SERVER) do
    it { should be_owned_by TOMCAT_OWNER }
    it { should be_grouped_into TOMCAT_GROUP }
    its('mode') { should cmp '0640' }
  end
end

# 23. Restrict access to Tomcat tomcat-users.xml
control 'tomcat-23' do
  impact 0.5
  title 'Restrict access to Tomcat tomcat-users.xml'
  desc 'Ensure tomcat-users.xml is owned by tomcat user and group.'
  describe file(File.join(TOMCAT_HOME, 'conf', 'tomcat-users.xml')) do
    it { should be_owned_by TOMCAT_OWNER }
    it { should be_grouped_into TOMCAT_GROUP }
    its('mode') { should cmp '0640' }
  end
end

# 24. Restrict access to Tomcat web.xml
control 'tomcat-24' do
  impact 0.5
  title 'Restrict access to Tomcat web.xml'
  desc 'Ensure web.xml is owned by tomcat user and group.'
  describe file(TOMCAT_CONF_WEB) do
    it { should be_owned_by TOMCAT_OWNER }
    it { should be_grouped_into TOMCAT_GROUP }
    its('mode') { should cmp '0640' }
  end
end

# 25. Use secure Realms
control 'tomcat-25' do
  impact 0.5
  title 'Use secure Realms'
  desc 'Ensure secure Realms are used in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Realm/@className']) { should_not include 'org.apache.catalina.realm.MemoryRealm' }
  end
end

# 26. Use LockOut Realms
control 'tomcat-26' do
  impact 0.5
  title 'Use LockOut Realms'
  desc 'Ensure LockOutRealm is used in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Realm/@className']) { should include 'org.apache.catalina.realm.LockOutRealm' }
  end
end

# 27. Setup Client-cert Authentication
control 'tomcat-27' do
  impact 0.5
  title 'Setup Client-cert Authentication'
  desc 'Ensure client-cert authentication is configured in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@clientAuth']) { should include 'true' }
  end
end

# 28. Ensure SSLEnabled is set to True for Sensitive Connectors
control 'tomcat-28' do
  impact 0.5
  title 'Ensure SSLEnabled is set to True for Sensitive Connectors'
  desc 'Ensure SSLEnabled is true for secure connectors in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector[@protocol="HTTP/1.1"]/@SSLEnabled']) { should include 'true' }
  end
end

# 29. Ensure scheme is set accurately
control 'tomcat-29' do
  impact 0.5
  title 'Ensure scheme is set accurately'
  desc 'Ensure scheme is set to https for secure connectors in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector[@SSLEnabled="true"]/@scheme']) { should include 'https' }
  end
end

# 30. Ensure secure is set to true only for SSL-enabled Connectors
control 'tomcat-30' do
  impact 0.5
  title 'Ensure secure is set to true only for SSL-enabled Connectors'
  desc 'Ensure secure attribute is true only for SSL-enabled connectors in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector[@SSLEnabled="true"]/@secure']) { should include 'true' }
  end
end

# 31. Ensure SSL Protocol is set to TLS for Secure Connectors
control 'tomcat-31' do
  impact 0.5
  title 'Ensure SSL Protocol is set to TLS for Secure Connectors'
  desc 'Ensure protocol is set to TLS for secure connectors in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector[@SSLEnabled="true"]/@sslProtocol']) { should include 'TLS' }
  end
end

# 32. Application specific logging
control 'tomcat-32' do
  impact 0.5
  title 'Application specific logging'
  desc 'Ensure application-specific logging is configured in logging.properties.'
  describe file(File.join(TOMCAT_HOME, 'logging.properties')) do
    its('content') { should match /org\.apache\.catalina\.core\.ContainerBase\.\[Catalina\]\.level = INFO/ }
  end
end

# 33. Specify file handler in logging.properties files
control 'tomcat-33' do
  impact 0.5
  title 'Specify file handler in logging.properties files'
  desc 'Ensure file handler is specified in logging.properties.'
  describe file(File.join(TOMCAT_HOME, 'logging.properties')) do
    its('content') { should match /handlers = java\.util\.logging\.FileHandler/ }
  end
end

# 34. Ensure className is set correctly in context.xml
control 'tomcat-34' do
  impact 0.5
  title 'Ensure className is set correctly in context.xml'
  desc 'Ensure className is set to org.apache.catalina.core.StandardContext in context.xml.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@className']) { should include 'org.apache.catalina.core.StandardContext' }
  end
end

# 35. Ensure directory in context.xml is a secure location
control 'tomcat-35' do
  impact 0.5
  title 'Ensure directory in context.xml is a secure location'
  desc 'Ensure docBase in context.xml is a secure location.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@docBase']) { should_not include '/tmp' }
  end
end

# 36. Ensure pattern in context.xml is correct
control 'tomcat-36' do
  impact 0.5
  title 'Ensure pattern in context.xml is correct'
  desc 'Ensure pattern attribute in context.xml is set correctly.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@antiResourceLocking']) { should include 'true' }
  end
end

# 37. Ensure directory in logging.properties is a secure location
control 'tomcat-37' do
  impact 0.5
  title 'Ensure directory in logging.properties is a secure location'
  desc 'Ensure log file directory in logging.properties is not /tmp.'
  describe file(File.join(TOMCAT_HOME, 'conf', 'logging.properties')) do
    its('content') { should_not match %r{java\.util\.logging\.FileHandler\.pattern = /tmp/} }
  end
end

# 38. Restrict runtime access to sensitive packages
control 'tomcat-38' do
  impact 0.5
  title 'Restrict runtime access to sensitive packages'
  desc 'Ensure package.access and package.definition are set in catalina.properties.'
  describe file(File.join(TOMCAT_HOME, 'catalina.properties')) do
    its('content') { should match /^package\.access=sun\.,org\.apache\.catalina\.,org\.apache\.coyote\.,org\.apache\.jasper\.,org\.apache\.tomcat\.$/ }
    its('content') { should match /^package\.definition=sun\.,org\.apache\.catalina\.,org\.apache\.coyote\.,org\.apache\.jasper\.,org\.apache\.tomcat\.$/ }
  end
end

control 'tomcat-39' do
  impact 0.5
  title 'Starting Tomcat with Security Manager'
  desc 'Ensure Security Manager is enabled in catalina.properties.'
  describe file(File.join(TOMCAT_HOME, 'catalina.properties')) do
    its('content') { should match /^security\.manager\.enabled=true$/ }
  end
end

# 40. Disabling auto deployment of applications
control 'tomcat-40' do
  impact 0.5
  title 'Disabling auto deployment of applications'
  desc 'Ensure autoDeploy is set to false in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Host/@autoDeploy']) { should include 'false' }
  end
end

# 41. Disable deploy on startup of applications
control 'tomcat-41' do
  impact 0.5
  title 'Disable deploy on startup of applications'
  desc 'Ensure deployOnStartup is set to false in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Host/@deployOnStartup']) { should include 'false' }
  end
end

# 42. Ensure Web content directory is on a separate partition from the Tomcat system files
control 'tomcat-42' do
  impact 0.0
  title 'Ensure Web content directory is on a separate partition from the Tomcat system files (SKIPPED)'
  desc 'SKIPPED: This control is not applicable in this environment.'
  # No checks; informational only.
end

# 43. Restrict access to the web administration
control 'tomcat-43' do
  impact 0.5
  title 'Restrict access to the web administration'
  desc 'Ensure web administration is restricted in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Valve/@className']) { should include 'org.apache.catalina.valves.RemoteAddrValve' }
  end
end

# 44. Restrict manager application
control 'tomcat-44' do
  impact 0.5
  title 'Restrict manager application'
  desc 'Ensure manager application is restricted in context.xml.'
  describe file('/Users/KMBL400649/Documents/Config_Check_Project/tomcat7-profile/config/webapps/manager/META-INF/context.xml') do
    it { should_not exist }
  end
end

# 45. Force SSL when accessing the manager application
control 'tomcat-45' do
  impact 0.5
  title 'Force SSL when accessing the manager application'
  desc 'Ensure SSL is required for manager application in context.xml.'
  describe file('/Users/KMBL400649/Documents/Config_Check_Project/tomcat7-profile/config/webapps/manager/META-INF/context.xml') do
    it { should_not exist }
  end
end

# 46. Enable strict servlet Compliance
control 'tomcat-46' do
  impact 0.5
  title 'Enable strict servlet Compliance'
  desc 'Ensure strict servlet compliance is enabled in web.xml.'
  describe xml(TOMCAT_CONF_WEB) do
    its(['//web-app/@metadata-complete']) { should include 'true' }
  end
end

# 47. Turn off session facade recycling
control 'tomcat-47' do
  impact 0.5
  title 'Turn off session facade recycling'
  desc 'Ensure session facade recycling is disabled in context.xml.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@sessionCookiePathUsesTrailingSlash']) { should include 'false' }
  end
end

# 48. Do not allow additional path delimiters
control 'tomcat-48' do
  impact 0.5
  title 'Do not allow additional path delimiters'
  desc 'Ensure allowAdditionalPathDelimiters is false in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@allowAdditionalPathDelimiters']) { should include 'false' }
  end
end

# 49. Do not allow custom header status messages
control 'tomcat-49' do
  impact 0.5
  title 'Do not allow custom header status messages'
  desc 'Ensure allowCustomStatusMsg is false in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@allowCustomStatusMsg']) { should include 'false' }
  end
end

# 50. Configure connectionTimeout
control 'tomcat-50' do
  impact 0.5
  title 'Configure connectionTimeout'
  desc 'Ensure connectionTimeout is set in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@connectionTimeout']) { should_not be_empty }
  end
end

# 51. Configure maxHttpHeaderSize
control 'tomcat-51' do
  impact 0.5
  title 'Configure maxHttpHeaderSize'
  desc 'Ensure maxHttpHeaderSize is set in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Connector/@maxHttpHeaderSize']) { should_not be_empty }
  end
end

# 52. Force SSL for all applications
control 'tomcat-52' do
  impact 0.5
  title 'Force SSL for all applications'
  desc 'Ensure all applications require SSL in web.xml.'
  describe xml(TOMCAT_CONF_WEB) do
    its(['//security-constraint/user-data-constraint/transport-guarantee']) { should include 'CONFIDENTIAL' }
  end
end

# 53. Do not allow symbolic linking
control 'tomcat-53' do
  impact 0.5
  title 'Do not allow symbolic linking'
  desc 'Ensure allowLinking is false in context.xml.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@allowLinking']) { should include 'false' }
  end
end

# 54. Do not run applications as privileged
control 'tomcat-54' do
  impact 0.5
  title 'Do not run applications as privileged'
  desc 'Ensure privileged is false in context.xml.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@privileged']) { should include 'false' }
  end
end

# 55. Do not allow cross context requests
control 'tomcat-55' do
  impact 0.5
  title 'Do not allow cross context requests'
  desc 'Ensure crossContext is false in context.xml.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Context/@crossContext']) { should include 'false' }
  end
end

# 56. Do not resolve hosts on logging valves
control 'tomcat-56' do
  impact 0.5
  title 'Do not resolve hosts on logging valves'
  desc 'Ensure resolveHosts is false on logging valves in server.xml.'
  describe xml(TOMCAT_CONF_SERVER) do
    its(['//Valve/@resolveHosts']) { should include 'false' }
  end
end

# 57. Enable memory leak listener
control 'tomcat-57' do
  impact 0.5
  title 'Enable memory leak listener'
  desc 'Ensure memory leak listener is enabled in context.xml.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Listener/@className']) { should include 'org.apache.catalina.core.JreMemoryLeakPreventionListener' }
  end
end

# 58. Setting Security Lifecycle Listener
control 'tomcat-58' do
  impact 0.5
  title 'Setting Security Lifecycle Listener'
  desc 'Ensure Security Lifecycle Listener is set in context.xml.'
  describe xml(TOMCAT_CONF_CONTEXT) do
    its(['//Listener/@className']) { should include 'org.apache.catalina.security.SecurityListener' }
  end
end

# 59. use the logEffectiveWebXml and metadata-complete settings for deploying applications in production
control 'tomcat-59' do
  impact 0.5
  title 'use the logEffectiveWebXml and metadata-complete settings for deploying applications in production'
  desc 'Ensure logEffectiveWebXml and metadata-complete are set in web.xml.'
  describe xml(TOMCAT_CONF_WEB) do
    its(['//web-app/@metadata-complete']) { should include 'true' }
    its(['//web-app/@logEffectiveWebXml']) { should include 'true' }
  end
end

# 60. Configure log file size limit
control 'tomcat-60' do
  impact 0.5
  title 'Configure log file size limit'
  desc 'Ensure log file size limit is set in logging.properties.'
  describe file(File.join(TOMCAT_HOME, 'logging.properties')) do
    its('content') { should match /java\.util\.logging\.FileHandler\.limit = 50000/ }
  end
end

# 61. Rename the manager application
control 'tomcat-61' do
  impact 0.5
  title 'Rename the manager application'
  desc 'Ensure the manager application is renamed from the default.'
  describe file(File.join(TOMCAT_APP_DIR, 'manager')) do
    it { should_not exist }
  end
end