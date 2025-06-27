# Tomcat 8 Security Config Profile

This InSpec profile implements 63 config-only security controls for Tomcat 8, checking only configuration files and permissions. All sample config files are included in the `config/` directory.

## Sample Config Files
- config/server.xml
- config/web.xml
- config/context.xml
- config/catalina.properties
- config/catalina.policy
- config/logging.properties
- config/tomcat-users.xml

## Usage
- Place your Tomcat 8 config files in the `config/` directory or use the provided samples.
- Run `inspec exec .` from the `tomcat8-profile` directory.

## Controls
All controls are config-file-only and compatible with macOS.
