# Tomcat 9 Config-Only Security Controls

This InSpec profile implements config-only security controls for Tomcat 9, modeled after the Tomcat 8 and 7 profiles.

## Usage

1. Place your Tomcat 9 configuration files in the `config/` directory.
2. Run the profile with:

```sh
inspec exec .
```

## Controls

This profile covers the following controls:

- Remove extraneous files and directories
- Disable unused connectors
- Alter advertised server info/number/built
- Disable X-Powered-By and rename Server header
- Restrict access to configuration, logs, binaries, and webapps
- Enforce secure configuration in server.xml, web.xml, context.xml, catalina.properties, catalina.policy, logging.properties, tomcat-users.xml, jaspic-providers.xml
- And more (see `controls/tomcat9_controls.rb`)
