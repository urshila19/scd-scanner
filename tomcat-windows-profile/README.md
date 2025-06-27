# Tomcat on Windows Config-Only Security Controls

This InSpec profile implements config-only security controls for Tomcat running on Windows.

## Usage

1. Place your Tomcat configuration files in the `config/` directory.
2. Run the profile with:

```sh
inspec exec .
```

## Controls

This profile covers the following controls:

- Version checks
- File permissions (Windows ACLs)
- Port restrictions
- Account privilege checks
- Application and connector hardening
- Password and encryption checks
- SSL/TLS and cipher configuration
- Banner and error page hardening
- Session and deployment settings
- And more (see `controls/tomcat_windows_controls.rb`)
