# IBM WebSphere InSpec Profile

This profile checks IBM WebSphere security configuration using only config file analysis.

- Controls are in `controls/ibm_websphere_controls.rb`
- Sample config files are in `config/`

## Usage

Run the profile from the parent directory:

```sh
inspec exec ibm-websphere-profile --reporter cli html:ibmwebsphere.html
```

## Profile Structure

- `inspec.yml` - Profile metadata
- `controls/` - InSpec controls
- `config/` - Sample configuration files
