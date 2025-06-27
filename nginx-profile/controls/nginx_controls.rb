title 'NGINX Server Config'

#only_if do
 # command('nginx').exist?
#end

# determine all required paths
nginx_path          = attribute('nginx_path', value: '/Users/KMBL400649/Documents/Config_Check_Project/nginx-profile/config', description: 'Default nginx configurations path')
nginx_conf          = File.join(nginx_path, 'nginx.conf')
nginx_confd         = File.join(nginx_path, 'conf.d')
nginx_enabled       = File.join(nginx_path, 'sites-enabled')
nginx_parsed_config = command("nginx -c #{nginx_conf} -T").stdout

options = {
  assignment_regex: /^\s*([^:]*?)\s*\ \s*(.*?)\s*;$/,
}

options_add_header = {
  assignment_regex: /^\s*([^:]*?)\s*\ \s*(.*?)\s*;$/,
  multiple_values: true,
}

# 1 Ensure HTTP WebDAV module is not installed
control 'nginx-10.1' do
  impact 0.5
  title 'Ensure HTTP WebDAV module is not installed'
  desc 'The http_dav_module enables file-based operations on your web server. It should not be installed unless required.'
  describe file(nginx_conf) do
    its('content') { should_not match /http_dav_module/ }
  end
end

# # 2 Ensure modules with gzip functionality are disabled
# control 'nginx-10.2' do
#   impact 0.0
#   title 'Ensure modules with gzip functionality are disabled'
#   desc 'Skipped: Homebrew NGINX is always built with --with-http_gzip_static_module on macOS.'
#   only_if('Homebrew NGINX is always built with --with-http_gzip_static_module on macOS.') { false }
# end

# 3 Ensure the autoindex module is disabled
control 'nginx-10.3' do
  impact 0.5
  title 'Ensure the autoindex module is disabled'
  desc 'Directory listing should be disabled to prevent information disclosure.'
  describe parse_config(nginx_parsed_config, options) do
    its('autoindex') { should_not eq 'on' }
  end
end

# 4 Ensure the NGINX service account is locked
control 'nginx-10.4' do
  impact 0.3
  title 'Ensure the NGINX service account is locked'
  desc 'The nginx user account should be locked to prevent logins.'
  passwd = file('/etc/passwd').content
  only_if('nginx user not present in /etc/passwd, skipping control') do
    passwd.match(/^nginx:/)
  end
  describe file('/etc/shadow') do
    its('content') { should match /^nginx:!|\*:/ }
  end
end

# 5 Ensure the NGINX service account has an invalid shell
control 'nginx-10.5' do
  impact 0.5
  title 'Ensure the NGINX service account has an invalid shell'
  desc 'The nginx account should have /sbin/nologin as its shell.'
  passwd = file('/etc/passwd').content
  only_if('nginx user not present in /etc/passwd, skipping control') do
    passwd.match(/^nginx:/)
  end
  describe file('/etc/passwd') do
    its('content') { should match %r{^nginx:.*:.*:.*:.*:.*:.*:/sbin/nologin$} }
  end
end

# 6 Ensure NGINX directories and files are owned by root
control 'nginx-10.6' do
  impact 0.5
  title 'Ensure NGINX directories and files are owned by root'
  desc 'The owner and group of the /etc/nginx directory and its files should be root.'
  describe file(File.join(nginx_path)) do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

# 7 Ensure access to NGINX directories and files is restricted
control 'nginx-10.7' do
  impact 0.5
  title 'Ensure access to NGINX directories and files is restricted'
  desc 'Permissions on the /etc/nginx directory should enforce the principle of least privilege.'
  describe file(nginx_path) do
    its('mode') { should cmp '0750' }
  end
  command("find #{nginx_path} -type f").stdout.split.each do |f|
    describe file(f) do
      its('mode') { should cmp '0640' }
    end
  end
end

# 8 Ensure the NGINX process ID (PID) file is secured
control 'nginx-10.8' do
  impact 0.5
  title 'Ensure the NGINX process ID (PID) file is secured'
  desc 'The PID file should be owned by root and have permissions 644.'
  describe file(File.join(nginx_path, 'nginx.pid')) do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    its('mode') { should cmp '0644' }
  end
end

# 9 Ensure keepalive_timeout is 10 seconds or less, but not 0
control 'nginx-10.9' do
  impact 0.3
  title 'Ensure keepalive_timeout is 10 seconds or less, but not 0'
  desc 'Set keepalive_timeout to 10 seconds or less, but not 0.'
  describe file(nginx_conf) do
    its('content') { should match /keepalive_timeout\s+([1-9]|10);/ }
  end
end

# 10 Ensure send_timeout is set to 10 seconds or less, but not 0
control 'nginx-10.10' do
  impact 0.3
  title 'Ensure send_timeout is set to 10 seconds or less, but not 0'
  desc 'Set send_timeout to 10 seconds or less, but not 0.'
  describe file(nginx_conf) do
    its('content') { should match /send_timeout\s+([1-9]|10)s?;/ }
  end
end

# 11 Ensure server_tokens directive is set to off
control 'nginx-10.11' do
  impact 0.3
  title 'Ensure server_tokens directive is set to off'
  desc 'The server_tokens directive should be set to off.'
  describe file(nginx_conf) do
    its('content') { should match /server_tokens\s+off;/ }
  end
end

# 12 Ensure default error and index.html pages do not reference NGINX
control 'nginx-10.12' do
  impact 0.3
  title 'Ensure default error and index.html pages do not reference NGINX'
  desc 'Default error and index.html pages should not disclose NGINX.'
  %w[/usr/share/nginx/html/index.html /usr/share/nginx/html/50x.html].each do |f|
    describe file(f) do
      its('content') { should_not match /nginx/i }
    end
  end
end

# 13 Ensure the NGINX reverse proxy does not enable information disclosure
control 'nginx-10.13' do
  impact 0.3
  title 'Ensure the NGINX reverse proxy does not enable information disclosure'
  desc 'The server and x-powered-by headers should be hidden by proxy.'
  describe file(nginx_conf) do
    its('content') { should match /proxy_hide_header\s+Server;/ }
    its('content') { should match /proxy_hide_header\s+X-Powered-By;/ }
  end
end

# 14 Ensure access logging is enabled
control 'nginx-10.14' do
  impact 0.7
  title 'Ensure access logging is enabled'
  desc 'The access_log directive should be enabled for every core site.'
  describe parse_config(nginx_parsed_config, options) do
    its('access_log') { should_not eq 'off' }
  end
end

# 15 Ensure error logging is enabled and set to the info logging level
control 'nginx-10.15' do
  impact 0.5
  title 'Ensure error logging is enabled and set to the info logging level'
  desc 'The error_log directive should be present and set to info or higher.'
  describe file(nginx_conf) do
    its('content') { should match /error_log\s+\S+\s+(info|notice|warn|error|crit|alert|emerg);/ }
  end
end

# 16 Ensure log files are rotated
control 'nginx-10.16' do
  impact 0.5
  title 'Ensure log files are rotated'
  desc 'Log rotation should be configured for nginx logs.'
  logrotate_file = File.join(nginx_path, 'logrotate.d', 'nginx')
  describe file(logrotate_file) do
    it { should exist }
    its('content') { should match(/rotate\s+\d+/) }
  end
end

# 17 Ensure proxies pass source IP information
control 'nginx-10.17' do
  impact 0.3
  title 'Ensure proxies pass source IP information'
  desc 'proxy_set_header X-Real-IP and X-Forwarded-For should be set.'
  describe file(nginx_conf) do
    its('content') { should match /proxy_set_header\s+X-Real-IP\s+\$remote_addr/ }
    its('content') { should match /proxy_set_header\s+X-Forwarded-For\s+\$proxy_add_x_forwarded_for/ }
  end
end


# 18 Ensure HTTP is redirected to HTTPS
control 'nginx-10.18' do
  impact 0.5
  title 'Ensure HTTP is redirected to HTTPS'
  desc 'HTTP should be redirected to HTTPS using a return 301 directive.'
  describe file(nginx_conf) do
    its('content') { should match /return\s+301\s+https:\/\// }
  end
end

# 19 Ensure private key permissions are restricted
control 'nginx-10.19' do
  impact 0.3
  title 'Ensure private key permissions are restricted'
  desc 'The server private key file should have permissions 400.'
  describe file(File.join(nginx_path, 'nginx.key')) do
    it { should exist }
    its('mode') { should cmp '0400' }
  end
end

# 20 Ensure only modern TLS protocols are used
control 'nginx-10.20' do
  impact 0.5
  title 'Ensure only modern TLS protocols are used'
  desc 'Only TLSv1.2 or higher should be enabled.'
  describe file(nginx_conf) do
    its('content') { should match /ssl_protocols\s+TLSv1\.2/ }
    its('content') { should_not match /ssl_protocols\s+.*(SSLv3|TLSv1(\.0)?|TLSv1\.1)/ }
  end
end

# 21 Disable weak ciphers
control 'nginx-10.21' do
  impact 0.5
  title 'Disable weak ciphers'
  desc 'ssl_ciphers and proxy_ssl_ciphers should not include weak ciphers.'
  describe parse_config(nginx_parsed_config, options) do
    its('ssl_ciphers') { should_not match(/EXP|NULL|ADH|LOW|SSLv2|SSLv3|MD5|RC4/) }
    its('proxy_ssl_ciphers') { should_not match(/EXP|NULL|ADH|LOW|SSLv2|SSLv3|MD5|RC4/) }
  end
end

# 22 Ensure custom Diffie-Hellman parameters are used
control 'nginx-10.22' do
  impact 0.5
  title 'Ensure custom Diffie-Hellman parameters are used'
  desc 'Custom DH parameters should be used for ssl_dhparam.'
  describe file(nginx_conf) do
    its('content') { should match %r{ssl_dhparam\s+#{nginx_path}/ssl/dhparam\.pem;} }
  end
  describe file(File.join(nginx_path, 'ssl', 'dhparam.pem')) do
    it { should exist }
    its('mode') { should cmp '0400' }
  end
end

# 23 Ensure Online Certificate Status Protocol (OCSP) stapling is enabled
control 'nginx-10.23' do
  impact 0.3
  title 'Ensure OCSP stapling is enabled'
  desc 'ssl_stapling and ssl_stapling_verify should be on.'
  describe file(nginx_conf) do
    its('content') { should match /ssl_stapling\s+on;/ }
    its('content') { should match /ssl_stapling_verify\s+on;/ }
  end
end

# 24 Ensure HTTP Strict Transport Security (HSTS) is enabled
control 'nginx-10.24' do
  impact 0.5
  title 'Ensure HTTP Strict Transport Security (HSTS) is enabled'
  desc 'Strict-Transport-Security header should be set with a long max-age.'
  describe file(nginx_conf) do
    its('content') { should match /add_header\s+Strict-Transport-Security\s+["']max-age=15768000["']/ }
  end
end

# 25 Ensure session resumption is disabled to enable perfect forward security
control 'nginx-10.25' do
  impact 0.3
  title 'Ensure session resumption is disabled to enable perfect forward security'
  desc 'ssl_session_tickets should be set to off.'
  describe file(nginx_conf) do
    its('content') { should match /ssl_session_tickets\s+off;/ }
  end
end

# 26 Ensure timeout values for reading the client header and body are set correctly
control 'nginx-10.26' do
  impact 0.3
  title 'Ensure timeout values for reading the client header and body are set correctly'
  desc 'client_header_timeout and client_body_timeout should be set to 10 seconds.'
  describe file(nginx_conf) do
    its('content') { should match /client_header_timeout\s+10;/ }
    its('content') { should match /client_body_timeout\s+10;/ }
  end
end

# 27 Ensure the maximum request body size is set correctly
control 'nginx-10.27' do
  impact 0.5
  title 'Ensure the maximum request body size is set correctly'
  desc 'client_max_body_size should be set to 100K.'
  describe file(nginx_conf) do
    its('content') { should match /client_max_body_size\s+100K;/ }
  end
end

# 28 Ensure the maximum buffer size for URIs is defined
control 'nginx-10.28' do
  impact 0.5
  title 'Ensure the maximum buffer size for URIs is defined'
  desc 'large_client_header_buffers should be set to 2 1k.'
  describe file(nginx_conf) do
    its('content') { should match /large_client_header_buffers\s+2\s+1k;/ }
  end
end

# 29 Ensure X-Frame-Options header is configured and enabled
control 'nginx-10.29' do
  impact 0.5
  title 'Ensure X-Frame-Options header is configured and enabled'
  desc 'X-Frame-Options header should be set to SAMEORIGIN.'
  describe file(nginx_conf) do
    its('content') { should match /add_header\s+X-Frame-Options\s+SAMEORIGIN/ }
  end
end

# 30 Ensure X-Content-Type-Options header is configured and enabled
control 'nginx-10.30' do
  impact 0.5
  title 'Ensure X-Content-Type-Options header is configured and enabled'
  desc 'X-Content-Type-Options header should be set to nosniff.'
  describe file(nginx_conf) do
    its('content') { should match /add_header\s+X-Content-Type-Options\s+nosniff/ }
  end
end

# 31 Ensure the X-XSS-Protection Header is enabled and configured properly
control 'nginx-10.31' do
  impact 0.5
  title 'Ensure the X-XSS-Protection Header is enabled and configured properly'
  desc 'X-Xss-Protection header should be set to 1; mode=block.'
  describe file(nginx_conf) do
    its('content') { should match /add_header\s+X-Xss-Protection\s+["']1; mode=block["']/ }
  end
end

# 32 Ensure that Content Security Policy (CSP) is enabled and configured properly
control 'nginx-10.32' do
  impact 0.3
  title 'Ensure that Content Security Policy (CSP) is enabled and configured properly'
  desc 'Content-Security-Policy header should be set to default-src \'self\'.'
  describe file(nginx_conf) do
    its('content') { should match /add_header\s+Content-Security-Policy\s+["']default-src 'self'["']/ }
  end
end

# 33 Ensure the Referrer Policy is enabled and configured properly
control 'nginx-10.33' do
  impact 0.5
  title 'Ensure the Referrer Policy is enabled and configured properly'
  desc 'Referrer-Policy header should be set to no-referrer.'
  describe file(nginx_conf) do
    its('content') { should match /add_header\s+Referrer-Policy\s+no-referrer/ }
  end
end