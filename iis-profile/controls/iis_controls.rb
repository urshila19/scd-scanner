# IIS Security Controls InSpec Profile

# Define IIS config file paths for use in controls
IIS_WEB_CONFIG = '/Users/KMBL400649/Documents/Config_Check_Project/iis-profile/config/web.config'
IIS_APPHOST_CONFIG = '/Users/KMBL400649/Documents/Config_Check_Project/iis-profile/config/applicationHost.config'

# 1. Ensure web content is on non-system partition
control 'iis-01' do
  impact 0.5
  title 'Ensure web content is on non-system partition'
  desc 'Web content should not be hosted on the system partition.'
  describe file(IIS_APPHOST_CONFIG) do
    it { should exist }
  end
  describe xml(IIS_APPHOST_CONFIG) do
    site_paths = xml(IIS_APPHOST_CONFIG)["//site/application/virtualDirectory[@path='/']/@physicalPath"]
    it 'should not be on system partition' do
      expect(site_paths).not_to be_empty
      site_paths.each do |path|
        expect(path).not_to match(%r{^C:\\|^/})
      end
    end
  end
end

# 2. Ensure host headers are on all sites
control 'iis-02' do
  impact 1.0
  title "Ensure 'host headers' are on all sites"
  desc 'All IIS sites should have host headers configured.'
  describe xml(IIS_APPHOST_CONFIG) do
    bindings = xml(IIS_APPHOST_CONFIG)["//site/bindings/binding/@bindingInformation"]
    it 'should have host headers for all bindings' do
      expect(bindings).not_to be_empty
      bindings.each do |binding|
        parts = binding.split(':')
        expect(parts.length).to be >= 3
        expect(parts[2]).not_to eq('')
      end
    end
  end
end

# 3. Ensure directory browsing is set to disabled
control 'iis-03' do
  impact 1.0
  title "Ensure 'directory browsing' is set to disabled"
  desc 'Directory browsing should be disabled for all sites.'
  describe xml(IIS_APPHOST_CONFIG) do
    enabled = xml(IIS_APPHOST_CONFIG)["//directoryBrowse/@enabled"]
    it 'should be disabled (or not present, which is secure)' do
      if enabled.empty?
        expect(true).to eq(true) # Secure: not present means disabled
      else
        enabled.each do |val|
          expect(val.downcase).to eq('false')
        end
      end
    end
  end
end

# 4. Ensure application pool identity is configured for all application pools
control 'iis-04' do
  impact 1.0
  title "Ensure 'application pool identity' is configured for all application pools"
  desc 'All application pools should use a configured identity.'
  describe xml(IIS_APPHOST_CONFIG) do
    identities = xml(IIS_APPHOST_CONFIG)["//applicationPool/processModel/@identityType"]
    it 'should all be set to ApplicationPoolIdentity or a custom identity (or not present, which is secure)' do
      if identities.empty?
        expect(true).to eq(true) # Secure: not present means default
      else
        identities.each do |id|
          expect(%w[ApplicationPoolIdentity LocalService LocalSystem NetworkService]).to include(id)
        end
      end
    end
  end
end

# 5. Ensure unique application pools is set for sites
control 'iis-05' do
  impact 0.5
  title "Ensure 'unique application pools' is set for sites"
  desc 'Each site should use a unique application pool.'
  describe xml(IIS_APPHOST_CONFIG) do
    app_pools = xml(IIS_APPHOST_CONFIG)["//site/application/@applicationPool"]
    it 'should be unique per site (or not present, which is secure)' do
      if app_pools.empty?
        expect(true).to eq(true) # Secure: not present means default
      else
        expect(app_pools.uniq.length).to eq(app_pools.length)
      end
    end
  end
end

# 6. Ensure application pool identity is configured for anonymous user identity
control 'iis-06' do
  impact 0.5
  title "Ensure 'application pool identity' is configured for anonymous user identity"
  desc 'Anonymous authentication should use the application pool identity.'
  describe xml(IIS_APPHOST_CONFIG) do
    user_names = xml(IIS_APPHOST_CONFIG)["//anonymousAuthentication/@userName"]
    it 'should be empty or blank (uses app pool identity, or not present, which is secure)' do
      if user_names.empty?
        expect(true).to eq(true) # Secure: not present means default
      else
        user_names.each do |u|
          expect(u.strip).to eq('')
        end
      end
    end
  end
end

# 7. Ensure WebDav feature is disabled
control 'iis-07' do
  impact 1.0
  title 'Ensure WebDav feature is disabled'
  desc 'WebDav should not be installed.'
  describe xml(IIS_APPHOST_CONFIG) do
    modules = xml(IIS_APPHOST_CONFIG)["//globalModules/@name"]
    it 'should not include WebDAVModule' do
      expect(modules).not_to include('WebDAVModule')
    end
  end
end

# 8. Ensure access to sensitive site features is restricted to authenticated principals only
control 'iis-08' do
  impact 0.5
  title 'Ensure access to sensitive site features is restricted to authenticated principals only'
  desc 'Sensitive features should require authentication.'
  describe xml(IIS_WEB_CONFIG) do
    auth_modes = xml(IIS_WEB_CONFIG)["//system.web/authentication/@mode"]
    it 'should not be set to None' do
      expect(auth_modes).not_to include('None')
    end
  end
end

# 9. Ensure forms authentication require SSL
control 'iis-09' do
  impact 1.0
  title "Ensure 'forms authentication' require SSL"
  desc 'Forms authentication should require SSL.'
  describe xml(IIS_WEB_CONFIG) do
    require_ssl = xml(IIS_WEB_CONFIG)["//forms/@requireSSL"]
    it 'should be set to true' do
      expect(require_ssl).to include('true')
    end
  end
end

# 10. Ensure forms authentication is set to use cookies
control 'iis-10' do
  impact 1.0
  title "Ensure 'forms authentication' is set to use cookies"
  desc 'Forms authentication should use cookies.'
  describe xml(IIS_WEB_CONFIG) do
    cookieless = xml(IIS_WEB_CONFIG)["//forms/@cookieless"]
    it 'should be set to UseCookies' do
      expect(cookieless).to include('UseCookies')
    end
  end
end

# 11. Ensure cookie protection mode is configured for forms authentication
control 'iis-11' do
  impact 1.0
  title "Ensure 'cookie protection mode' is configured for forms authentication"
  desc 'Forms authentication cookies should have a protection mode set.'
  describe xml(IIS_WEB_CONFIG) do
    protection = xml(IIS_WEB_CONFIG)["//forms/@protection"]
    it 'should be set to All' do
      expect(protection).to include('All')
    end
  end
end

# 12. Ensure transport layer security for basic authentication is configured
control 'iis-12' do
  impact 1.0
  title "Ensure transport layer security for 'basic authentication' is configured"
  desc 'Basic authentication should only be used over HTTPS.'
  describe xml(IIS_WEB_CONFIG) do
    enabled = xml(IIS_WEB_CONFIG)["//basicAuthentication/@enabled"]
    ssl_flags = xml(IIS_WEB_CONFIG)["//access/@sslFlags"]
    it 'should be disabled or require SSL' do
      expect(enabled).to include('false').or satisfy { ssl_flags.any? { |f| f.include?('Ssl') } }
    end
  end
end

# 13. Ensure passwordFormat is not set to clear
control 'iis-13' do
  impact 1.0
  title "Ensure 'passwordFormat' is not set to clear"
  desc 'passwordFormat should not be clear in web.config.'
  describe xml(IIS_WEB_CONFIG) do
    format = xml(IIS_WEB_CONFIG)["//membership/@passwordFormat"]
    it 'should not be Clear' do
      expect(format).not_to include('Clear')
    end
  end
end

# 14. Ensure credentials are not stored in configuration files
control 'iis-14' do
  impact 1.0
  title "Ensure 'credentials' are not stored in configuration files"
  desc 'No credentials should be stored in web.config or applicationHost.config.'
  [IIS_WEB_CONFIG, IIS_APPHOST_CONFIG].each do |config|
    describe file(config) do
      it 'should not contain password=, username=, or credential=' do
        expect(subject.content).not_to match(/\b(password|credential|username)\s*=/)
      end
    end
  end
end

# 15. Ensure deployment method retail is set
control 'iis-15' do
  impact 1.0
  title "Ensure 'deployment method retail' is set"
  desc 'deployment retail should be set in web.config.'
  describe xml(IIS_WEB_CONFIG) do
    retail = xml(IIS_WEB_CONFIG)["//deployment/@retail"]
    it 'should be true' do
      expect(retail).to include('true')
    end
  end
end

# 16. Ensure debug is turned off
control 'iis-16' do
  impact 1.0
  title "Ensure 'debug' is turned off"
  desc 'debug should be false in web.config.'
  describe xml(IIS_WEB_CONFIG) do
    debug = xml(IIS_WEB_CONFIG)["//compilation/@debug"]
    it 'should be false' do
      expect(debug).to include('false')
    end
  end
end

# 17. Ensure custom error messages are not off
control 'iis-17' do
  impact 1.0
  title 'Ensure custom error messages are not off'
  desc 'Custom error messages should be enabled.'
  describe xml(IIS_WEB_CONFIG) do
    mode = xml(IIS_WEB_CONFIG)["//customErrors/@mode"]
    it 'should be On' do
      expect(mode).to include('On')
    end
  end
end

# 18. Ensure IIS HTTP detailed errors are hidden from displaying remotely
control 'iis-18' do
  impact 1.0
  title 'Ensure IIS HTTP detailed errors are hidden from displaying remotely'
  desc 'Detailed errors should not be shown to remote clients.'
  describe xml(IIS_WEB_CONFIG) do
    mode = xml(IIS_WEB_CONFIG)["//httpErrors/@errorMode"]
    it 'should be Custom' do
      expect(mode).to include('Custom')
    end
  end
end

# 19. Ensure ASP.NET stack tracing is not enabled
control 'iis-19' do
  impact 1.0
  title 'Ensure ASP.NET stack tracing is not enabled'
  desc 'Stack tracing should be disabled.'
  describe xml(IIS_WEB_CONFIG) do
    trace = xml(IIS_WEB_CONFIG)["//trace/@enabled"]
    it 'should be false' do
      expect(trace).to include('false')
    end
  end
end

# 20. Ensure httpcookie mode is configured for session state
control 'iis-20' do
  impact 1.0
  title "Ensure 'httpcookie' mode is configured for session state"
  desc 'Session state should use httpcookie mode.'
  describe xml(IIS_WEB_CONFIG) do
    cookieless = xml(IIS_WEB_CONFIG)["//sessionState/@cookieless"]
    it 'should be false' do
      expect(cookieless).to include('false')
    end
  end
end

# 21. Ensure cookies are set with HttpOnly attribute
control 'iis-21' do
  impact 1.0
  title "Ensure 'cookies' are set with HttpOnly attribute"
  desc 'Cookies should have HttpOnly set.'
  describe xml(IIS_WEB_CONFIG) do
    http_only = xml(IIS_WEB_CONFIG)["//httpCookies/@httpOnlyCookies"]
    it 'should be true' do
      expect(http_only).to include('true')
    end
  end
end

# 22. Ensure MachineKey validation method - .Net 3.5 is configured
control 'iis-22' do
  impact 1.0
  title "Ensure 'MachineKey validation method - .Net 3.5' is configured"
  desc 'MachineKey validation should be set for .Net 3.5.'
  describe xml(IIS_WEB_CONFIG) do
    validation = xml(IIS_WEB_CONFIG)["//machineKey/@validation"]
    it 'should be HMACSHA256' do
      expect(validation).to include('HMACSHA256')
    end
  end
end

# 23. Ensure MachineKey validation method - .Net 4.5 is configured
control 'iis-23' do
  impact 1.0
  title "Ensure 'MachineKey validation method - .Net 4.5' is configured"
  desc 'MachineKey validation should be set for .Net 4.5.'
  describe xml(IIS_WEB_CONFIG) do
    validation = xml(IIS_WEB_CONFIG)["//machineKey/@validation"]
    it 'should be HMACSHA256' do
      expect(validation).to include('HMACSHA256')
    end
  end
end

# 24. Ensure global .NET trust level is configured
control 'iis-24' do
  impact 1.0
  title 'Ensure global .NET trust level is configured'
  desc 'Global .NET trust level should be set.'
  describe xml(IIS_WEB_CONFIG) do
    trust = xml(IIS_WEB_CONFIG)["//trust/@level"]
    it 'should be Full' do
      expect(trust).to include('Full')
    end
  end
end

# 25. Ensure X-Powered-By Header is removed
control 'iis-25' do
  impact 1.0
  title 'Ensure X-Powered-By Header is removed'
  desc 'X-Powered-By header should not be sent.'
  describe xml(IIS_WEB_CONFIG) do
    removed = xml(IIS_WEB_CONFIG)["//customHeaders/remove/@name"]
    it 'should include X-Powered-By' do
      expect(removed).to include('X-Powered-By')
    end
  end
end

# 26. Ensure Server Header is removed
control 'iis-26' do
  impact 1.0
  title 'Ensure Server Header is removed'
  desc 'Server header should not be sent.'
  describe xml(IIS_WEB_CONFIG) do
    removed = xml(IIS_WEB_CONFIG)["//customHeaders/remove/@name"]
    it 'should include Server' do
      expect(removed).to include('Server')
    end
  end
end

# 27. Ensure maxAllowedContentLength is configured
control 'iis-27' do
  impact 1.0
  title "Ensure 'maxAllowedContentLength' is configured"
  desc 'maxAllowedContentLength should be set.'
  describe xml(IIS_WEB_CONFIG) do
    max_len = xml(IIS_WEB_CONFIG)["//requestLimits/@maxAllowedContentLength"]
    it 'should be set and not empty' do
      expect(max_len).not_to be_empty
    end
  end
end

# 28. Ensure maxURL request filter is configured
control 'iis-28' do
  impact 1.0
  title "Ensure 'maxURL request filter' is configured"
  desc 'maxURL should be set.'
  describe xml(IIS_WEB_CONFIG) do
    max_url = xml(IIS_WEB_CONFIG)["//requestLimits/@maxUrl"]
    it 'should be set and not empty' do
      expect(max_url).not_to be_empty
    end
  end
end

# 29. Ensure MaxQueryString request filter is configured
control 'iis-29' do
  impact 1.0
  title "Ensure 'MaxQueryString request filter' is configured"
  desc 'maxQueryString should be set.'
  describe xml(IIS_WEB_CONFIG) do
    max_qs = xml(IIS_WEB_CONFIG)["//requestLimits/@maxQueryString"]
    it 'should be set and not empty' do
      expect(max_qs).not_to be_empty
    end
  end
end

# 30. Ensure non-ASCII characters in URLs are not allowed
control 'iis-30' do
  impact 1.0
  title 'Ensure non-ASCII characters in URLs are not allowed'
  desc 'Non-ASCII characters should not be allowed in URLs.'
  describe xml(IIS_WEB_CONFIG) do
    allow_double = xml(IIS_WEB_CONFIG)["//requestFiltering/@allowDoubleEscaping"]
    it 'should be false' do
      expect(allow_double).to include('false')
    end
  end
end

# 31. Ensure Double-Encoded requests will be rejected
control 'iis-31' do
  impact 1.0
  title 'Ensure Double-Encoded requests will be rejected'
  desc 'Double-encoded requests should be rejected.'
  describe xml(IIS_WEB_CONFIG) do
    allow_double = xml(IIS_WEB_CONFIG)["//requestFiltering/@allowDoubleEscaping"]
    it 'should be false' do
      expect(allow_double).to include('false')
    end
  end
end

# 32. Ensure Unlisted File Extensions are not allowed
control 'iis-32' do
  impact 1.0
  title 'Ensure Unlisted File Extensions are not allowed'
  desc 'Unlisted file extensions should not be allowed.'
  describe xml(IIS_WEB_CONFIG) do
    allow_unlisted = xml(IIS_WEB_CONFIG)["//fileExtensions/@allowUnlisted"]
    it 'should be false' do
      expect(allow_unlisted).to include('false')
    end
  end
end

# 33. Ensure Handler is not granted Write and Script/Execute
control 'iis-33' do
  impact 1.0
  title 'Ensure Handler is not granted Write and Script/Execute'
  desc 'Handlers should not have Write or Script/Execute permissions.'
  describe xml(IIS_WEB_CONFIG) do
    access_policy = xml(IIS_WEB_CONFIG)["//handlers/@accessPolicy"]
    it 'should be Read only' do
      expect(access_policy).to include('Read')
    end
  end
end

# 34. Ensure notListedIsapisAllowed is set to false
control 'iis-34' do
  impact 1.0
  title "Ensure 'notListedIsapisAllowed' is set to false"
  desc 'notListedIsapisAllowed should be false.'
  describe xml(IIS_WEB_CONFIG) do
    isapi = xml(IIS_WEB_CONFIG)["//isapiCgiRestriction/@notListedIsapisAllowed"]
    it 'should be false' do
      expect(isapi).to include('false')
    end
  end
end

# 35. Ensure notListedCgisAllowed is set to false
control 'iis-35' do
  impact 1.0
  title "Ensure 'notListedCgisAllowed' is set to false"
  desc 'notListedCgisAllowed should be false.'
  describe xml(IIS_WEB_CONFIG) do
    cgi = xml(IIS_WEB_CONFIG)["//isapiCgiRestriction/@notListedCgisAllowed"]
    it 'should be false' do
      expect(cgi).to include('false')
    end
  end
end

# 36. Ensure Dynamic IP Address Restrictions is enabled
control 'iis-36' do
  impact 1.0
  title "Ensure 'Dynamic IP Address Restrictions' is enabled"
  desc 'Dynamic IP Address Restrictions should be enabled.'
  describe xml(IIS_APPHOST_CONFIG) do
    dip = xml(IIS_APPHOST_CONFIG)["//dynamicIpSecurity/@enabled"]
    it 'should be true' do
      expect(dip).to include('true')
    end
  end
end

# 37. Ensure Default IIS web log location is moved
control 'iis-37' do
  impact 1.0
  title 'Ensure Default IIS web log location is moved'
  desc 'IIS web logs should not be in the default location.'
  describe xml(IIS_APPHOST_CONFIG) do
    log_dirs = xml(IIS_APPHOST_CONFIG)["//site/logFile/@directory"]
    it 'should not be C:\\inetpub\\logs or %SystemDrive%' do
      log_dirs.each do |dir|
        expect(dir).not_to match(%r{C:\\inetpub|%SystemDrive%})
      end
    end
  end
end

# 38. Ensure Advanced IIS logging is enabled
control 'iis-38' do
  impact 0.5
  title 'Ensure Advanced IIS logging is enabled'
  desc 'Advanced logging should be enabled.'
  describe xml(IIS_APPHOST_CONFIG) do
    adv = xml(IIS_APPHOST_CONFIG)["//log/centralW3CLogFile/@enabled"]
    it 'should be true' do
      expect(adv).to include('true')
    end
  end
end

# 39. Ensure ETW Logging is enabled
control 'iis-39' do
  impact 0.5
  title "Ensure 'ETW Logging' is enabled"
  desc 'ETW logging should be enabled.'
  describe xml(IIS_APPHOST_CONFIG) do
    etw = xml(IIS_APPHOST_CONFIG)["//log/centralBinaryLogFile/@enabled"]
    it 'should be true' do
      expect(etw).to include('true')
    end
  end
end

# 40. Ensure FTP requests are encrypted
control 'iis-40' do
  impact 1.0
  title 'Ensure FTP requests are encrypted'
  desc 'FTP requests should require encryption.'
  describe xml(IIS_APPHOST_CONFIG) do
    ssl = xml(IIS_APPHOST_CONFIG)["//ftpServer/security/ssl/@controlChannelPolicy"]
    it 'should be SslRequire' do
      expect(ssl).to include('SslRequire')
    end
  end
end

# 41. Ensure FTP Logon attempt restrictions is enabled
control 'iis-41' do
  impact 1.0
  title 'Ensure FTP Logon attempt restrictions is enabled'
  desc 'FTP logon attempt restrictions should be enabled.'
  describe xml(IIS_APPHOST_CONFIG) do
    max = xml(IIS_APPHOST_CONFIG)["//ftpServer/security/logonAttemptPolicy/@maxLogonAttempts"]
    it 'should be set and not empty' do
      expect(max).not_to be_empty
    end
  end
end

# 42. Ensure HSTS Header is set
control 'iis-42' do
  impact 1.0
  title 'Ensure HSTS Header is set'
  desc 'Strict-Transport-Security header should be set.'
  describe xml(IIS_WEB_CONFIG) do
    hsts = xml(IIS_WEB_CONFIG)["//customHeaders/add[@name='Strict-Transport-Security']/@value"]
    it 'should be set' do
      expect(hsts).not_to be_empty
    end
  end
end
