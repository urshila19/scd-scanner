# Security controls for Windows Server 2019

# 1. Ensure 'Enforce password history' is set to '5 or more password(s)'
control 'win2019-ensure-enforce-password-history' do
  title "Ensure 'Enforce password history' is set to '5 or more password(s)'"
  desc "Verify that 'Enforce password history' is set to '5 or more password(s)'."
  impact 1.0
  describe security_policy do
    its('PasswordHistorySize') { should cmp >= 5 }
  end
end

# 2. Ensure 'Maximum password age' is set to '45 or fewer days, but not 0'
control 'win2019-ensure-maximum-password-age' do
  title "Ensure 'Maximum password age' is set to '45 or fewer days, but not 0'"
  desc "Verify that 'Maximum password age' is set to '45 or fewer days, but not 0'."
  impact 1.0
  describe security_policy do
    its('MaximumPasswordAge') { should cmp <= 45 }
    its('MaximumPasswordAge') { should cmp > 0 }
  end
end

# 3. Ensure 'Minimum password age' is set to '1 or more day(s)'
control 'win2019-ensure-minimum-password-age' do
  title "Ensure 'Minimum password age' is set to '1 or more day(s)'"
  desc "Verify that 'Minimum password age' is set to '1 or more day(s)'."
  impact 1.0
  describe security_policy do
    its('MinimumPasswordAge') { should cmp >= 1 }
  end
end

# 4. Ensure 'Minimum password length' is set to '8 or more character(s)'
control 'win2019-ensure-minimum-password-length' do
  title "Ensure 'Minimum password length' is set to '8 or more character(s)'"
  desc "Verify that 'Minimum password length' is set to '8 or more character(s)'."
  impact 1.0
  describe security_policy do
    its('MinimumPasswordLength') { should cmp >= 8 }
  end
end

# 5. Ensure 'Password must meet complexity requirements' is set to 'Enabled'
control 'win2019-ensure-password-complexity-requirements' do
  title "Ensure 'Password must meet complexity requirements' is set to 'Enabled'"
  desc "Verify that 'Password must meet complexity requirements' is set to 'Enabled'."
  impact 1.0
  describe security_policy do
    its('PasswordComplexity') { should cmp 1 }
  end
end

# 6. Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
control 'win2019-ensure-store-passwords-reversible-encryption-disabled' do
  title "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"
  desc "Verify that 'Store passwords using reversible encryption' is set to 'Disabled'."
  impact 1.0
  describe security_policy do
    its('ClearTextPassword') { should cmp 0 }
  end
end

# 7. Ensure 'Account lockout duration' is set to '15 or more minute(s)'
control 'win2019-ensure-account-lockout-duration' do
  title "Ensure 'Account lockout duration' is set to '15 or more minute(s)'"
  desc "Verify that 'Account lockout duration' is set to '15 or more minute(s)'."
  impact 1.0
  describe security_policy do
    its('LockoutDuration') { should cmp >= 15 }
  end
end

# 8. Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s)'
control 'win2019-ensure-account-lockout-threshold' do
  title "Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s)'"
  desc "Verify that 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s)'."
  impact 1.0
  describe security_policy do
    its('LockoutBadCount') { should cmp <= 10 }
  end
end

# 9. Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
control 'win2019-ensure-reset-account-lockout-counter' do
  title "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'"
  desc "Verify that 'Reset account lockout counter after' is set to '15 or more minute(s)'."
  impact 1.0
  describe security_policy do
    its('ResetLockoutCount') { should cmp >= 15 }
  end
end

# 10. Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
control 'win2019-ensure-access-credential-manager-trusted-caller' do
  title "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
  desc "Verify that 'Access Credential Manager as a trusted caller' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should be_empty }
  end
end

# 11. Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users'
control 'win2019-ensure-access-computer-from-network' do
  title "Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users'"
  desc "Verify that 'Access this computer from the network' is set to 'Administrators, Authenticated Users'."
  impact 1.0
  describe security_policy do
    its('SeNetworkLogonRight') { should match_array ['S-1-5-32-544', 'S-1-5-11'] }
  end
end

# 12. Ensure 'Act as part of the operating system' is set to 'No One'
control 'win2019-ensure-act-as-part-of-os' do
  title "Ensure 'Act as part of the operating system' is set to 'No One'"
  desc "Verify that 'Act as part of the operating system' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeTcbPrivilege') { should be_empty }
  end
end

# 13. Ensure 'Add workstations to domain' is set to 'Administrators'
control 'win2019-ensure-add-workstations-to-domain' do
  title "Ensure 'Add workstations to domain' is set to 'Administrators'"
  desc "Verify that 'Add workstations to domain' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeMachineAccountPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 14. Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
control 'win2019-ensure-adjust-memory-quotas' do
  title "Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
  desc "Verify that 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeIncreaseQuotaPrivilege') { should match_array ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20'] }
  end
end

# 15. Ensure 'Allow log on locally' is set to 'Administrators'
control 'win2019-ensure-allow-log-on-locally' do
  title "Ensure 'Allow log on locally' is set to 'Administrators'"
  desc "Verify that 'Allow log on locally' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeInteractiveLogonRight') { should match_array ['S-1-5-32-544'] }
  end
end

# 16. Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'
control 'win2019-ensure-allow-log-on-through-rdp' do
  title "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'"
  desc "Verify that 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'."
  impact 1.0
  describe security_policy do
    its('SeRemoteInteractiveLogonRight') { should match_array ['S-1-5-32-544', 'S-1-5-32-555'] }
  end
end

# 17. Ensure 'Back up files and directories' is set to 'Administrators'
control 'win2019-ensure-backup-files-and-directories' do
  title "Ensure 'Back up files and directories' is set to 'Administrators'"
  desc "Verify that 'Back up files and directories' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeBackupPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 18. Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
control 'win2019-ensure-change-system-time' do
  title "Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
  desc "Verify that 'Change the system time' is set to 'Administrators, LOCAL SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeSystemTimePrivilege') { should match_array ['S-1-5-32-544', 'S-1-5-19'] }
  end
end

# 19. Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
control 'win2019-ensure-change-time-zone' do
  title "Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
  desc "Verify that 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeTimeZonePrivilege') { should match_array ['S-1-5-32-544', 'S-1-5-19'] }
  end
end

# 20. Ensure 'Create a pagefile' is set to 'Administrators'
control 'win2019-ensure-create-pagefile' do
  title "Ensure 'Create a pagefile' is set to 'Administrators'"
  desc "Verify that 'Create a pagefile' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeCreatePagefilePrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 21. Ensure 'Create a token object' is set to 'No One'
control 'win2019-ensure-create-token-object' do
  title "Ensure 'Create a token object' is set to 'No One'"
  desc "Verify that 'Create a token object' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeCreateTokenPrivilege') { should be_empty }
  end
end

# 22. Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
control 'win2019-ensure-create-global-objects' do
  title "Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
  desc "Verify that 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeCreateGlobalPrivilege') { should match_array ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20', 'S-1-5-6'] }
  end
end

# 23. Ensure 'Create permanent shared objects' is set to 'No One'
control 'win2019-ensure-create-permanent-shared-objects' do
  title "Ensure 'Create permanent shared objects' is set to 'No One'"
  desc "Verify that 'Create permanent shared objects' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeCreatePermanentPrivilege') { should be_empty }
  end
end

# 24. Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'
control 'win2019-ensure-create-symbolic-links' do
  title "Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\\Virtual Machines'"
  desc "Verify that 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\\Virtual Machines'."
  impact 1.0
  describe security_policy do
    its('SeCreateSymbolicLinkPrivilege') { should match_array ['S-1-5-32-544', 'S-1-5-83-0'] }
  end
end

# 25. Ensure 'Debug programs' is set to 'Administrators'
control 'win2019-ensure-debug-programs' do
  title "Ensure 'Debug programs' is set to 'Administrators'"
  desc "Verify that 'Debug programs' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeDebugPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 26. Ensure 'Deny access to this computer from the network' is set to 'Guests'
control 'win2019-ensure-deny-access-computer-from-network' do
  title "Ensure 'Deny access to this computer from the network' is set to 'Guests'"
  desc "Verify that 'Deny access to this computer from the network' is set to 'Guests'."
  impact 1.0
  describe security_policy do
    its('SeDenyNetworkLogonRight') { should match_array ['S-1-5-32-546'] }
  end
end

# 27. Ensure 'Deny log on as a batch job' to include 'Guests'
control 'win2019-ensure-deny-log-on-batch-job-guests' do
  title "Ensure 'Deny log on as a batch job' to include 'Guests'"
  desc "Verify that 'Deny log on as a batch job' includes 'Guests'."
  impact 1.0
  describe security_policy do
    its('SeDenyBatchLogonRight') { should include 'S-1-5-32-546' }
  end
end

# 28. Ensure 'Deny log on as a service' to include 'Guests'
control 'win2019-ensure-deny-log-on-service-guests' do
  title "Ensure 'Deny log on as a service' to include 'Guests'"
  desc "Verify that 'Deny log on as a service' includes 'Guests'."
  impact 1.0
  describe security_policy do
    its('SeDenyServiceLogonRight') { should include 'S-1-5-32-546' }
  end
end

# 29. Ensure 'Deny log on locally' to include 'Guests'
control 'win2019-ensure-deny-log-on-locally-guests' do
  title "Ensure 'Deny log on locally' to include 'Guests'"
  desc "Verify that 'Deny log on locally' includes 'Guests'."
  impact 1.0
  describe security_policy do
    its('SeDenyInteractiveLogonRight') { should include 'S-1-5-32-546' }
  end
end

# 30. Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests'
control 'win2019-ensure-deny-log-on-through-rdp-guests' do
  title "Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests'"
  desc "Verify that 'Deny log on through Remote Desktop Services' is set to 'Guests'."
  impact 1.0
  describe security_policy do
    its('SeDenyRemoteInteractiveLogonRight') { should match_array ['S-1-5-32-546'] }
  end
end

# 31. Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'
control 'win2019-ensure-enable-trusted-delegation' do
  title "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"
  desc "Verify that 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeEnableDelegationPrivilege') { should be_empty }
  end
end

# 32. Ensure 'Force shutdown from a remote system' is set to 'Administrators'
control 'win2019-ensure-force-shutdown-remote' do
  title "Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
  desc "Verify that 'Force shutdown from a remote system' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeRemoteShutdownPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 33. Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
control 'win2019-ensure-generate-security-audits' do
  title "Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
  desc "Verify that 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeAuditPrivilege') { should match_array ['S-1-5-19', 'S-1-5-20'] }
  end
end

# 34. Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS'
control 'win2019-ensure-impersonate-client-authentication' do
  title "Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS'"
  desc "Verify that 'Impersonate a client after authentication' is set to the specified groups."
  impact 1.0
  describe security_policy do
    its('SeImpersonatePrivilege') { should match_array ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20', 'S-1-5-6', 'S-1-5-17'] }
  end
end

# 35. Ensure 'Increase scheduling priority' is set to 'Administrators'
control 'win2019-ensure-increase-scheduling-priority' do
  title "Ensure 'Increase scheduling priority' is set to 'Administrators'"
  desc "Verify that 'Increase scheduling priority' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeIncreaseBasePriorityPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 36. Ensure 'Load and unload device drivers' is set to 'Administrators'
control 'win2019-ensure-load-unload-drivers' do
  title "Ensure 'Load and unload device drivers' is set to 'Administrators'"
  desc "Verify that 'Load and unload device drivers' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeLoadDriverPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 37. Ensure 'Lock pages in memory' is set to 'No One'
control 'win2019-ensure-lock-pages-memory' do
  title "Ensure 'Lock pages in memory' is set to 'No One'"
  desc "Verify that 'Lock pages in memory' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeLockMemoryPrivilege') { should be_empty }
  end
end

# 38. Ensure 'Log on as a batch job' is set to 'Administrators'
control 'win2019-ensure-log-on-batch-job' do
  title "Ensure 'Log on as a batch job' is set to 'Administrators'"
  desc "Verify that 'Log on as a batch job' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeBatchLogonRight') { should match_array ['S-1-5-32-544'] }
  end
end

# 39. Ensure 'Manage auditing and security log' is set to 'Administrators'
control 'win2019-ensure-manage-auditing-security-log' do
  title "Ensure 'Manage auditing and security log' is set to 'Administrators'"
  desc "Verify that 'Manage auditing and security log' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeSecurityPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 40. Ensure 'Modify an object label' is set to 'No One'
control 'win2019-ensure-modify-object-label' do
  title "Ensure 'Modify an object label' is set to 'No One'"
  desc "Verify that 'Modify an object label' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeRelabelPrivilege') { should be_empty }
  end
end

# 41. Ensure 'Modify firmware environment values' is set to 'Administrators'
control 'win2019-ensure-modify-firmware-values' do
  title "Ensure 'Modify firmware environment values' is set to 'Administrators'"
  desc "Verify that 'Modify firmware environment values' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeSystemEnvironmentPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 42. Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
control 'win2019-ensure-perform-volume-maintenance' do
  title "Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
  desc "Verify that 'Perform volume maintenance tasks' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeManageVolumePrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 43. Ensure 'Profile single process' is set to 'Administrators'
control 'win2019-ensure-profile-single-process' do
  title "Ensure 'Profile single process' is set to 'Administrators'"
  desc "Verify that 'Profile single process' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeProfileSingleProcessPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 44. Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
control 'win2019-ensure-profile-system-performance' do
  title "Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\\WdiServiceHost'"
  desc "Verify that 'Profile system performance' is set to 'Administrators, NT SERVICE\\WdiServiceHost'."
  impact 1.0
  describe security_policy do
    its('SeSystemProfilePrivilege') { should match_array ['S-1-5-32-544', 'S-1-5-80-574'] }
  end
end

# 45. Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
control 'win2019-ensure-replace-process-token' do
  title "Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
  desc "Verify that 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeAssignPrimaryTokenPrivilege') { should match_array ['S-1-5-19', 'S-1-5-20'] }
  end
end

# 46. Ensure 'Restore files and directories' is set to 'Administrators'
control 'win2019-ensure-restore-files-directories' do
  title "Ensure 'Restore files and directories' is set to 'Administrators'"
  desc "Verify that 'Restore files and directories' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeRestorePrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 47. Ensure 'Shut down the system' is set to 'Administrators'
control 'win2019-ensure-shut-down-system' do
  title "Ensure 'Shut down the system' is set to 'Administrators'"
  desc "Verify that 'Shut down the system' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeShutdownPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 48. Ensure 'Synchronize directory service data' is set to 'No One'
control 'win2019-ensure-synchronize-directory-service-data' do
  title "Ensure 'Synchronize directory service data' is set to 'No One'"
  desc "Verify that 'Synchronize directory service data' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeSyncAgentPrivilege') { should be_empty }
  end
end

# 49. Ensure 'Take ownership of files or other objects' is set to 'Administrators'
control 'win2019-ensure-take-ownership-files' do
  title "Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
  desc "Verify that 'Take ownership of files or other objects' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeTakeOwnershipPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 50. Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
control 'win2019-ensure-block-microsoft-accounts' do
  title "Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"
  desc "Verify that 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('NoConnectedUser') { should cmp 3 }
  end
end

# 51. Ensure 'Accounts: Guest account status' is set to 'Disabled'
control 'win2019-ensure-guest-account-status' do
  title "Ensure 'Accounts: Guest account status' is set to 'Disabled'"
  desc "Verify that 'Accounts: Guest account status' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\000001F5') do
    its('F') { should cmp 0x10 }
  end
end

# 52. Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
control 'win2019-ensure-limit-local-account-blank-passwords' do
  title "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
  desc "Verify that 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('LimitBlankPasswordUse') { should cmp 1 }
  end
end

# 53. Configure 'Accounts: Rename administrator account'
control 'win2019-configure-rename-administrator-account' do
  title "Configure 'Accounts: Rename administrator account'"
  desc "Verify that 'Accounts: Rename administrator account' is configured."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names\Administrator') do
    it { should exist }
  end
end

# 54. Configure 'Accounts: Rename guest account'
control 'win2019-configure-rename-guest-account' do
  title "Configure 'Accounts: Rename guest account'"
  desc "Verify that 'Accounts: Rename guest account' is configured."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names\Guest') do
    it { should exist }
  end
end

# 55. Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
control 'win2019-ensure-force-audit-policy-subcategory-settings' do
  title "Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'"
  desc "Verify that 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('SCENoApplyLegacyAuditPolicy') { should cmp 1 }
  end
end

# 56. Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
control 'win2019-ensure-shutdown-if-unable-to-log-audits' do
  title "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"
  desc "Verify that 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('CrashOnAuditFail') { should cmp 0 }
  end
end

# 57. Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
control 'win2019-ensure-format-eject-removable-media' do
  title "Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'"
  desc "Verify that 'Devices: Allowed to format and eject removable media' is set to 'Administrators'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('NoMediaSharing') { should cmp 1 }
  end
end

# 58. Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
control 'win2019-ensure-prevent-installing-printer-drivers' do
  title "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'"
  desc "Verify that 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers') do
    its('DisablePrinterDriverInstall') { should cmp 1 }
  end
end

# 59. Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
control 'win2019-ensure-digitally-sign-secure-channel-data' do
  title "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'"
  desc "Verify that 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('SealSecureChannel') { should cmp 1 }
  end
end

# 60. Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
control 'win2019-ensure-disable-machine-account-password-changes' do
  title "Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'"
  desc "Verify that 'Domain member: Disable machine account password changes' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('DisablePasswordChange') { should cmp 0 }
  end
end

# 61. Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
control 'win2019-ensure-max-machine-account-password-age' do
  title "Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'"
  desc "Verify that 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('MaximumPasswordAge') { should cmp <= 30 }
    its('MaximumPasswordAge') { should cmp > 0 }
  end
end

# 62. Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
control 'win2019-ensure-require-strong-session-key' do
  title "Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'"
  desc "Verify that 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('RequireStrongKey') { should cmp 1 }
  end
end

# 63. Ensure 'Interactive logon: Don't display last sign-in' is set to 'Enabled'
control 'win2019-ensure-dont-display-last-sign-in' do
  title "Ensure 'Interactive logon: Don't display last sign-in' is set to 'Enabled'"
  desc "Verify that 'Interactive logon: Don't display last sign-in' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('DontDisplayLastUserName') { should cmp 1 }
  end
end

# 64. Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
control 'win2019-ensure-do-not-require-ctrl-alt-del' do
  title "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'"
  desc "Verify that 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('DisableCAD') { should cmp 0 }
  end
end

# 65. Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
control 'win2019-ensure-machine-inactivity-limit' do
  title "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'"
  desc "Verify that 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('InactivityTimeoutSecs') { should cmp <= 900 }
    its('InactivityTimeoutSecs') { should cmp > 0 }
  end
end

# 66. Configure 'Interactive logon: Message text for users attempting to log on'
control 'win2019-configure-message-text-logon' do
  title "Configure 'Interactive logon: Message text for users attempting to log on'"
  desc "Verify that 'Interactive logon: Message text for users attempting to log on' is configured."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('LegalNoticeText') { should_not be_empty }
  end
end

# 67. Configure 'Interactive logon: Message title for users attempting to log on'
control 'win2019-configure-message-title-logon' do
  title "Configure 'Interactive logon: Message title for users attempting to log on'"
  desc "Verify that 'Interactive logon: Message title for users attempting to log on' is configured."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('LegalNoticeCaption') { should_not be_empty }
  end
end

# 68. Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '0 or fewer logon(s)'
control 'win2019-ensure-cache-previous-logons' do
  title "Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '0 or fewer logon(s)'"
  desc "Verify that 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '0 or fewer logon(s)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('CachedLogonsCount') { should cmp <= 0 }
  end
end

# 69. Ensure 'Interactive logon: Prompt user to change password before expiration' is set to '14 days'
control 'win2019-ensure-prompt-password-change-before-expiration' do
  title "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to '14 days'"
  desc "Verify that 'Interactive logon: Prompt user to change password before expiration' is set to '14 days'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('PasswordExpiryWarning') { should cmp 14 }
  end
end

# 70. Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'
control 'win2019-ensure-require-dc-authentication-unlock' do
  title "Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'"
  desc "Verify that 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('ForceUnlockLogon') { should cmp 1 }
  end
end

# 71. Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation'
control 'win2019-ensure-smart-card-removal-behavior' do
  title "Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation'"
  desc "Verify that 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('ScRemoveOption') { should cmp 1 }
  end
end

# 72. Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
control 'win2019-ensure-network-client-sign-communications-always' do
  title "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
  desc "Verify that 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    its('EnableSecuritySignature') { should cmp 1 }
  end
end

# 73. Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
control 'win2019-ensure-network-client-sign-communications-if-server-agrees' do
  title "Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'"
  desc "Verify that 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    its('RequireSecuritySignature') { should cmp 1 }
  end
end

# 74. Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
control 'win2019-ensure-network-client-send-unencrypted-password' do
  title "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
  desc "Verify that 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    its('EnablePlainTextPassword') { should cmp 0 }
  end
end

# 75. Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'
control 'win2019-ensure-network-server-idle-time' do
  title "Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'"
  desc "Verify that 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('IdleTimeout') { should cmp <= 15 }
    its('IdleTimeout') { should cmp > 0 }
  end
end

# 76. Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
control 'win2019-ensure-network-server-sign-communications-always' do
  title "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
  desc "Verify that 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('EnableSecuritySignature') { should cmp 1 }
  end
end

# 77. Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
control 'win2019-ensure-network-server-sign-communications-if-client-agrees' do
  title "Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
  desc "Verify that 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('RequireSecuritySignature') { should cmp 1 }
  end
end

# 78. Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
control 'win2019-ensure-network-server-disconnect-clients-logon-hours-expire' do
  title "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'"
  desc "Verify that 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('EnableForcedLogoff') { should cmp 1 }
  end
end

# 79. Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher
control 'win2019-ensure-network-server-spn-validation-level' do
  title "Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher"
  desc "Verify that 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('SmbServerNameHardeningLevel') { should cmp >= 1 }
  end
end

# 80. Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
control 'win2019-ensure-network-access-allow-anonymous-sid-name-translation' do
  title "Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'"
  desc "Verify that 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('AllowAnonymousSIDNameTranslation') { should cmp 0 }
  end
end

# 81. Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'
control 'win2019-ensure-network-access-no-anonymous-enumeration-sam-accounts' do
  title "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'"
  desc "Verify that 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('RestrictAnonymousSAM') { should cmp 1 }
  end
end

# 82. Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
control 'win2019-ensure-network-access-no-anonymous-enumeration-sam-accounts-shares' do
  title "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'"
  desc "Verify that 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('RestrictAnonymous') { should cmp 1 }
  end
end

# 83. Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
control 'win2019-ensure-network-access-no-storage-passwords-credentials' do
  title "Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'"
  desc "Verify that 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('DisableDomainCreds') { should cmp 1 }
  end
end

# 84. Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
control 'win2019-ensure-network-access-no-everyone-permissions-anonymous-users' do
  title "Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'"
  desc "Verify that 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('EveryoneIncludesAnonymous') { should cmp 0 }
  end
end

# 85. Configure 'Network access: Named Pipes that can be accessed anonymously'
control 'win2019-configure-network-access-named-pipes-anonymous' do
  title "Configure 'Network access: Named Pipes that can be accessed anonymously'"
  desc "Verify that 'Network access: Named Pipes that can be accessed anonymously' is configured."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('NullSessionPipes') { should be_empty }
  end
end

# 86. Configure 'Network access: Remotely accessible registry paths'
control 'win2019-configure-network-access-registry-paths' do
  title "Configure 'Network access: Remotely accessible registry paths'"
  desc "Verify that 'Network access: Remotely accessible registry paths' is configured."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg') do
    its('AllowedExactPaths') { should_not be_empty }
  end
end

# 87. Configure 'Network access: Remotely accessible registry paths and sub-paths'
control 'win2019-configure-network-access-registry-paths-subpaths' do
  title "Configure 'Network access: Remotely accessible registry paths and sub-paths'"
  desc "Verify that 'Network access: Remotely accessible registry paths and sub-paths' is configured."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg') do
    its('AllowedPaths') { should_not be_empty }
  end
end

# 88. Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
control 'win2019-ensure-network-access-restrict-anonymous-named-pipes-shares' do
  title "Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"
  desc "Verify that 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('RestrictNullSessAccess') { should cmp 1 }
  end
end

# 89. Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'
control 'win2019-ensure-network-access-restrict-clients-remote-calls-sam' do
  title "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
  desc "Verify that 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('RestrictRemoteSAM') { should cmp 1 }
  end
end

# 90. Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
control 'win2019-ensure-network-access-shares-anonymous-none' do
  title "Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"
  desc "Verify that 'Network access: Shares that can be accessed anonymously' is set to 'None'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('NullSessionShares') { should be_empty }
  end
end

# 91. Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
control 'win2019-ensure-network-access-sharing-security-model' do
  title "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'"
  desc "Verify that 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('ForceGuest') { should cmp 0 }
  end
end

# 92. Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
control 'win2019-ensure-network-security-allow-local-system-identity' do
  title "Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
  desc "Verify that 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('UseMachineIdentity') { should cmp 1 }
  end
end

# 93. Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
control 'win2019-ensure-network-security-allow-localsystem-null-session' do
  title "Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
  desc "Verify that 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('AllowNullSessionFallback') { should cmp 0 }
  end
end

# 94. Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
control 'win2019-ensure-network-security-allow-pku2u-authentication' do
  title "Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'"
  desc "Verify that 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u') do
    its('AllowOnlineID') { should cmp 0 }
  end
end

# 95. Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
control 'win2019-ensure-network-security-no-lan-manager-hash' do
  title "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"
  desc "Verify that 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('NoLMHash') { should cmp 1 }
  end
end

# 96. Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'
control 'win2019-ensure-network-security-force-logoff-logon-hours-expire' do
  title "Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'"
  desc "Verify that 'Network security: Force logoff when logon hours expire' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('ForceLogoffWhenHourExpire') { should cmp 1 }
  end
end

# 97. Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
control 'win2019-ensure-network-security-lan-manager-authentication-level' do
  title "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'"
  desc "Verify that 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('LmCompatibilityLevel') { should cmp 5 }
  end
end

# 98. Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
control 'win2019-ensure-network-security-ldap-client-signing' do
  title "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher"
  desc "Verify that 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP') do
    its('LDAPClientIntegrity') { should cmp >= 1 }
  end
end

# 99. Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
control 'win2019-ensure-network-security-minimum-session-security-clients' do
  title "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
  desc "Verify that 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('NTLMMinClientSec') { should cmp 0x20080000 }
  end
end

# 100. Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
control 'win2019-ensure-network-security-minimum-session-security-servers' do
  title "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
  desc "Verify that 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('NTLMMinServerSec') { should cmp 0x20080000 }
  end
end

# 101. Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
control 'win2019-ensure-shutdown-without-logon' do
  title "Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'"
  desc "Verify that 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('ShutdownWithoutLogon') { should cmp 0 }
  end
end

# 102. Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
control 'win2019-ensure-system-objects-case-insensitivity' do
  title "Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'"
  desc "Verify that 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager') do
    its('ObCaseInsensitive') { should cmp 1 }
  end
end

# 103. Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
control 'win2019-ensure-system-objects-strengthen-permissions' do
  title "Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'"
  desc "Verify that 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager') do
    its('ProtectionMode') { should cmp 1 }
  end
end

# 104. Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
control 'win2019-ensure-uac-elevation-prompt-standard-users' do
  title "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
  desc "Verify that 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('ConsentPromptBehaviorUser') { should cmp 0 }
  end
end

# 105. Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
control 'win2019-ensure-uac-detect-app-installations' do
  title "Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
  desc "Verify that 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('EnableInstallerDetection') { should cmp 1 }
  end
end

# 106. Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'
control 'win2019-ensure-uac-elevate-uiaccess-secure-locations' do
  title "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
  desc "Verify that 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('EnableSecureUIAPaths') { should cmp 1 }
  end
end

# 107. Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
control 'win2019-ensure-uac-switch-secure-desktop' do
  title "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"
  desc "Verify that 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('PromptOnSecureDesktop') { should cmp 1 }
  end
end

# 108. Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
control 'win2019-ensure-uac-virtualize-write-failures' do
  title "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
  desc "Verify that 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('EnableVirtualization') { should cmp 1 }
  end
end

# 109. Ensure 'Audit Credential Validation' is set to 'Success and Failure'
control 'win2019-ensure-audit-credential-validation' do
  title "Ensure 'Audit Credential Validation' is set to 'Success and Failure'"
  desc "Verify that 'Audit Credential Validation' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Credential Validation']) { should eq 'Success and Failure' }
  end
end

# 110. Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure'
control 'win2019-ensure-audit-kerberos-authentication-service' do
  title "Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure'"
  desc "Verify that 'Audit Kerberos Authentication Service' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Kerberos Authentication Service']) { should eq 'Success and Failure' }
  end
end

# 111. Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure'
control 'win2019-ensure-audit-kerberos-service-ticket-operations' do
  title "Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure'"
  desc "Verify that 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Kerberos Service Ticket Operations']) { should eq 'Success and Failure' }
  end
end

# 112. Ensure 'Audit Application Group Management' is set to 'Success and Failure'
control 'win2019-ensure-audit-application-group-management' do
  title "Ensure 'Audit Application Group Management' is set to 'Success and Failure'"
  desc "Verify that 'Audit Application Group Management' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Application Group Management']) { should eq 'Success and Failure' }
  end
end

# 113. Ensure 'Audit Computer Account Management' is set to 'Success and Failure'
control 'win2019-ensure-audit-computer-account-management' do
  title "Ensure 'Audit Computer Account Management' is set to 'Success and Failure'"
  desc "Verify that 'Audit Computer Account Management' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Computer Account Management']) { should eq 'Success and Failure' }
  end
end

# 114. Ensure 'Audit Distribution Group Management' is set to 'Success and Failure'
control 'win2019-ensure-audit-distribution-group-management' do
  title "Ensure 'Audit Distribution Group Management' is set to 'Success and Failure'"
  desc "Verify that 'Audit Distribution Group Management' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Distribution Group Management']) { should eq 'Success and Failure' }
  end
end

# 115. Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'
control 'win2019-ensure-audit-other-account-management-events' do
  title "Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'"
  desc "Verify that 'Audit Other Account Management Events' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Other Account Management Events']) { should eq 'Success and Failure' }
  end
end

# 116. Ensure 'Audit Security Group Management' is set to 'Success and Failure'
control 'win2019-ensure-audit-security-group-management' do
  title "Ensure 'Audit Security Group Management' is set to 'Success and Failure'"
  desc "Verify that 'Audit Security Group Management' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Security Group Management']) { should eq 'Success and Failure' }
  end
end

# 117. Ensure 'Audit User Account Management' is set to 'Success and Failure'
control 'win2019-ensure-audit-user-account-management' do
  title "Ensure 'Audit User Account Management' is set to 'Success and Failure'"
  desc "Verify that 'Audit User Account Management' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['User Account Management']) { should eq 'Success and Failure' }
  end
end

# 118. Ensure 'Audit PNP Activity' is set to 'Success'
control 'win2019-ensure-audit-pnp-activity' do
  title "Ensure 'Audit PNP Activity' is set to 'Success'"
  desc "Verify that 'Audit PNP Activity' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its(['Plug and Play Events']) { should eq 'Success' }
  end
end

# 119. Ensure 'Audit Process Creation' is set to 'Success'
control 'win2019-ensure-audit-process-creation' do
  title "Ensure 'Audit Process Creation' is set to 'Success'"
  desc "Verify that 'Audit Process Creation' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its(['Process Creation']) { should eq 'Success' }
  end
end

# 120. Ensure 'Audit Directory Service Access' is set to 'Success and Failure'
control 'win2019-ensure-audit-directory-service-access' do
  title "Ensure 'Audit Directory Service Access' is set to 'Success and Failure'"
  desc "Verify that 'Audit Directory Service Access' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Directory Service Access']) { should eq 'Success and Failure' }
  end
end

# 121. Ensure 'Audit Directory Service Changes' is set to 'Success and Failure'
control 'win2019-ensure-audit-directory-service-changes' do
  title "Ensure 'Audit Directory Service Changes' is set to 'Success and Failure'"
  desc "Verify that 'Audit Directory Service Changes' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Directory Service Changes']) { should eq 'Success and Failure' }
  end
end

# 122. Ensure 'Audit Account Lockout' is set to 'Success and Failure'
control 'win2019-ensure-audit-account-lockout' do
  title "Ensure 'Audit Account Lockout' is set to 'Success and Failure'"
  desc "Verify that 'Audit Account Lockout' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Account Lockout']) { should eq 'Success and Failure' }
  end
end

# 123. Ensure 'Audit Group Membership' is set to 'Success'
control 'win2019-ensure-audit-group-membership' do
  title "Ensure 'Audit Group Membership' is set to 'Success'"
  desc "Verify that 'Audit Group Membership' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its(['Group Membership']) { should eq 'Success' }
  end
end

# 124. Ensure 'Audit Logoff' is set to 'Success'
control 'win2019-ensure-audit-logoff' do
  title "Ensure 'Audit Logoff' is set to 'Success'"
  desc "Verify that 'Audit Logoff' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its(['Logoff']) { should eq 'Success' }
  end
end

# 125. Ensure 'Audit Logon' is set to 'Success and Failure'
control 'win2019-ensure-audit-logon' do
  title "Ensure 'Audit Logon' is set to 'Success and Failure'"
  desc "Verify that 'Audit Logon' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Logon']) { should eq 'Success and Failure' }
  end
end

# 126. Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
control 'win2019-ensure-audit-other-logon-logoff-events' do
  title "Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"
  desc "Verify that 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Other Logon/Logoff Events']) { should eq 'Success and Failure' }
  end
end

# 127. Ensure 'Audit Special Logon' is set to 'Success'
control 'win2019-ensure-audit-special-logon' do
  title "Ensure 'Audit Special Logon' is set to 'Success'"
  desc "Verify that 'Audit Special Logon' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its(['Special Logon']) { should eq 'Success' }
  end
end

# 128. Ensure 'Audit Detailed File Share' is set to include 'Failure'
control 'win2019-ensure-audit-detailed-file-share' do
  title "Ensure 'Audit Detailed File Share' is set to include 'Failure'"
  desc "Verify that 'Audit Detailed File Share' is set to include 'Failure'."
  impact 1.0
  describe audit_policy do
    its(['Detailed File Share']) { should include 'Failure' }
  end
end

# 129. Ensure 'Audit File Share' is set to 'Success and Failure'
control 'win2019-ensure-audit-file-share' do
  title "Ensure 'Audit File Share' is set to 'Success and Failure'"
  desc "Verify that 'Audit File Share' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['File Share']) { should eq 'Success and Failure' }
  end
end

# 130. Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'
control 'win2019-ensure-audit-other-object-access-events' do
  title "Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'"
  desc "Verify that 'Audit Other Object Access Events' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Other Object Access Events']) { should eq 'Success and Failure' }
  end
end

# 131. Ensure 'Audit Removable Storage' is set to 'Success and Failure'
control 'win2019-ensure-audit-removable-storage' do
  title "Ensure 'Audit Removable Storage' is set to 'Success and Failure'"
  desc "Verify that 'Audit Removable Storage' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Removable Storage']) { should eq 'Success and Failure' }
  end
end

# 132. Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'
control 'win2019-ensure-audit-policy-change' do
  title "Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'"
  desc "Verify that 'Audit Audit Policy Change' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Audit Policy Change']) { should eq 'Success and Failure' }
  end
end

# 133. Ensure 'Audit Authentication Policy Change' is set to 'Success'
control 'win2019-ensure-authentication-policy-change' do
  title "Ensure 'Audit Authentication Policy Change' is set to 'Success'"
  desc "Verify that 'Audit Authentication Policy Change' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its(['Authentication Policy Change']) { should eq 'Success' }
  end
end

# 134. Ensure 'Audit Authorization Policy Change' is set to 'Success'
control 'win2019-ensure-authorization-policy-change' do
  title "Ensure 'Audit Authorization Policy Change' is set to 'Success'"
  desc "Verify that 'Audit Authorization Policy Change' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its(['Authorization Policy Change']) { should eq 'Success' }
  end
end

# 135. Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'
control 'win2019-ensure-mpssvc-rule-policy-change' do
  title "Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'"
  desc "Verify that 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['MPSSVC Rule-Level Policy Change']) { should eq 'Success and Failure' }
  end
end

# 136. Ensure 'Audit Other Policy Change Events' is set to include 'Failure'
control 'win2019-ensure-other-policy-change-events' do
  title "Ensure 'Audit Other Policy Change Events' is set to include 'Failure'"
  desc "Verify that 'Audit Other Policy Change Events' is set to include 'Failure'."
  impact 1.0
  describe audit_policy do
    its(['Other Policy Change Events']) { should include 'Failure' }
  end
end

# 137. Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
control 'win2019-ensure-sensitive-privilege-use' do
  title "Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'"
  desc "Verify that 'Audit Sensitive Privilege Use' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Sensitive Privilege Use']) { should eq 'Success and Failure' }
  end
end

# 138. Ensure 'Audit IPsec Driver' is set to 'Success and Failure'
control 'win2019-ensure-ipsec-driver' do
  title "Ensure 'Audit IPsec Driver' is set to 'Success and Failure'"
  desc "Verify that 'Audit IPsec Driver' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['IPsec Driver']) { should eq 'Success and Failure' }
  end
end

# 139. Ensure 'Audit Other System Events' is set to 'Success and Failure'
control 'win2019-ensure-other-system-events' do
  title "Ensure 'Audit Other System Events' is set to 'Success and Failure'"
  desc "Verify that 'Audit Other System Events' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Other System Events']) { should eq 'Success and Failure' }
  end
end

# 140. Ensure 'Audit Security State Change' is set to 'Success'
control 'win2019-ensure-security-state-change' do
  title "Ensure 'Audit Security State Change' is set to 'Success'"
  desc "Verify that 'Audit Security State Change' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its(['Security State Change']) { should eq 'Success' }
  end
end

# 141. Ensure 'Audit Security System Extension' is set to 'Success and Failure'
control 'win2019-ensure-security-system-extension' do
  title "Ensure 'Audit Security System Extension' is set to 'Success and Failure'"
  desc "Verify that 'Audit Security System Extension' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Security System Extension']) { should eq 'Success and Failure' }
  end
end

# 142. Ensure 'Audit System Integrity' is set to 'Success and Failure'
control 'win2019-ensure-system-integrity' do
  title "Ensure 'Audit System Integrity' is set to 'Success and Failure'"
  desc "Verify that 'Audit System Integrity' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['System Integrity']) { should eq 'Success and Failure' }
  end
end

# 143. Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'
control 'win2019-prevent-lock-screen-camera' do
  title "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
  desc "Verify that 'Prevent enabling lock screen camera' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization') do
    its('NoLockScreenCamera') { should eq 1 }
  end
end

# 144. Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
control 'win2019-prevent-lock-screen-slide-show' do
  title "Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
  desc "Verify that 'Prevent enabling lock screen slide show' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization') do
    its('NoLockScreenSlideshow') { should eq 1 }
  end
end

# 145. Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'
control 'win2019-disable-online-speech-recognition' do
  title "Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'"
  desc "Verify that 'Allow users to enable online speech recognition services' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Speech') do
    its('AllowSpeechServices') { should eq 0 }
  end
end

# 146. Ensure 'Allow Online Tips' is set to 'Disabled'
control 'win2019-disable-online-tips' do
  title "Ensure 'Allow Online Tips' is set to 'Disabled'"
  desc "Verify that 'Allow Online Tips' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableSoftLanding') { should eq 1 }
  end
end

# 147. Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'
control 'win2019-apply-uac-restrictions-network-logons' do
  title "Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'"
  desc "Verify that 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('LocalAccountTokenFilterPolicy') { should eq 0 }
  end
end

# 148. Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'
control 'win2019-configure-smb-v1-client-driver' do
  title "Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'"
  desc "Verify that 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation') do
    its('Start') { should eq 4 }
  end
end

# 149. Ensure 'Configure SMB v1 server' is set to 'Disabled'
control 'win2019-configure-smb-v1-server' do
  title "Ensure 'Configure SMB v1 server' is set to 'Disabled'"
  desc "Verify that 'Configure SMB v1 server' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer') do
    its('Start') { should eq 4 }
  end
end

# 150. Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'
control 'win2019-enable-sehop' do
  title "Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
  desc "Verify that 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\kernel') do
    its('DisableExceptionChainValidation') { should eq 0 }
  end
end

# 151. Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'
control 'win2019-netbt-nodetype-configuration' do
  title "Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'"
  desc "Verify that 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters') do
    its('NodeType') { should eq 2 }
  end
end

# 152. Ensure 'WDigest Authentication' is set to 'Disabled'
control 'win2019-wdigest-authentication' do
  title "Ensure 'WDigest Authentication' is set to 'Disabled'"
  desc "Verify that 'WDigest Authentication' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest') do
    its('UseLogonCredential') { should eq 0 }
  end
end

# 153. Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
control 'win2019-auto-admin-logon' do
  title "Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'"
  desc "Verify that 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon') do
    its('AutoAdminLogon') { should eq 0 }
  end
end

# 154. Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
control 'win2019-disable-ip-source-routing-ipv6' do
  title "Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
  desc "Verify that 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters') do
    its('DisableIPSourceRouting') { should eq 2 }
  end
end

# 155. Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
control 'win2019-disable-ip-source-routing' do
  title "Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
  desc "Verify that 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    its('DisableIPSourceRouting') { should eq 2 }
  end
end

# 156. Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'
control 'win2019-enable-icmp-redirect' do
  title "Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
  desc "Verify that 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    its('EnableICMPRedirect') { should eq 0 }
  end
end

# 157. Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'
control 'win2019-keep-alive-time' do
  title "Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'"
  desc "Verify that 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    its('KeepAliveTime') { should eq 300000 }
  end
end

# 158. Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'
control 'win2019-no-name-release-on-demand' do
  title "Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
  desc "Verify that 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters') do
    its('NoNameReleaseOnDemand') { should eq 1 }
  end
end

# 159. Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'
control 'win2019-perform-router-discovery' do
  title "Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'"
  desc "Verify that 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    its('PerformRouterDiscovery') { should eq 0 }
  end
end

# 160. Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'
control 'win2019-safe-dll-search-mode' do
  title "Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'"
  desc "Verify that 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager') do
    its('SafeDllSearchMode') { should eq 1 }
  end
end

# 161. Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'
control 'win2019-screen-saver-grace-period' do
  title "Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'"
  desc "Verify that 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager') do
    its('ScreenSaverGracePeriod') { should eq 5 }
  end
end

# 162. Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
control 'win2019-tcp-max-data-retransmissions-ipv6' do
  title "Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
  desc "Verify that 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters') do
    its('TcpMaxDataRetransmissions') { should eq 3 }
  end
end

# 163. Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
control 'win2019-tcp-max-data-retransmissions' do
  title "Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
  desc "Verify that 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    its('TcpMaxDataRetransmissions') { should eq 3 }
  end
end

# 164. Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'
control 'win2019-warning-level' do
  title "Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"
  desc "Verify that 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EventLog\Security') do
    its('WarningLevel') { should be <= 90 }
  end
end

# 165. Ensure 'Turn off multicast name resolution' is set to 'Enabled'
control 'win2019-turn-off-multicast-name-resolution' do
  title "Ensure 'Turn off multicast name resolution' is set to 'Enabled'"
  desc "Verify that 'Turn off multicast name resolution' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD') do
    its('EnableMulticast') { should eq 0 }
  end
end

# 166. Ensure 'Enable Font Providers' is set to 'Disabled'
control 'win2019-enable-font-providers' do
  title "Ensure 'Enable Font Providers' is set to 'Disabled'"
  desc "Verify that 'Enable Font Providers' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Font Providers') do
    its('EnableFontProviders') { should eq 0 }
  end
end

# 167. Ensure 'Enable insecure guest logons' is set to 'Disabled'
control 'win2019-enable-insecure-guest-logons' do
  title "Ensure 'Enable insecure guest logons' is set to 'Disabled'"
  desc "Verify that 'Enable insecure guest logons' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation') do
    its('AllowInsecureGuestAuth') { should eq 0 }
  end
end

# 168. Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'
control 'win2019-turn-on-mapper-io-driver' do
  title "Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'"
  desc "Verify that 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD') do
    its('AllowMapperIO') { should eq 0 }
  end
end

# 169. Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'
control 'win2019-turn-on-responder-driver' do
  title "Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'"
  desc "Verify that 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD') do
    its('AllowRspndr') { should eq 0 }
  end
end

# 170. Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'
control 'win2019-turn-off-peer-to-peer-networking' do
  title "Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'"
  desc "Verify that 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\PeerToPeer') do
    its('Disabled') { should eq 1 }
  end
end

# 171. Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
control 'win2019-prohibit-network-bridge-installation' do
  title "Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
  desc "Verify that 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections') do
    its('NC_AllowNetBridge_NLA') { should eq 0 }
  end
end

# 172. Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
control 'win2019-prohibit-internet-connection-sharing' do
  title "Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
  desc "Verify that 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections') do
    its('NC_ShowSharedAccessUI') { should eq 0 }
  end
end

# 173. Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'
control 'win2019-require-elevation-network-location' do
  title "Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'"
  desc "Verify that 'Require domain users to elevate when setting a network's location' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections') do
    its('NC_StdDomainUserSetLocation') { should eq 1 }
  end
end

# 174. Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'
control 'win2019-hardened-unc-paths' do
  title "Ensure 'Hardened UNC Paths' is set to 'Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares'"
  desc "Verify that 'Hardened UNC Paths' is set to 'Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths') do
    its('\\\\*\\NETLOGON') { should eq "RequireMutualAuthentication=1, RequireIntegrity=1" }
    its('\\\\*\\SYSVOL') { should eq "RequireMutualAuthentication=1, RequireIntegrity=1" }
  end
end

# 175. Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')
control 'win2019-disable-ipv6' do
  title "Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')"
  desc "Verify that IPv6 is disabled by ensuring TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\TCPIP6\Parameters') do
    its('DisabledComponents') { should eq 255 }
  end
end

# 176. Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'
control 'win2019-disable-windows-connect-now-wireless-settings' do
  title "Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
  desc "Verify that 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Settings') do
    its('DisableWcnConfig') { should eq 1 }
  end
end

# 177. Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'
control 'win2019-prohibit-windows-connect-now-wizards' do
  title "Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'"
  desc "Verify that 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Settings') do
    its('DisableWcnUi') { should eq 1 }
  end
end

# 178. Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
control 'win2019-minimize-simultaneous-connections' do
  title "Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'"
  desc "Verify that 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy') do
    its('fMinimizeConnections') { should eq 1 }
  end
end

# 179. Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'
control 'win2019-prohibit-non-domain-networks' do
  title "Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'"
  desc "Verify that 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy') do
    its('fBlockNonDomain') { should eq 1 }
  end
end

# 180. Ensure 'Turn off notifications network usage' is set to 'Enabled'
control 'win2019-turn-off-network-usage-notifications' do
  title "Ensure 'Turn off notifications network usage' is set to 'Enabled'"
  desc "Verify that 'Turn off notifications network usage' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkUsage') do
    its('DisableNotifications') { should eq 1 }
  end
end

# 181. Ensure 'Include command line in process creation events' is set to Enabled
control 'win2019-include-command-line-process-creation' do
  title "Ensure 'Include command line in process creation events' is set to Enabled"
  desc "Verify that 'Include command line in process creation events' is set to Enabled."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit') do
    its('ProcessCreationIncludeCmdLine_Enabled') { should eq 1 }
  end
end

# 182. Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'
control 'win2019-remote-host-delegation-non-exportable-credentials' do
  title "Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'"
  desc "Verify that 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\CredentialsDelegation') do
    its('AllowProtectedCreds') { should eq 1 }
  end
end

# 183. Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'
control 'win2019-turn-on-virtualization-based-security' do
  title "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'"
  desc "Verify that 'Turn On Virtualization Based Security' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard') do
    its('EnableVirtualizationBasedSecurity') { should eq 1 }
  end
end

# 184. Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection'
control 'win2019-virtualization-security-platform-level' do
  title "Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection'"
  desc "Verify that 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard') do
    its('RequirePlatformSecurityFeatures') { should eq 3 }
  end
end

# 185. Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'
control 'win2019-virtualization-security-code-integrity' do
  title "Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'"
  desc "Verify that 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard') do
    its('HypervisorEnforcedCodeIntegrity') { should eq 2 }
  end
end

# 186. Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True'
control 'win2019-virtualization-security-uefi-memory-table' do
  title "Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True'"
  desc "Verify that 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard') do
    its('RequireMemoryAttributes') { should eq 1 }
  end
end

# 187. Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock' (MS Only)
control 'win2019-virtualization-security-credential-guard' do
  title "Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock' (MS Only)"
  desc "Verify that 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock' (MS Only)."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard') do
    its('LsaCfgFlags') { should eq 2 }
  end
end

# 188. Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'
control 'win2019-virtualization-security-secure-launch' do
  title "Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'"
  desc "Verify that 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard') do
    its('SecureLaunch') { should eq 1 }
  end
end

# 189. Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
control 'win2019-boot-start-driver-policy' do
  title "Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
  desc "Verify that 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies\EarlyLaunch') do
    its('DriverLoadPolicy') { should eq 7 }
  end
end

# 190. Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
control 'win2019-configure-registry-policy-processing' do
  title "Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"
  desc "Verify that 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DisableBkGndGroupPolicy') { should eq 0 }
  end
end

# 191. Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
control 'win2019-configure-registry-policy-processing-group-policy-unchanged' do
  title "Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
  desc "Verify that 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('GroupPolicyRefresh') { should eq 1 }
  end
end

# 192. Ensure 'Continue experiences on this device' is set to 'Disabled'
control 'win2019-continue-experiences-disabled' do
  title "Ensure 'Continue experiences on this device' is set to 'Disabled'"
  desc "Verify that 'Continue experiences on this device' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('EnableCdp') { should eq 0 }
  end
end

# 193. Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'
control 'win2019-turn-off-background-refresh-group-policy' do
  title "Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'"
  desc "Verify that 'Turn off background refresh of Group Policy' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DisableBkGndGroupPolicy') { should eq 0 }
  end
end

# 194. Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
control 'win2019-turn-off-print-drivers-http' do
  title "Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'"
  desc "Verify that 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers') do
    its('DisableHTTPPrinting') { should eq 1 }
  end
end

# 195. Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
control 'win2019-turn-off-handwriting-data-sharing' do
  title "Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'"
  desc "Verify that 'Turn off handwriting personalization data sharing' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization') do
    its('RestrictImplicitTextCollection') { should eq 1 }
  end
end

# 196. Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
control 'win2019-turn-off-handwriting-error-reporting' do
  title "Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'"
  desc "Verify that 'Turn off handwriting recognition error reporting' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization') do
    its('RestrictImplicitInkCollection') { should eq 1 }
  end
end

# 197. Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
control 'win2019-turn-off-internet-connection-wizard' do
  title "Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'"
  desc "Verify that 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Internet Connection Wizard') do
    its('DisableICW') { should eq 1 }
  end
end

# 198. Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
control 'win2019-turn-off-internet-download-web-publishing' do
  title "Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'"
  desc "Verify that 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoWebServices') { should eq 1 }
  end
end

# 199. Ensure 'Turn off printing over HTTP' is set to 'Enabled'
control 'win2019-turn-off-printing-http' do
  title "Ensure 'Turn off printing over HTTP' is set to 'Enabled'"
  desc "Verify that 'Turn off printing over HTTP' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers') do
    its('DisableHTTPPrinting') { should eq 1 }
  end
end

# 200. Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
control 'win2019-turn-off-registration-microsoft-url' do
  title "Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'"
  desc "Verify that 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Registration') do
    its('DisableRegistration') { should eq 1 }
  end
end

# 201. Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
control 'win2019-turn-off-search-companion-updates' do
  title "Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'"
  desc "Verify that 'Turn off Search Companion content file updates' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SearchCompanion') do
    its('DisableContentFileUpdates') { should eq 1 }
  end
end

# 202. Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
control 'win2019-turn-off-order-prints-task' do
  title "Ensure 'Turn off the \"Order Prints\" picture task' is set to 'Enabled'"
  desc "Verify that 'Turn off the \"Order Prints\" picture task' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoOnlinePrintsWizard') { should eq 1 }
  end
end

# 203. Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
control 'win2019-turn-off-publish-to-web-task' do
  title "Ensure 'Turn off the \"Publish to Web\" task for files and folders' is set to 'Enabled'"
  desc "Verify that 'Turn off the \"Publish to Web\" task for files and folders' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoPublishingWizard') { should eq 1 }
  end
end

# 204. Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
control 'win2019-turn-off-messenger-customer-experience' do
  title "Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'"
  desc "Verify that 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger') do
    its('CEIP') { should eq 0 }
  end
end

# 205. Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
control 'win2019-turn-off-windows-customer-experience' do
  title "Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'"
  desc "Verify that 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SQMClient') do
    its('CEIPEnable') { should eq 0 }
  end
end

# 206. Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
control 'win2019-turn-off-windows-error-reporting' do
  title "Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'"
  desc "Verify that 'Turn off Windows Error Reporting' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Error Reporting') do
    its('Disabled') { should eq 1 }
  end
end

# 207. Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'
control 'win2019-support-device-authentication-certificate' do
  title "Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'"
  desc "Verify that 'Support device authentication using certificate' is set to 'Enabled: Automatic'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceAuthentication') do
    its('CertificateAuthentication') { should eq 1 }
  end
end

# 208. Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'
control 'win2019-disallow-copying-user-input-methods' do
  title "Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'"
  desc "Verify that 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Control Panel\International') do
    its('BlockUserInputMethodsForSystem') { should eq 1 }
  end
end

# 209. Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'
control 'win2019-enumeration-policy-external-devices' do
  title "Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'"
  desc "Verify that 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\KernelDMAProtection') do
    its('ExternalDeviceEnumerationPolicy') { should eq 0 }
  end
end

# 210. Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'
control 'win2019-block-user-account-details-sign-in' do
  title "Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'"
  desc "Verify that 'Block user from showing account details on sign-in' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('BlockUserAccountDetails') { should eq 1 }
  end
end

# 211. Ensure 'Do not display network selection UI' is set to 'Enabled'
control 'win2019-do-not-display-network-selection-ui' do
  title "Ensure 'Do not display network selection UI' is set to 'Enabled'"
  desc "Verify that 'Do not display network selection UI' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DontDisplayNetworkSelectionUI') { should eq 1 }
  end
end

# 212. Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'
control 'win2019-do-not-enumerate-connected-users' do
  title "Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'"
  desc "Verify that 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DontEnumerateConnectedUsers') { should eq 1 }
  end
end

# 213. Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'
control 'win2019-enumerate-local-users-disabled' do
  title "Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'"
  desc "Verify that 'Enumerate local users on domain-joined computers' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('EnumerateLocalUsers') { should eq 0 }
  end
end

# 214. Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'
control 'win2019-turn-off-app-notifications-lock-screen' do
  title "Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'"
  desc "Verify that 'Turn off app notifications on the lock screen' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DisableLockScreenAppNotifications') { should eq 1 }
  end
end

# 215. Ensure 'Turn off picture password sign-in' is set to 'Enabled'
control 'win2019-turn-off-picture-password-sign-in' do
  title "Ensure 'Turn off picture password sign-in' is set to 'Enabled'"
  desc "Verify that 'Turn off picture password sign-in' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('BlockPicturePassword') { should eq 1 }
  end
end

# 216. Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
control 'win2019-turn-on-convenience-pin-sign-in' do
  title "Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'"
  desc "Verify that 'Turn on convenience PIN sign-in' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('AllowDomainPINLogon') { should eq 0 }
  end
end

# 217. Ensure 'Untrusted Font Blocking' is set to 'Enabled: Block untrusted fonts and log events'
control 'win2019-untrusted-font-blocking' do
  title "Ensure 'Untrusted Font Blocking' is set to 'Enabled: Block untrusted fonts and log events'"
  desc "Verify that 'Untrusted Font Blocking' is set to 'Enabled: Block untrusted fonts and log events'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\MitigationOptions') do
    its('MitigationOptions_Font') { should eq 1000000000000 }
  end
end

# 218. Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled'
control 'win2019-allow-clipboard-sync-disabled' do
  title "Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled'"
  desc "Verify that 'Allow Clipboard synchronization across devices' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('AllowCrossDeviceClipboard') { should eq 0 }
  end
end

# 219. Ensure 'Allow upload of User Activities' is set to 'Disabled'
control 'win2019-allow-upload-user-activities-disabled' do
  title "Ensure 'Allow upload of User Activities' is set to 'Disabled'"
  desc "Verify that 'Allow upload of User Activities' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('UploadUserActivities') { should eq 0 }
  end
end

# 220. Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'
control 'win2019-allow-network-connectivity-connected-standby-battery' do
  title "Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'"
  desc "Verify that 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Power') do
    its('AllowConnectedStandbyBattery') { should eq 0 }
  end
end

# 221. Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'
control 'win2019-allow-network-connectivity-connected-standby-plugged-in' do
  title "Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'"
  desc "Verify that 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Power') do
    its('AllowConnectedStandbyPluggedIn') { should eq 0 }
  end
end

# 222. Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'
control 'win2019-require-password-computer-wakes-battery' do
  title "Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'"
  desc "Verify that 'Require a password when a computer wakes (on battery)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Power') do
    its('PromptPasswordOnResumeBattery') { should eq 1 }
  end
end

# 223. Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'
control 'win2019-require-password-computer-wakes-plugged-in' do
  title "Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'"
  desc "Verify that 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Power') do
    its('PromptPasswordOnResumePluggedIn') { should eq 1 }
  end
end

# 224. Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
control 'win2019-configure-offer-remote-assistance' do
  title "Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
  desc "Verify that 'Configure Offer Remote Assistance' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fAllowUnsolicited') { should eq 0 }
  end
end

# 225. Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
control 'win2019-configure-solicited-remote-assistance' do
  title "Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
  desc "Verify that 'Configure Solicited Remote Assistance' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fAllowToGetHelp') { should eq 0 }
  end
end

# 226. Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'
control 'win2019-enable-rpc-endpoint-mapper-authentication' do
  title "Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'"
  desc "Verify that 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('EnableAuthEpMapper') { should eq 1 }
  end
end

# 227. Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'
control 'win2019-restrict-unauthenticated-rpc-clients' do
  title "Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'"
  desc "Verify that 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('RestrictRemoteClients') { should eq 1 }
  end
end

# 228. Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'
control 'win2019-enable-disable-perftrack' do
  title "Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'"
  desc "Verify that 'Enable/Disable PerfTrack' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WDI') do
    its('DisableWdiPerfTrack') { should eq 1 }
  end
end

# 229. Ensure 'Turn off the advertising ID' is set to 'Enabled'
control 'win2019-turn-off-advertising-id' do
  title "Ensure 'Turn off the advertising ID' is set to 'Enabled'"
  desc "Verify that 'Turn off the advertising ID' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AdvertisingInfo') do
    its('Disabled') { should eq 1 }
  end
end

# 230. Ensure 'Enable Windows NTP Client' is set to 'Enabled'
control 'win2019-enable-windows-ntp-client' do
  title "Ensure 'Enable Windows NTP Client' is set to 'Enabled'"
  desc "Verify that 'Enable Windows NTP Client' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\W32Time\Parameters') do
    its('NtpClientEnabled') { should eq 1 }
  end
end

# 231. Ensure 'Enable Windows NTP Server' is set to 'Disabled'
control 'win2019-enable-windows-ntp-server' do
  title "Ensure 'Enable Windows NTP Server' is set to 'Disabled'"
  desc "Verify that 'Enable Windows NTP Server' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\W32Time\Parameters') do
    its('NtpServerEnabled') { should eq 0 }
  end
end

# 232. Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'
control 'win2019-allow-app-data-sharing-disabled' do
  title "Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'"
  desc "Verify that 'Allow a Windows app to share application data between users' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy') do
    its('SharedUserData') { should eq 0 }
  end
end

# 233. Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
control 'win2019-allow-microsoft-accounts-optional' do
  title "Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
  desc "Verify that 'Allow Microsoft accounts to be optional' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('AllowMicrosoftAccountSignIn') { should eq 1 }
  end
end

# 234. Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
control 'win2019-disallow-autoplay-non-volume-devices' do
  title "Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
  desc "Verify that 'Disallow Autoplay for non-volume devices' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoAutoplayNonVolume') { should eq 1 }
  end
end

# 235. Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
control 'win2019-set-default-behavior-autorun' do
  title "Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'"
  desc "Verify that 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('NoDriveTypeAutoRun') { should eq 255 }
  end
end

# 236. Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
control 'win2019-turn-off-autoplay' do
  title "Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'"
  desc "Verify that 'Turn off Autoplay' is set to 'Enabled: All drives'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('NoDriveTypeAutoRun') { should eq 255 }
  end
end

# 237. Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'
control 'win2019-configure-enhanced-anti-spoofing' do
  title "Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'"
  desc "Verify that 'Configure enhanced anti-spoofing' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Biometrics') do
    its('EnhancedAntiSpoofing') { should eq 1 }
  end
end

# 238. Ensure 'Allow Use of Camera' is set to 'Disabled'
control 'win2019-allow-use-of-camera-disabled' do
  title "Ensure 'Allow Use of Camera' is set to 'Disabled'"
  desc "Verify that 'Allow Use of Camera' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Camera') do
    its('AllowCamera') { should eq 0 }
  end
end

# 239. Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'
control 'win2019-turn-off-microsoft-consumer-experiences' do
  title "Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
  desc "Verify that 'Turn off Microsoft consumer experiences' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableWindowsConsumerFeatures') { should eq 1 }
  end
end

# 240. Ensure 'Require pin for pairing' is set to 'Enabled'
control 'win2019-require-pin-for-pairing' do
  title "Ensure 'Require pin for pairing' is set to 'Enabled'"
  desc "Verify that 'Require pin for pairing' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DevicePairing') do
    its('RequirePinForPairing') { should eq 1 }
  end
end

# 241. Ensure 'Do not display the password reveal button' is set to 'Enabled'
control 'win2019-do-not-display-password-reveal-button' do
  title "Ensure 'Do not display the password reveal button' is set to 'Enabled'"
  desc "Verify that 'Do not display the password reveal button' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI') do
    its('DisablePasswordReveal') { should eq 1 }
  end
end

# 242. Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
control 'win2019-enumerate-admin-accounts-disabled' do
  title "Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
  desc "Verify that 'Enumerate administrator accounts on elevation' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('EnumerateAdministrators') { should eq 0 }
  end
end

# 243. Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'
control 'win2019-allow-telemetry' do
  title "Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'"
  desc "Verify that 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection') do
    its('AllowTelemetry') { should be_in [0, 1] }
  end
end

# 244. Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'
control 'win2019-configure-authenticated-proxy-telemetry' do
  title "Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'"
  desc "Verify that 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection') do
    its('DisableAuthProxy') { should eq 1 }
  end
end

# 245. Ensure 'Do not show feedback notifications' is set to 'Enabled'
control 'win2019-do-not-show-feedback-notifications' do
  title "Ensure 'Do not show feedback notifications' is set to 'Enabled'"
  desc "Verify that 'Do not show feedback notifications' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\FeedbackNotifications') do
    its('Disabled') { should eq 1 }
  end
end

# 246. Ensure 'Toggle user control over Insider builds' is set to 'Disabled'
control 'win2019-toggle-user-control-insider-builds' do
  title "Ensure 'Toggle user control over Insider builds' is set to 'Disabled'"
  desc "Verify that 'Toggle user control over Insider builds' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PreviewBuilds') do
    its('AllowBuildPreview') { should eq 0 }
  end
end

# 247. Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
control 'win2019-application-control-event-log-max-size' do
  title "Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc "Verify that 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application') do
    its('Retention') { should eq 0 }
  end
end

# 248. Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
control 'win2019-application-max-log-file-size' do
  title "Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc "Verify that 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application') do
    its('MaxSize') { should be >= 32768 }
  end
end

# 249. Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
control 'win2019-security-control-event-log-max-size' do
  title "Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc "Verify that 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security') do
    its('Retention') { should eq 0 }
  end
end

# 250. Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
control 'win2019-security-max-log-file-size' do
  title "Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'"
  desc "Verify that 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security') do
    its('MaxSize') { should be >= 196608 }
  end
end

# 251. Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
control 'win2019-setup-control-event-log-max-size' do
  title "Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc "Verify that 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup') do
    its('Retention') { should eq 0 }
  end
end

# 252. Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
control 'win2019-setup-max-log-file-size' do
  title "Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc "Verify that 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup') do
    its('MaxSize') { should be >= 32768 }
  end
end

# 253. Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
control 'win2019-system-control-event-log-max-size' do
  title "Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc "Verify that 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System') do
    its('Retention') { should eq 0 }
  end
end

# 254. Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
control 'win2019-system-max-log-file-size' do
  title "Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc "Verify that 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System') do
    its('MaxSize') { should be >= 32768 }
  end
end

# 255. Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
control 'win2019-turn-off-dep-explorer' do
  title "Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"
  desc "Verify that 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoDataExecutionPrevention') { should eq 0 }
  end
end

# 256. Ensure 'Turn off heap termination on corruption' is set to 'Disabled'
control 'win2019-turn-off-heap-termination-corruption' do
  title "Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"
  desc "Verify that 'Turn off heap termination on corruption' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoHeapTerminationOnCorruption') { should eq 0 }
  end
end

# 257. Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'
control 'win2019-turn-off-shell-protocol-protected-mode' do
  title "Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'"
  desc "Verify that 'Turn off shell protocol protected mode' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoShellProtocolProtectedMode') { should eq 0 }
  end
end

# 258. Ensure 'Turn off location' is set to 'Enabled'
control 'win2019-turn-off-location' do
  title "Ensure 'Turn off location' is set to 'Enabled'"
  desc "Verify that 'Turn off location' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors') do
    its('DisableLocation') { should eq 1 }
  end
end

# 259. Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'
control 'win2019-allow-message-service-cloud-sync' do
  title "Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'"
  desc "Verify that 'Allow Message Service Cloud Sync' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Messaging') do
    its('AllowCloudSync') { should eq 0 }
  end
end

# 260. Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'
control 'win2019-block-consumer-microsoft-account-authentication' do
  title "Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'"
  desc "Verify that 'Block all consumer Microsoft account user authentication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('BlockMicrosoftAccount') { should eq 1 }
  end
end

# 261. Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'
control 'win2019-prevent-onedrive-file-storage' do
  title "Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'"
  desc "Verify that 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\OneDrive') do
    its('DisableFileSync') { should eq 1 }
  end
end

# 262. Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
control 'win2019-do-not-allow-passwords-saved' do
  title "Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
  desc "Verify that 'Do not allow passwords to be saved' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI') do
    its('DisablePasswordSaving') { should eq 1 }
  end
end

# 263. Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'
control 'win2019-restrict-rds-single-session' do
  title "Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'"
  desc "Verify that 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fSingleSessionPerUser') { should eq 1 }
  end
end

# 264. Ensure 'Do not allow COM port redirection' is set to 'Enabled'
control 'win2019-do-not-allow-com-port-redirection' do
  title "Ensure 'Do not allow COM port redirection' is set to 'Enabled'"
  desc "Verify that 'Do not allow COM port redirection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('DisableComPortRedirection') { should eq 1 }
  end
end

# 265. Ensure 'Do not allow drive redirection' is set to 'Enabled'
control 'win2019-do-not-allow-drive-redirection' do
  title "Ensure 'Do not allow drive redirection' is set to 'Enabled'"
  desc "Verify that 'Do not allow drive redirection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('DisableDriveRedirection') { should eq 1 }
  end
end

# 266. Ensure 'Do not allow LPT port redirection' is set to 'Enabled'
control 'win2019-do-not-allow-lpt-port-redirection' do
  title "Ensure 'Do not allow LPT port redirection' is set to 'Enabled'"
  desc "Verify that 'Do not allow LPT port redirection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('DisableLPTPortRedirection') { should eq 1 }
  end
end

# 267. Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'
control 'win2019-do-not-allow-pnp-device-redirection' do
  title "Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'"
  desc "Verify that 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('DisablePNPRedirection') { should eq 1 }
  end
end

# 268. Ensure 'Require secure RPC communication' is set to 'Enabled'
control 'win2019-require-secure-rpc-communication' do
  title "Ensure 'Require secure RPC communication' is set to 'Enabled'"
  desc "Verify that 'Require secure RPC communication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('EnableSecureRPC') { should eq 1 }
  end
end

# 269. Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'
control 'win2019-require-specific-security-layer-rdp' do
  title "Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'"
  desc "Verify that 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('SecurityLayer') { should eq 2 }
  end
end

# 270. Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'
control 'win2019-require-user-authentication-nla' do
  title "Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'"
  desc "Verify that 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('UserAuthentication') { should eq 1 }
  end
end

# 271. Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
control 'win2019-set-client-connection-encryption-level' do
  title "Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
  desc "Verify that 'Set client connection encryption level' is set to 'Enabled: High Level'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('MinEncryptionLevel') { should eq 3 }
  end
end

# 272. Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'
control 'win2019-set-time-limit-idle-rds-sessions' do
  title "Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'"
  desc "Verify that 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('IdleTimeout') { should be <= 900 }
  end
end

# 273. Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
control 'win2019-do-not-delete-temp-folders-exit' do
  title "Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'"
  desc "Verify that 'Do not delete temp folders upon exit' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('DeleteTempFolders') { should eq 1 }
  end
end

# 274. Ensure 'Do not use temporary folders per session' is set to 'Disabled'
control 'win2019-do-not-use-temp-folders-per-session' do
  title "Ensure 'Do not use temporary folders per session' is set to 'Disabled'"
  desc "Verify that 'Do not use temporary folders per session' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('PerSessionTempFolders') { should eq 1 }
  end
end

# 275. Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
control 'win2019-prevent-downloading-enclosures' do
  title "Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"
  desc "Verify that 'Prevent downloading of enclosures' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoEnclosureDownload') { should eq 1 }
  end
end

# 276. Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'
control 'win2019-allow-cloud-search' do
  title "Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'"
  desc "Verify that 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Search') do
    its('DisableCloudSearch') { should eq 1 }
  end
end

# 277. Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
control 'win2019-allow-indexing-encrypted-files' do
  title "Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
  desc "Verify that 'Allow indexing of encrypted files' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Search') do
    its('AllowIndexingEncryptedStoresOrItems') { should eq 0 }
  end
end

# 278. Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'
control 'win2019-turn-off-kms-client-avs-validation' do
  title "Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'"
  desc "Verify that 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\KMSClient') do
    its('DisableAVSValidation') { should eq 1 }
  end
end

# 279. Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'
control 'win2019-allow-suggested-apps-ink-workspace' do
  title "Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'"
  desc "Verify that 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsInkWorkspace') do
    its('AllowSuggestedApps') { should eq 0 }
  end
end

# 280. Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'
control 'win2019-allow-windows-ink-workspace' do
  title "Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'"
  desc "Verify that 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsInkWorkspace') do
    its('AllowWindowsInkWorkspace') { should be_in [0, 2] }
  end
end

# 281. Ensure 'Allow user control over installs' is set to 'Disabled'
control 'win2019-allow-user-control-installs' do
  title "Ensure 'Allow user control over installs' is set to 'Disabled'"
  desc "Verify that 'Allow user control over installs' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer') do
    its('EnableUserControl') { should eq 0 }
  end
end

# 282. Ensure 'Always install with elevated privileges' is set to 'Disabled'
control 'win2019-always-install-elevated-privileges' do
  title "Ensure 'Always install with elevated privileges' is set to 'Disabled'"
  desc "Verify that 'Always install with elevated privileges' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer') do
    its('AlwaysInstallElevated') { should eq 0 }
  end
end

# 283. Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'
control 'win2019-prevent-sharing-files-profile' do
  title "Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'"
  desc "Verify that 'Prevent users from sharing files within their profile.' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DisableProfileSharing') { should eq 1 }
  end
end

# 284. Ensure 'Prevent Codec Download' is set to 'Enabled'
control 'win2019-prevent-codec-download' do
  title "Ensure 'Prevent Codec Download' is set to 'Enabled'"
  desc "Verify that 'Prevent Codec Download' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\MediaPlayer') do
    its('PreventCodecDownload') { should eq 1 }
  end
end

# 285. Antivirus software is not installed
control 'win2019-antivirus-software-not-installed' do
  title "Antivirus software is not installed"
  desc "Verify that antivirus software is installed."
  impact 1.0
  describe command('Get-MpComputerStatus') do
    its('AntivirusEnabled') { should eq true }
  end
end

# 286. Ensure 'Print Spooler (Spooler)' is set to 'Disabled'
control 'win2019-print-spooler-disabled' do
  title "Ensure 'Print Spooler (Spooler)' is set to 'Disabled'"
  desc "Verify that 'Print Spooler (Spooler)' is set to 'Disabled'."
  impact 1.0
  describe service('Spooler') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end

# 287. Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'
control 'win2019-point-print-restrictions-new-connection' do
  title "Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'"
  desc "Verify that 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint') do
    its('RestrictDriverInstallationToAdministrators') { should eq 1 }
  end
end

# 288. Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'
control 'win2019-point-print-restrictions-existing-connection' do
  title "Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'"
  desc "Verify that 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint') do
    its('RestrictDriverInstallationToAdministrators') { should eq 1 }
  end
end

# 289. Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'
control 'win2019-allow-print-spooler-client-connections' do
  title "Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'"
  desc "Verify that 'Allow Print Spooler to accept client connections' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers') do
    its('DisableClientConnections') { should eq 1 }
  end
end

# 290. Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'
control 'win2019-prevent-device-metadata-retrieval' do
  title "Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'"
  desc "Verify that 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceMetadata') do
    its('PreventDeviceMetadataFromNetwork') { should eq 1 }
  end
end

# 291. Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'
control 'win2019-limit-print-driver-installation' do
  title "Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'"
  desc "Verify that 'Limits print driver installation to Administrators' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint') do
    its('RestrictDriverInstallationToAdministrators') { should eq 1 }
  end
end

# 292. Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher
control 'win2019-configure-dns-over-https' do
  title "Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher"
  desc "Verify that 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DNSClient') do
    its('EnableAutoDoH') { should eq 1 }
  end
end

# 293. Ensure 'Turn off Push To Install service' is set to 'Enabled' (Automated)
control 'win2019-turn-off-push-to-install' do
  title "Ensure 'Turn off Push To Install service' is set to 'Enabled' (Automated)"
  desc "Verify that 'Turn off Push To Install service' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PushToInstall') do
    its('DisablePushToInstall') { should eq 1 }
  end
end

# 294. Ensure 'Manage preview builds' is set to 'Disabled: Disable preview builds'
control 'win2019-manage-preview-builds' do
  title "Ensure 'Manage preview builds' is set to 'Disabled: Disable preview builds'"
  desc "Verify that 'Manage preview builds' is set to 'Disabled: Disable preview builds'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PreviewBuilds') do
    its('AllowBuildPreview') { should eq 0 }
  end
end

# 295. Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'
control 'win2019-select-preview-builds-feature-updates' do
  title "Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'"
  desc "Verify that 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate') do
    its('DeferFeatureUpdates') { should eq 1 }
    its('DeferFeatureUpdatesPeriodInDays') { should be >= 180 }
  end
end

# 296. Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'
control 'win2019-select-quality-updates' do
  title "Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'"
  desc "Verify that 'Select when Quality Updates are received' is set to 'Enabled: 0 days'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate') do
    its('DeferQualityUpdates') { should eq 1 }
    its('DeferQualityUpdatesPeriodInDays') { should eq 0 }
  end
end

# 297. Ensure 'Configure Automatic Updates' is set to 'Enabled'
control 'win2019-configure-automatic-updates' do
  title "Ensure 'Configure Automatic Updates' is set to 'Enabled'"
  desc "Verify that 'Configure Automatic Updates' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU') do
    its('NoAutoUpdate') { should eq 0 }
  end
end

# 298. Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'
control 'win2019-configure-automatic-updates-scheduled-day' do
  title "Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'"
  desc "Verify that 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU') do
    its('ScheduledInstallDay') { should eq 0 }
  end
end

# 299. Ensure 'Enable screen saver' is set to 'Enabled'
control 'win2019-enable-screen-saver' do
  title "Ensure 'Enable screen saver' is set to 'Enabled'"
  desc "Verify that 'Enable screen saver' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_CURRENT_USER\Control Panel\Desktop') do
    its('ScreenSaveActive') { should eq "1" }
  end
end

# 300. Ensure 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'
control 'win2019-force-specific-screen-saver' do
  title "Ensure 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'"
  desc "Verify that 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'."
  impact 1.0
  describe registry_key('HKEY_CURRENT_USER\Control Panel\Desktop') do
    its('SCRNSAVE.EXE') { should eq "scrnsave.scr" }
  end
end

# 301. Ensure 'Password protect the screen saver' is set to 'Enabled'
control 'win2019-password-protect-screen-saver' do
  title "Ensure 'Password protect the screen saver' is set to 'Enabled'"
  desc "Verify that 'Password protect the screen saver' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_CURRENT_USER\Control Panel\Desktop') do
    its('ScreenSaverIsSecure') { should eq "1" }
  end
end

# 302. Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'
control 'win2019-screen-saver-timeout' do
  title "Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'"
  desc "Verify that 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'."
  impact 1.0
  describe registry_key('HKEY_CURRENT_USER\Control Panel\Desktop') do
    its('ScreenSaveTimeOut') { should be > 0 }
    its('ScreenSaveTimeOut') { should be <= 900 }
  end
end

# 303. Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'
control 'win2019-turn-off-toast-notifications-lock-screen' do
  title "Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'"
  desc "Verify that 'Turn off toast notifications on the lock screen' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications') do
    its('NoToastApplicationNotification') { should eq 1 }
  end
end

# 304. Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'
control 'win2019-turn-off-help-experience-improvement' do
  title "Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'"
  desc "Verify that 'Turn off Help Experience Improvement Program' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Assistance\Client\1.0') do
    its('NoImplicitFeedback') { should eq 1 }
  end
end

# 305. Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'
control 'win2019-do-not-preserve-zone-info-file-attachments' do
  title "Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'"
  desc "Verify that 'Do not preserve zone information in file attachments' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Attachments') do
    its('SaveZoneInformation') { should eq 1 }
  end
end

# 306. Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'
control 'win2019-notify-antivirus-opening-attachments' do
  title "Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'"
  desc "Verify that 'Notify antivirus programs when opening attachments' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Attachments') do
    its('ScanWithAntiVirus') { should eq 1 }
  end
end

# 307. Ensure 'Configure Windows spotlight on lock screen' is set to Disabled'
control 'win2019-configure-windows-spotlight-lock-screen' do
  title "Ensure 'Configure Windows spotlight on lock screen' is set to Disabled'"
  desc "Verify that 'Configure Windows spotlight on lock screen' is set to Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableWindowsSpotlightOnActionCenter') { should eq 1 }
  end
end

# 308. Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'
control 'win2019-do-not-suggest-third-party-content-spotlight' do
  title "Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'"
  desc "Verify that 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableThirdPartySuggestions') { should eq 1 }
  end
end

# 309. Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'
control 'win2019-do-not-use-diagnostic-data-tailored-experiences' do
  title "Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'"
  desc "Verify that 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableTailoredExperiencesWithDiagnosticData') { should eq 1 }
  end
end

# 310. Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'
control 'win2019-turn-off-all-windows-spotlight-features' do
  title "Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'"
  desc "Verify that 'Turn off all Windows spotlight features' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableWindowsSpotlightFeatures') { should eq 1 }
  end
end

# 311. Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'
control 'win2019-prevent-sharing-files-profile' do
  title "Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'"
  desc "Verify that 'Prevent users from sharing files within their profile.' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DisableProfileSharing') { should eq 1 }
  end
end

# 312. Ensure 'Always install with elevated privileges' is set to 'Disabled'
control 'win2019-always-install-elevated-privileges' do
  title "Ensure 'Always install with elevated privileges' is set to 'Disabled'"
  desc "Verify that 'Always install with elevated privileges' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer') do
    its('AlwaysInstallElevated') { should eq 0 }
  end
end

# 313. Ensure 'Prevent Codec Download' is set to 'Enabled'
control 'win2019-prevent-codec-download' do
  title "Ensure 'Prevent Codec Download' is set to 'Enabled'"
  desc "Verify that 'Prevent Codec Download' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\MediaPlayer') do
    its('PreventCodecDownload') { should eq 1 }
  end
end

# 314. Antivirus software is not installed
control 'win2019-antivirus-software-not-installed' do
  title "Antivirus software is not installed"
  desc "Verify that antivirus software is installed."
  impact 1.0
  describe command('Get-MpComputerStatus') do
    its('AntivirusEnabled') { should eq true }
  end
end

# 315. Ensure 'Print Spooler (Spooler)' is set to 'Disabled'
control 'win2019-print-spooler-disabled' do
  title "Ensure 'Print Spooler (Spooler)' is set to 'Disabled'"
  desc "Verify that 'Print Spooler (Spooler)' is set to 'Disabled'."
  impact 1.0
  describe service('Spooler') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end

# 316. Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'
control 'win2019-point-print-restrictions-new-connection' do
  title "Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'"
  desc "Verify that 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint') do
    its('RestrictDriverInstallationToAdministrators') { should eq 1 }
  end
end

# 317. Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'
control 'win2019-point-print-restrictions-existing-connection' do
  title "Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'"
  desc "Verify that 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint') do
    its('RestrictDriverInstallationToAdministrators') { should eq 1 }
  end
end

# 318. Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'
control 'win2019-allow-print-spooler-client-connections' do
  title "Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'"
  desc "Verify that 'Allow Print Spooler to accept client connections' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers') do
    its('DisableClientConnections') { should eq 1 }
  end
end

# 319. Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'
control 'win2019-prevent-device-metadata-retrieval' do
  title "Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'"
  desc "Verify that 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceMetadata') do
    its('PreventDeviceMetadataFromNetwork') { should eq 1 }
  end
end

# 320. Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'
control 'win2019-limit-print-driver-installation' do
  title "Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'"
  desc "Verify that 'Limits print driver installation to Administrators' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint') do
    its('RestrictDriverInstallationToAdministrators') { should eq 1 }
  end
end

# 321. Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher
control 'win2019-configure-dns-over-https' do
  title "Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher"
  desc "Verify that 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DNSClient') do
    its('EnableAutoDoH') { should eq 1 }
  end
end

# 322. Ensure 'Turn off cloud consumer account state content' is set to 'Enabled'
control 'win2019-turn-off-cloud-consumer-account-content' do
  title "Ensure 'Turn off cloud consumer account state content' is set to 'Enabled'"
  desc "Verify that 'Turn off cloud consumer account state content' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableCloudConsumerAccountContent') { should eq 1 }
  end
end

# 323. Ensure 'Enable OneSettings Auditing' is set to 'Enabled'
control 'win2019-enable-onesettings-auditing' do
  title "Ensure 'Enable OneSettings Auditing' is set to 'Enabled'"
  desc "Verify that 'Enable OneSettings Auditing' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\OneSettings') do
    its('EnableAuditing') { should eq 1 }
  end
end

# 324. Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled'
control 'win2019-limit-diagnostic-log-collection' do
  title "Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled'"
  desc "Verify that 'Limit Diagnostic Log Collection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection') do
    its('LimitDiagnosticLogCollection') { should eq 1 }
  end
end

# 325. Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled'
control 'win2019-turn-off-spotlight-collection-desktop' do
  title "Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled'"
  desc "Verify that 'Turn off Spotlight collection on Desktop' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableWindowsSpotlightCollection') { should eq 1 }
  end
end

# 326. Ensure 'Disable OneSettings Downloads' is set to 'Enabled'
control 'win2019-disable-onesettings-downloads' do
  title "Ensure 'Disable OneSettings Downloads' is set to 'Enabled'"
  desc "Verify that 'Disable OneSettings Downloads' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\OneSettings') do
    its('DisableDownloads') { should eq 1 }
  end
end

# 327. Ensure to turn on Module Logging
control 'win2019-turn-on-module-logging' do
  title "Ensure to turn on Module Logging"
  desc "Verify that Module Logging is turned on."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging') do
    its('EnableModuleLogging') { should eq 1 }
  end
end

# 328. Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'
control 'win2019-configure-rpc-packet-privacy' do
  title "Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'"
  desc "Verify that 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('EnablePacketPrivacy') { should eq 1 }
  end
end

# 329. Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'
control 'win2019-configure-netbios-settings' do
  title "Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'"
  desc "Verify that 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetBIOS') do
    its('DisableNetBIOSOnPublicNetworks') { should eq 1 }
  end
end

# 330. Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock'
control 'win2019-configure-lsass-protected-process' do
  title "Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock'"
  desc "Verify that 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LSASS') do
    its('RunAsProtectedProcess') { should eq 1 }
  end
end

# 331. Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'
control 'win2019-configure-redirection-guard' do
  title "Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'"
  desc "Verify that 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RedirectionGuard') do
    its('EnableRedirectionGuard') { should eq 1 }
  end
end

# 332. Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'
control 'win2019-configure-rpc-connection-protocol' do
  title "Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'"
  desc "Verify that 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('ProtocolForOutgoingConnections') { should eq 'TCP' }
  end
end

# 333. Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'
control 'win2019-configure-rpc-connection-authentication' do
  title "Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'"
  desc "Verify that 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('AuthenticationForOutgoingConnections') { should eq 'Default' }
  end
end

# 334. Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'
control 'win2019-configure-rpc-listener-protocols' do
  title "Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'"
  desc "Verify that 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('ProtocolsForIncomingConnections') { should eq 'TCP' }
  end
end

# 335. Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher
control 'win2019-configure-rpc-listener-authentication' do
  title "Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher"
  desc "Verify that 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('AuthenticationProtocolForIncomingConnections') { should eq 'Negotiate' }
  end
end

# 336. Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0' (Automated)
control 'win2019-configure-rpc-tcp-port' do
  title "Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0' (Automated)"
  desc "Verify that 'Configure RPC over TCP port' is set to 'Enabled: 0'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('TcpPort') { should eq 0 }
  end
end

# 337. Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles' (Automated)
control 'win2019-manage-queue-specific-files' do
  title "Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles' (Automated)"
  desc "Verify that 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\QueueProcessing') do
    its('LimitQueueSpecificFiles') { should eq 'ColorProfiles' }
  end
end

# 338. Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data' (Automated)
control 'win2019-allow-diagnostic-data' do
  title "Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data' (Automated)"
  desc "Verify that 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection') do
    its('DiagnosticData') { should eq 'Required' }
  end
end

# 339. Ensure 'Limit Dump Collection' is set to 'Enabled' (Automated)
control 'win2019-limit-dump-collection' do
  title "Ensure 'Limit Dump Collection' is set to 'Enabled' (Automated)"
  desc "Verify that 'Limit Dump Collection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\ErrorReporting') do
    its('LimitDumpCollection') { should eq 1 }
  end
end

# 340. Ensure 'Enable App Installer' is set to 'Disabled' (Automated)
control 'win2019-enable-app-installer' do
  title "Ensure 'Enable App Installer' is set to 'Disabled' (Automated)"
  desc "Verify that 'Enable App Installer' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppInstaller') do
    its('EnableAppInstaller') { should eq 0 }
  end
end

# 341. Ensure 'Enable App Installer Experimental Features' is set to 'Disabled' (Automated)
control 'win2019-enable-app-installer-experimental-features' do
  title "Ensure 'Enable App Installer Experimental Features' is set to 'Disabled' (Automated)"
  desc "Verify that 'Enable App Installer Experimental Features' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppInstaller') do
    its('EnableExperimentalFeatures') { should eq 0 }
  end
end

# 342. Ensure 'Enable App Installer Hash Override' is set to 'Disabled' (Automated)
control 'win2019-enable-app-installer-hash-override' do
  title "Ensure 'Enable App Installer Hash Override' is set to 'Disabled' (Automated)"
  desc "Verify that 'Enable App Installer Hash Override' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppInstaller') do
    its('EnableHashOverride') { should eq 0 }
  end
end

# 343. Ensure 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled' (Automated)
control 'win2019-enable-app-installer-protocol' do
  title "Ensure 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled' (Automated)"
  desc "Verify that 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppInstaller') do
    its('EnableProtocol') { should eq 0 }
  end
end

# 344. Ensure 'Turn off Push To Install service' is set to 'Enabled' (Automated)
control 'win2019-turn-off-push-to-install' do
  title "Ensure 'Turn off Push To Install service' is set to 'Enabled' (Automated)"
  desc "Verify that 'Turn off Push To Install service' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PushToInstall') do
    its('DisablePushToInstall') { should eq 1 }
  end
end

# 345. Ensure 'Allow search highlights' is set to 'Disabled' (Automated)
control 'win2019-allow-search-highlights' do
  title "Ensure 'Allow search highlights' is set to 'Disabled' (Automated)"
  desc "Verify that 'Allow search highlights' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Search') do
    its('AllowSearchHighlights') { should eq 0 }
  end
end

# 346. Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'
control 'win2019-turn-off-msdt-interactive-communication' do
  title "Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'"
  desc "Verify that 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\MSDT') do
    its('EnableInteractiveCommunication') { should eq 0 }
  end
end

# 347. Ensure 'Allow Administrator account lockout' is set to 'Enabled'
control 'win2019-allow-administrator-account-lockout' do
  title "Ensure 'Allow Administrator account lockout' is set to 'Enabled'"
  desc "Verify that 'Allow Administrator account lockout' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AccountLockout') do
    its('EnableAdministratorLockout') { should eq 1 }
  end
end

# 348. Ensure active User ID's which were not logged in for more than 90 days or never is to be disabled
control 'win2019-disable-inactive-user-ids' do
  title "Ensure active User ID's which were not logged in for more than 90 days or never is to be disabled"
  desc "Verify that active User ID's which were not logged in for more than 90 days or never is to be disabled."
  impact 1.0
  describe command('Get-ADUser -Filter {LastLogonDate -lt (Get-Date).AddDays(-90)}') do
    its('Disabled') { should eq true }
  end
end

# 349. Ensure no Users are present in Administrator group except Profiles ID
control 'win2019-restrict-administrator-group' do
  title "Ensure no Users are present in Administrator group except Profiles ID"
  desc "Verify that no Users are present in Administrator group except Profiles ID."
  impact 1.0
  describe command('Get-LocalGroupMember -Group Administrators') do
    its('Members') { should eq ['Profiles ID'] }
  end
end

# 350. Ensure System Files are not having write permissions to Everyone
control 'win2019-restrict-system-file-permissions' do
  title "Ensure System Files are not having write permissions to Everyone"
  desc "Verify that System Files are not having write permissions to Everyone."
  impact 1.0
  describe file('C:\Windows\System32') do
    it { should_not be_writable.by('Everyone') }
  end
end

# 351. Ensure 'Configure security policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
control 'win2019-configure-security-policy-processing' do
  title "Ensure 'Configure security policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"
  desc "Verify that 'Configure security policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\GroupPolicy') do
    its('DisableBackgroundProcessing') { should eq 0 }
  end
end

# 352. Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'
control 'win2019-restrict-ntlm-audit-incoming' do
  title "Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'"
  desc "Verify that 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('AuditIncomingNTLM') { should eq 'Enable auditing for all accounts' }
  end
end

# 353. Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher
control 'win2019-restrict-ntlm-outgoing' do
  title "Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher"
  desc "Verify that 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('RestrictOutgoingNTLM') { should eq 'Audit all' }
  end
end

# 354. Ensure 'Enable Certificate Padding' is set to 'Enabled'
control 'win2019-enable-certificate-padding' do
  title "Ensure 'Enable Certificate Padding' is set to 'Enabled'"
  desc "Verify that 'Enable Certificate Padding' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CertificatePadding') do
    its('EnablePadding') { should eq 1 }
  end
end

# 355. Disable Automounting
control 'win2019-disable-automounting' do
  title "Disable Automounting"
  desc "Verify that Automounting is disabled."
  impact 1.0
  describe command('mountvol /N') do
    its('exit_status') { should eq 0 }
  end
end

# 356. Disable USB Storage
control 'win2019-disable-usb-storage' do
  title "Disable USB Storage"
  desc "Verify that USB Storage is disabled."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\USBSTOR') do
    its('Start') { should eq 4 }
  end
end


