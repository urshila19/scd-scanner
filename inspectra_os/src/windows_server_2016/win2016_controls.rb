# Security controls for Windows Server 2016

# 1. Ensure 'Enforce password history' is set to '5 or more password(s)'
control 'win2016-ensure-enforce-password-history' do
  title "Ensure 'Enforce password history' is set to '5 or more password(s)'"
  desc "Verify that 'Enforce password history' is set to '5 or more password(s)'."
  impact 1.0
  describe security_policy do
    its('PasswordHistorySize') { should cmp >= 5 }
  end
end

# 2. Ensure 'Maximum password age' is set to '45 or fewer days, but not 0'
control 'win2016-ensure-maximum-password-age' do
  title "Ensure 'Maximum password age' is set to '45 or fewer days, but not 0'"
  desc "Verify that 'Maximum password age' is set to '45 or fewer days, but not 0'."
  impact 1.0
  describe security_policy do
    its('MaximumPasswordAge') { should cmp <= 45 }
    its('MaximumPasswordAge') { should cmp > 0 }
  end
end

# 3. Ensure 'Minimum password age' is set to '1 or more day(s)'
control 'win2016-ensure-minimum-password-age' do
  title "Ensure 'Minimum password age' is set to '1 or more day(s)'"
  desc "Verify that 'Minimum password age' is set to '1 or more day(s)'."
  impact 1.0
  describe security_policy do
    its('MinimumPasswordAge') { should cmp >= 1 }
  end
end

# 4. Ensure 'Minimum password length' is set to '8 or more character(s)'
control 'win2016-ensure-minimum-password-length' do
  title "Ensure 'Minimum password length' is set to '8 or more character(s)'"
  desc "Verify that 'Minimum password length' is set to '8 or more character(s)'."
  impact 1.0
  describe security_policy do
    its('MinimumPasswordLength') { should cmp >= 8 }
  end
end

# 5. Ensure 'Password must meet complexity requirements' is set to 'Enabled'
control 'win2016-ensure-password-complexity-requirements' do
  title "Ensure 'Password must meet complexity requirements' is set to 'Enabled'"
  desc "Verify that 'Password must meet complexity requirements' is set to 'Enabled'."
  impact 1.0
  describe security_policy do
    its('PasswordComplexity') { should cmp 1 }
  end
end

# 6. Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
control 'win2016-ensure-store-passwords-reversible-encryption-disabled' do
  title "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"
  desc "Verify that 'Store passwords using reversible encryption' is set to 'Disabled'."
  impact 1.0
  describe security_policy do
    its('ClearTextPassword') { should cmp 0 }
  end
end

# 7. Ensure 'Account lockout duration' is set to '15 or more minute(s)'
control 'win2016-ensure-account-lockout-duration' do
  title "Ensure 'Account lockout duration' is set to '15 or more minute(s)'"
  desc "Verify that 'Account lockout duration' is set to '15 or more minute(s)'."
  impact 1.0
  describe security_policy do
    its('LockoutDuration') { should cmp >= 15 }
  end
end

# 8. Ensure 'Account lockout threshold' is set to '3 or fewer invalid logon attempt(s), but not 0'
control 'win2016-ensure-account-lockout-threshold' do
  title "Ensure 'Account lockout threshold' is set to '3 or fewer invalid logon attempt(s), but not 0'"
  desc "Verify that 'Account lockout threshold' is set to '3 or fewer invalid logon attempt(s), but not 0'."
  impact 1.0
  describe security_policy do
    its('LockoutBadCount') { should cmp <= 3 }
    its('LockoutBadCount') { should cmp > 0 }
  end
end

# 9. Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
control 'win2016-ensure-reset-account-lockout-counter' do
  title "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'"
  desc "Verify that 'Reset account lockout counter after' is set to '15 or more minute(s)'."
  impact 1.0
  describe security_policy do
    its('ResetLockoutCount') { should cmp >= 15 }
  end
end

# 10. Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
control 'win2016-ensure-access-credential-manager-trusted-caller' do
  title "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
  desc "Verify that 'Access Credential Manager as a trusted caller' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should be_empty }
  end
end

# 11. Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users'
control 'win2016-ensure-access-computer-from-network' do
  title "Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users'"
  desc "Verify that 'Access this computer from the network' is set to 'Administrators, Authenticated Users'."
  impact 1.0
  describe security_policy do
    its('SeNetworkLogonRight') { should match_array ['S-1-5-32-544', 'S-1-5-11'] }
  end
end

# 12. Ensure 'Act as part of the operating system' is set to 'No One'
control 'win2016-ensure-act-as-part-of-os' do
  title "Ensure 'Act as part of the operating system' is set to 'No One'"
  desc "Verify that 'Act as part of the operating system' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeTcbPrivilege') { should be_empty }
  end
end

# 13. Ensure 'Add workstations to domain' is set to 'Administrators'
control 'win2016-ensure-add-workstations-to-domain' do
  title "Ensure 'Add workstations to domain' is set to 'Administrators'"
  desc "Verify that 'Add workstations to domain' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeMachineAccountPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 14. Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
control 'win2016-ensure-adjust-memory-quotas' do
  title "Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
  desc "Verify that 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeIncreaseQuotaPrivilege') { should match_array ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20'] }
  end
end

# 15. Ensure 'Allow log on locally' is set to 'Administrators'
control 'win2016-ensure-allow-log-on-locally' do
  title "Ensure 'Allow log on locally' is set to 'Administrators'"
  desc "Verify that 'Allow log on locally' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeInteractiveLogonRight') { should match_array ['S-1-5-32-544'] }
  end
end

# 16. Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'
control 'win2016-ensure-allow-log-on-through-rdp' do
  title "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'"
  desc "Verify that 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'."
  impact 1.0
  describe security_policy do
    its('SeRemoteInteractiveLogonRight') { should match_array ['S-1-5-32-544', 'S-1-5-32-555'] }
  end
end

# 17. Ensure 'Back up files and directories' is set to 'Administrators'
control 'win2016-ensure-backup-files-and-directories' do
  title "Ensure 'Back up files and directories' is set to 'Administrators'"
  desc "Verify that 'Back up files and directories' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeBackupPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 18. Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
control 'win2016-ensure-change-system-time' do
  title "Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
  desc "Verify that 'Change the system time' is set to 'Administrators, LOCAL SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeSystemTimePrivilege') { should match_array ['S-1-5-32-544', 'S-1-5-19'] }
  end
end

# 19. Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
control 'win2016-ensure-change-time-zone' do
  title "Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
  desc "Verify that 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeTimeZonePrivilege') { should match_array ['S-1-5-32-544', 'S-1-5-19'] }
  end
end

# 20. Ensure 'Create a pagefile' is set to 'Administrators'
control 'win2016-ensure-create-pagefile' do
  title "Ensure 'Create a pagefile' is set to 'Administrators'"
  desc "Verify that 'Create a pagefile' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeCreatePagefilePrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 21. Ensure 'Create a token object' is set to 'No One'
control 'win2016-ensure-create-token-object' do
  title "Ensure 'Create a token object' is set to 'No One'"
  desc "Verify that 'Create a token object' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeCreateTokenPrivilege') { should be_empty }
  end
end

# 22. Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
control 'win2016-ensure-create-global-objects' do
  title "Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
  desc "Verify that 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeCreateGlobalPrivilege') { should match_array ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20', 'S-1-5-6'] }
  end
end

# 23. Ensure 'Create permanent shared objects' is set to 'No One'
control 'win2016-ensure-create-permanent-shared-objects' do
  title "Ensure 'Create permanent shared objects' is set to 'No One'"
  desc "Verify that 'Create permanent shared objects' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeCreatePermanentPrivilege') { should be_empty }
  end
end

# 24. Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'
control 'win2016-ensure-create-symbolic-links' do
  title "Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'"
  desc "Verify that 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'."
  impact 1.0
  describe security_policy do
    its('SeCreateSymbolicLinkPrivilege') { should match_array ['S-1-5-32-544', 'S-1-5-83-0'] }
  end
end

# 25. Ensure 'Debug programs' is set to 'Administrators'
control 'win2016-ensure-debug-programs' do
  title "Ensure 'Debug programs' is set to 'Administrators'"
  desc "Verify that 'Debug programs' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeDebugPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 26. Ensure 'Deny access to this computer from the network' is set to 'Guests'
control 'win2016-ensure-deny-access-computer-from-network' do
  title "Ensure 'Deny access to this computer from the network' is set to 'Guests'"
  desc "Verify that 'Deny access to this computer from the network' is set to 'Guests'."
  impact 1.0
  describe security_policy do
    its('SeDenyNetworkLogonRight') { should match_array ['S-1-5-32-546'] }
  end
end

# 27. Ensure 'Deny log on as a batch job' to include 'Guests'
control 'win2016-ensure-deny-log-on-batch-job' do
  title "Ensure 'Deny log on as a batch job' to include 'Guests'"
  desc "Verify that 'Deny log on as a batch job' to include 'Guests'."
  impact 1.0
  describe security_policy do
    its('SeDenyBatchLogonRight') { should include 'S-1-5-32-546' }
  end
end

# 28. Ensure 'Deny log on as a service' to include 'Guests'
control 'win2016-ensure-deny-log-on-service' do
  title "Ensure 'Deny log on as a service' to include 'Guests'"
  desc "Verify that 'Deny log on as a service' to include 'Guests'."
  impact 1.0
  describe security_policy do
    its('SeDenyServiceLogonRight') { should include 'S-1-5-32-546' }
  end
end

# 29. Ensure 'Deny log on locally' to include 'Guests'
control 'win2016-ensure-deny-log-on-locally' do
  title "Ensure 'Deny log on locally' to include 'Guests'"
  desc "Verify that 'Deny log on locally' to include 'Guests'."
  impact 1.0
  describe security_policy do
    its('SeDenyInteractiveLogonRight') { should include 'S-1-5-32-546' }
  end
end

# 30. Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests'
control 'win2016-ensure-deny-log-on-through-rdp' do
  title "Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests'"
  desc "Verify that 'Deny log on through Remote Desktop Services' is set to 'Guests'."
  impact 1.0
  describe security_policy do
    its('SeDenyRemoteInteractiveLogonRight') { should match_array ['S-1-5-32-546'] }
  end
end

# 31. Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators'
control 'win2016-ensure-enable-trusted-delegation-admins' do
  title "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators'"
  desc "Verify that 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeEnableDelegationPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 32. Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'
control 'win2016-ensure-enable-trusted-delegation-no-one' do
  title "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"
  desc "Verify that 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeEnableDelegationPrivilege') { should be_empty }
  end
end

# 33. Ensure 'Force shutdown from a remote system' is set to 'Administrators'
control 'win2016-ensure-force-shutdown-remote-system' do
  title "Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
  desc "Verify that 'Force shutdown from a remote system' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeRemoteShutdownPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 34. Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
control 'win2016-ensure-generate-security-audits' do
  title "Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
  desc "Verify that 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeAuditPrivilege') { should match_array ['S-1-5-19', 'S-1-5-20'] }
  end
end

# 35. Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
control 'win2016-ensure-impersonate-client-authentication' do
  title "Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
  desc "Verify that 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeImpersonatePrivilege') { should match_array ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20', 'S-1-5-6'] }
  end
end

# 36. Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS'
control 'win2016-ensure-impersonate-client-authentication-iis' do
  title "Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and 'IIS_IUSRS'"
  desc "Verify that 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and 'IIS_IUSRS' when the Web Server (IIS) Role with Web Services Role Service is installed."
  impact 1.0
  describe security_policy do
    its('SeImpersonatePrivilege') { should match_array ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20', 'S-1-5-6', 'S-1-5-32-568'] }
  end
end

# 37. Ensure 'Increase scheduling priority' is set to 'Administrators'
control 'win2016-ensure-increase-scheduling-priority' do
  title "Ensure 'Increase scheduling priority' is set to 'Administrators'"
  desc "Verify that 'Increase scheduling priority' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeIncreaseBasePriorityPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 38. Ensure 'Load and unload device drivers' is set to 'Administrators'
control 'win2016-ensure-load-unload-device-drivers' do
  title "Ensure 'Load and unload device drivers' is set to 'Administrators'"
  desc "Verify that 'Load and unload device drivers' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeLoadDriverPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 39. Ensure 'Lock pages in memory' is set to 'No One'
control 'win2016-ensure-lock-pages-in-memory' do
  title "Ensure 'Lock pages in memory' is set to 'No One'"
  desc "Verify that 'Lock pages in memory' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeLockMemoryPrivilege') { should be_empty }
  end
end

# 40. Ensure 'Log on as a batch job' is set to 'Administrators'
control 'win2016-ensure-log-on-batch-job' do
  title "Ensure 'Log on as a batch job' is set to 'Administrators'"
  desc "Verify that 'Log on as a batch job' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeBatchLogonRight') { should match_array ['S-1-5-32-544'] }
  end
end

# 41. Ensure 'Manage auditing and security log' is set to 'Administrators'
control 'win2016-ensure-manage-auditing-security-log' do
  title "Ensure 'Manage auditing and security log' is set to 'Administrators'"
  desc "Verify that 'Manage auditing and security log' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeSecurityPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 42. Ensure 'Modify an object label' is set to 'No One'
control 'win2016-ensure-modify-object-label' do
  title "Ensure 'Modify an object label' is set to 'No One'"
  desc "Verify that 'Modify an object label' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeRelabelPrivilege') { should be_empty }
  end
end

# 43. Ensure 'Modify firmware environment values' is set to 'Administrators'
control 'win2016-ensure-modify-firmware-environment-values' do
  title "Ensure 'Modify firmware environment values' is set to 'Administrators'"
  desc "Verify that 'Modify firmware environment values' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeSystemEnvironmentPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 44. Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
control 'win2016-ensure-perform-volume-maintenance-tasks' do
  title "Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
  desc "Verify that 'Perform volume maintenance tasks' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeManageVolumePrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 45. Ensure 'Profile single process' is set to 'Administrators'
control 'win2016-ensure-profile-single-process' do
  title "Ensure 'Profile single process' is set to 'Administrators'"
  desc "Verify that 'Profile single process' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeProfileSingleProcessPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 46. Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
control 'win2016-ensure-profile-system-performance' do
  title "Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\\WdiServiceHost'"
  desc "Verify that 'Profile system performance' is set to 'Administrators, NT SERVICE\\WdiServiceHost'."
  impact 1.0
  describe security_policy do
    its('SeSystemProfilePrivilege') { should match_array ['S-1-5-32-544', 'S-1-5-80-574'] }
  end
end

# 47. Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
control 'win2016-ensure-replace-process-level-token' do
  title "Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
  desc "Verify that 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeAssignPrimaryTokenPrivilege') { should match_array ['S-1-5-19', 'S-1-5-20'] }
  end
end

# 48. Ensure 'Restore files and directories' is set to 'Administrators'
control 'win2016-ensure-restore-files-directories' do
  title "Ensure 'Restore files and directories' is set to 'Administrators'"
  desc "Verify that 'Restore files and directories' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeRestorePrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 49. Ensure 'Shut down the system' is set to 'Administrators'
control 'win2016-ensure-shut-down-system' do
  title "Ensure 'Shut down the system' is set to 'Administrators'"
  desc "Verify that 'Shut down the system' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeShutdownPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 50. Ensure 'Synchronize directory service data' is set to 'No One'
control 'win2016-ensure-synchronize-directory-service-data' do
  title "Ensure 'Synchronize directory service data' is set to 'No One'"
  desc "Verify that 'Synchronize directory service data' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeSyncAgentPrivilege') { should be_empty }
  end
end

# 51. Ensure 'Take ownership of files or other objects' is set to 'Administrators'
control 'win2016-ensure-take-ownership-files-objects' do
  title "Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
  desc "Verify that 'Take ownership of files or other objects' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeTakeOwnershipPrivilege') { should match_array ['S-1-5-32-544'] }
  end
end

# 52. Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
control 'win2016-ensure-block-microsoft-accounts' do
  title "Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"
  desc "Verify that 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('NoConnectedUser') { should cmp 3 }
  end
end

# 53. Ensure 'Accounts: Guest account status' is set to 'Disabled'
control 'win2016-ensure-guest-account-status-disabled' do
  title "Ensure 'Accounts: Guest account status' is set to 'Disabled'"
  desc "Verify that 'Accounts: Guest account status' is set to 'Disabled'."
  impact 1.0
  describe user('Guest') do
    it { should_not exist }
  end
end

# 54. Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
control 'win2016-ensure-limit-local-account-blank-passwords' do
  title "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
  desc "Verify that 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('LimitBlankPasswordUse') { should cmp 1 }
  end
end

# 55. Configure 'Accounts: Rename administrator account'
control 'win2016-configure-rename-administrator-account' do
  title "Configure 'Accounts: Rename administrator account'"
  desc "Verify that 'Accounts: Rename administrator account' is configured."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('AdministratorAccountName') { should_not cmp 'Administrator' }
  end
end

# 56. Configure 'Accounts: Rename guest account'
control 'win2016-configure-rename-guest-account' do
  title "Configure 'Accounts: Rename guest account'"
  desc "Verify that 'Accounts: Rename guest account' is configured."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('GuestAccountName') { should_not cmp 'Guest' }
  end
end

# 57. Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
control 'win2016-ensure-force-audit-policy-subcategory-settings' do
  title "Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'"
  desc "Verify that 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('SCENoApplyLegacyAuditPolicy') { should cmp 1 }
  end
end

# 58. Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
control 'win2016-ensure-shut-down-system-unable-log-audits' do
  title "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"
  desc "Verify that 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('CrashOnAuditFail') { should cmp 0 }
  end
end

# 59. Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
control 'win2016-ensure-format-eject-removable-media' do
  title "Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'"
  desc "Verify that 'Devices: Allowed to format and eject removable media' is set to 'Administrators'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('NoMediaFormatting') { should cmp 1 }
  end
end

# 60. Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
control 'win2016-ensure-prevent-installing-printer-drivers' do
  title "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'"
  desc "Verify that 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('NoPrinterDrivers') { should cmp 1 }
  end
end

# 61. Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled'
control 'win2016-ensure-allow-server-operators-schedule-tasks' do
  title "Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled'"
  desc "Verify that 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('SubmitControl') { should cmp 0 }
  end
end

# 62. Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing'
control 'win2016-ensure-ldap-server-signing-requirements' do
  title "Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing'"
  desc "Verify that 'Domain controller: LDAP server signing requirements' is set to 'Require signing'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters') do
    its('LDAPServerIntegrity') { should cmp 2 }
  end
end

# 63. Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled'
control 'win2016-ensure-refuse-machine-account-password-changes' do
  title "Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled'"
  desc "Verify that 'Domain controller: Refuse machine account password changes' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('RefusePasswordChange') { should cmp 0 }
  end
end

# 64. Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
control 'win2016-ensure-secure-channel-data-encrypt-sign-always' do
  title "Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'"
  desc "Verify that 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('RequireSignOrSeal') { should cmp 1 }
  end
end

# 65. Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
control 'win2016-ensure-secure-channel-data-encrypt-when-possible' do
  title "Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'"
  desc "Verify that 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('SealSecureChannel') { should cmp 1 }
  end
end

# 66. Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
control 'win2016-ensure-secure-channel-data-sign-when-possible' do
  title "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'"
  desc "Verify that 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('SignSecureChannel') { should cmp 1 }
  end
end

# 67. Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
control 'win2016-ensure-disable-machine-account-password-changes' do
  title "Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'"
  desc "Verify that 'Domain member: Disable machine account password changes' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('DisablePasswordChange') { should cmp 0 }
  end
end

# 68. Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
control 'win2016-ensure-max-machine-account-password-age' do
  title "Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'"
  desc "Verify that 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('MaximumPasswordAge') { should cmp <= 30 }
    its('MaximumPasswordAge') { should cmp > 0 }
  end
end

# 69. Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
control 'win2016-ensure-require-strong-session-key' do
  title "Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'"
  desc "Verify that 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('RequireStrongKey') { should cmp 1 }
  end
end

# 70. Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
control 'win2016-ensure-do-not-display-last-user-name' do
  title "Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'"
  desc "Verify that 'Interactive logon: Do not display last user name' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('DontDisplayLastUserName') { should cmp 1 }
  end
end

# 71. Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
control 'win2016-ensure-do-not-require-ctrl-alt-del' do
  title "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'"
  desc "Verify that 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('DisableCAD') { should cmp 0 }
  end
end

# 72. Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
control 'win2016-ensure-machine-inactivity-limit' do
  title "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'"
  desc "Verify that 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('InactivityTimeoutSecs') { should cmp <= 900 }
    its('InactivityTimeoutSecs') { should cmp > 0 }
  end
end

# 73. Configure 'Interactive logon: Message text for users attempting to log on'
control 'win2016-configure-message-text-logon' do
  title "Configure 'Interactive logon: Message text for users attempting to log on'"
  desc "Verify that 'Interactive logon: Message text for users attempting to log on' is configured."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('LegalNoticeText') { should_not cmp '' }
  end
end

# 74. Configure 'Interactive logon: Message title for users attempting to log on'
control 'win2016-configure-message-title-logon' do
  title "Configure 'Interactive logon: Message title for users attempting to log on'"
  desc "Verify that 'Interactive logon: Message title for users attempting to log on' is configured."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('LegalNoticeCaption') { should_not cmp '' }
  end
end

# 75. Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '0 or fewer logon(s)'
control 'win2016-ensure-previous-logons-cache' do
  title "Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '0 or fewer logon(s)'"
  desc "Verify that 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '0 or fewer logon(s)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('CachedLogonsCount') { should cmp <= 0 }
  end
end

# 76. Ensure 'Interactive logon: Prompt user to change password before expiration' is set to '14 days'
control 'win2016-ensure-prompt-change-password-before-expiration' do
  title "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to '14 days'"
  desc "Verify that 'Interactive logon: Prompt user to change password before expiration' is set to '14 days'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('PasswordExpiryWarning') { should cmp 14 }
  end
end

# 77. Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'
control 'win2016-ensure-require-dc-authentication-unlock-workstation' do
  title "Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'"
  desc "Verify that 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('ForceUnlockLogon') { should cmp 1 }
  end
end

# 78. Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation'
control 'win2016-ensure-smart-card-removal-behavior' do
  title "Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation'"
  desc "Verify that 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('ScRemoveOption') { should cmp 1 }
  end
end

# 79. Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
control 'win2016-ensure-network-client-sign-communications-always' do
  title "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
  desc "Verify that 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    its('EnableSecuritySignature') { should cmp 1 }
  end
end

# 80. Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
control 'win2016-ensure-network-client-sign-communications-if-server-agrees' do
  title "Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'"
  desc "Verify that 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    its('RequireSecuritySignature') { should cmp 1 }
  end
end

# 81. Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
control 'win2016-ensure-send-unencrypted-password-disabled' do
  title "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
  desc "Verify that 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    its('EnablePlainTextPassword') { should cmp 0 }
  end
end

# 82. Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'
control 'win2016-ensure-idle-time-before-suspending-session' do
  title "Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'"
  desc "Verify that 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('IdleTimeout') { should cmp <= 15 }
    its('IdleTimeout') { should cmp > 0 }
  end
end

# 83. Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
control 'win2016-ensure-network-server-sign-communications-always' do
  title "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
  desc "Verify that 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('EnableSecuritySignature') { should cmp 1 }
  end
end

# 84. Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
control 'win2016-ensure-network-server-sign-communications-if-client-agrees' do
  title "Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
  desc "Verify that 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('RequireSecuritySignature') { should cmp 1 }
  end
end

# 85. Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
control 'win2016-ensure-disconnect-clients-logon-hours-expire' do
  title "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'"
  desc "Verify that 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('EnableForcedLogoff') { should cmp 1 }
  end
end

# 86. Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher
control 'win2016-ensure-server-spn-target-name-validation-level' do
  title "Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher"
  desc "Verify that 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('SmbServerNameHardeningLevel') { should cmp >= 1 }
  end
end

# 87. Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
control 'win2016-ensure-allow-anonymous-sid-name-translation-disabled' do
  title "Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'"
  desc "Verify that 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('AllowAnonymousNameLookup') { should cmp 0 }
  end
end

# 88. Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'
control 'win2016-ensure-do-not-allow-anonymous-enumeration-sam-accounts' do
  title "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'"
  desc "Verify that 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('RestrictAnonymousSAM') { should cmp 1 }
  end
end

# 89. Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
control 'win2016-ensure-do-not-allow-anonymous-enumeration-sam-accounts-shares' do
  title "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'"
  desc "Verify that 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('RestrictAnonymous') { should cmp 1 }
  end
end

# 90. Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
control 'win2016-ensure-do-not-allow-storage-passwords-credentials' do
  title "Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'"
  desc "Verify that 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('DisableDomainCreds') { should cmp 1 }
  end
end

# 91. Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
control 'win2016-ensure-let-everyone-permissions-anonymous-users-disabled' do
  title "Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'"
  desc "Verify that 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('EveryoneIncludesAnonymous') { should cmp 0 }
  end
end

# 92. Configure 'Network access: Named Pipes that can be accessed anonymously'
control 'win2016-configure-named-pipes-anonymous-access' do
  title "Configure 'Network access: Named Pipes that can be accessed anonymously'"
  desc "Verify that 'Network access: Named Pipes that can be accessed anonymously' is configured."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('NullSessionPipes') { should_not cmp '' }
  end
end

# 93. Configure 'Network access: Remotely accessible registry paths'
control 'win2016-configure-remotely-accessible-registry-paths' do
  title "Configure 'Network access: Remotely accessible registry paths'"
  desc "Verify that 'Network access: Remotely accessible registry paths' is configured."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg') do
    its('AllowedPaths') { should_not cmp '' }
  end
end

# 94. Configure 'Network access: Remotely accessible registry paths and sub-paths'
control 'win2016-configure-remotely-accessible-registry-paths-sub-paths' do
  title "Configure 'Network access: Remotely accessible registry paths and sub-paths'"
  desc "Verify that 'Network access: Remotely accessible registry paths and sub-paths' is configured."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg') do
    its('AllowedPaths') { should_not cmp '' }
  end
end

# 95. Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
control 'win2016-ensure-restrict-anonymous-access-named-pipes-shares' do
  title "Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"
  desc "Verify that 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('RestrictNullSessAccess') { should cmp 1 }
  end
end

# 96. Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'
control 'win2016-ensure-restrict-clients-remote-calls-sam' do
  title "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
  desc "Verify that 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('RestrictRemoteSAM') { should cmp 1 }
  end
end

# 97. Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
control 'win2016-ensure-shares-accessed-anonymously-none' do
  title "Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"
  desc "Verify that 'Network access: Shares that can be accessed anonymously' is set to 'None'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('NullSessionShares') { should cmp '' }
  end
end

# 98. Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
control 'win2016-ensure-sharing-security-model-local-accounts' do
  title "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'"
  desc "Verify that 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('ForceGuest') { should cmp 0 }
  end
end

# 99. Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
control 'win2016-ensure-allow-local-system-computer-identity-ntlm' do
  title "Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
  desc "Verify that 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('UseMachineId') { should cmp 1 }
  end
end

# 100. Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
control 'win2016-ensure-allow-localsystem-null-session-fallback-disabled' do
  title "Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
  desc "Verify that 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('DisableNullSessionFallback') { should cmp 1 }
  end
end

# 101. Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
control 'win2016-ensure-allow-pku2u-authentication-disabled' do
  title "Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'"
  desc "Verify that 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u') do
    its('AllowOnlineID') { should cmp 0 }
  end
end

# 102. Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
control 'win2016-ensure-do-not-store-lan-manager-hash' do
  title "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"
  desc "Verify that 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('NoLMHash') { should cmp 1 }
  end
end

# 103. Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'
control 'win2016-ensure-force-logoff-logon-hours-expire' do
  title "Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'"
  desc "Verify that 'Network security: Force logoff when logon hours expire' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('ForceLogoffWhenHourExpire') { should cmp 1 }
  end
end

# 104. Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
control 'win2016-ensure-lan-manager-authentication-level' do
  title "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'"
  desc "Verify that 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('LmCompatibilityLevel') { should cmp 5 }
  end
end

# 105. Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
control 'win2016-ensure-ldap-client-signing-requirements' do
  title "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher"
  desc "Verify that 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP') do
    its('LDAPClientIntegrity') { should cmp >= 1 }
  end
end

# 106. Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
control 'win2016-ensure-minimum-session-security-ntlm-clients' do
  title "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
  desc "Verify that 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('NTLMMinClientSec') { should cmp 0x20080000 }
  end
end

# 107. Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
control 'win2016-ensure-minimum-session-security-ntlm-servers' do
  title "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
  desc "Verify that 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('NTLMMinServerSec') { should cmp 0x20080000 }
  end
end

# 108. Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
control 'win2016-ensure-shutdown-without-logon-disabled' do
  title "Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'"
  desc "Verify that 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('ShutdownWithoutLogon') { should cmp 0 }
  end
end

# 109. Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
control 'win2016-ensure-case-insensitivity-non-windows-subsystems' do
  title "Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'"
  desc "Verify that 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager') do
    its('ObCaseInsensitive') { should cmp 1 }
  end
end

# 110. Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
control 'win2016-ensure-strengthen-default-permissions-internal-system-objects' do
  title "Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'"
  desc "Verify that 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager') do
    its('ProtectionMode') { should cmp 1 }
  end
end

# 111. Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
control 'win2016-ensure-uac-elevation-prompt-standard-users-deny' do
  title "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
  desc "Verify that 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('ConsentPromptBehaviorUser') { should cmp 0 }
  end
end

# 112. Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
control 'win2016-ensure-uac-detect-app-installations-prompt-elevation' do
  title "Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
  desc "Verify that 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('EnableInstallerDetection') { should cmp 1 }
  end
end

# 113. Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'
control 'win2016-ensure-uac-elevate-uiaccess-secure-locations' do
  title "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
  desc "Verify that 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('EnableSecureUIAPaths') { should cmp 1 }
  end
end

# 114. Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
control 'win2016-ensure-uac-switch-secure-desktop-prompt-elevation' do
  title "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"
  desc "Verify that 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('PromptOnSecureDesktop') { should cmp 1 }
  end
end

# 115. Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
control 'win2016-ensure-uac-virtualize-file-registry-write-failures' do
  title "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
  desc "Verify that 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('EnableVirtualization') { should cmp 1 }
  end
end

# 116. Ensure 'Audit Credential Validation' is set to 'Success and Failure'
control 'win2016-ensure-audit-credential-validation' do
  title "Ensure 'Audit Credential Validation' is set to 'Success and Failure'"
  desc "Verify that 'Audit Credential Validation' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Credential Validation') { should eq 'Success and Failure' }
  end
end

# 117. Ensure 'Audit Application Group Management' is set to 'Success and Failure'
control 'win2016-ensure-audit-application-group-management' do
  title "Ensure 'Audit Application Group Management' is set to 'Success and Failure'"
  desc "Verify that 'Audit Application Group Management' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Application Group Management') { should eq 'Success and Failure' }
  end
end

# 118. Ensure 'Audit Computer Account Management' is set to 'Success and Failure'
control 'win2016-ensure-audit-computer-account-management' do
  title "Ensure 'Audit Computer Account Management' is set to 'Success and Failure'"
  desc "Verify that 'Audit Computer Account Management' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Computer Account Management') { should eq 'Success and Failure' }
  end
end

# 119. Ensure 'Audit Distribution Group Management' is set to 'Success and Failure'
control 'win2016-ensure-audit-distribution-group-management' do
  title "Ensure 'Audit Distribution Group Management' is set to 'Success and Failure'"
  desc "Verify that 'Audit Distribution Group Management' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Distribution Group Management') { should eq 'Success and Failure' }
  end
end

# 120. Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'
control 'win2016-ensure-audit-other-account-management-events' do
  title "Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'"
  desc "Verify that 'Audit Other Account Management Events' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Other Account Management Events') { should eq 'Success and Failure' }
  end
end

# 121. Ensure 'Audit Security Group Management' is set to 'Success and Failure'
control 'win2016-ensure-audit-security-group-management' do
  title "Ensure 'Audit Security Group Management' is set to 'Success and Failure'"
  desc "Verify that 'Audit Security Group Management' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Security Group Management') { should eq 'Success and Failure' }
  end
end

# 122. Ensure 'Audit User Account Management' is set to 'Success and Failure'
control 'win2016-ensure-audit-user-account-management' do
  title "Ensure 'Audit User Account Management' is set to 'Success and Failure'"
  desc "Verify that 'Audit User Account Management' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('User Account Management') { should eq 'Success and Failure' }
  end
end

# 123. Ensure 'Audit PNP Activity' is set to 'Success'
control 'win2016-ensure-audit-pnp-activity' do
  title "Ensure 'Audit PNP Activity' is set to 'Success'"
  desc "Verify that 'Audit PNP Activity' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its('PNP Activity') { should eq 'Success' }
  end
end

# 124. Ensure 'Audit Process Creation' is set to 'Success'
control 'win2016-ensure-audit-process-creation' do
  title "Ensure 'Audit Process Creation' is set to 'Success'"
  desc "Verify that 'Audit Process Creation' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its('Process Creation') { should eq 'Success' }
  end
end

# 125. Ensure 'Audit Directory Service Access' is set to 'Success and Failure'
control 'win2016-ensure-audit-directory-service-access' do
  title "Ensure 'Audit Directory Service Access' is set to 'Success and Failure'"
  desc "Verify that 'Audit Directory Service Access' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Directory Service Access') { should eq 'Success and Failure' }
  end
end

# 126. Ensure 'Audit Directory Service Changes' is set to 'Success and Failure'
control 'win2016-ensure-audit-directory-service-changes' do
  title "Ensure 'Audit Directory Service Changes' is set to 'Success and Failure'"
  desc "Verify that 'Audit Directory Service Changes' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Directory Service Changes') { should eq 'Success and Failure' }
  end
end

# 127. Ensure 'Audit Account Lockout' is set to 'Success and Failure'
control 'win2016-ensure-audit-account-lockout' do
  title "Ensure 'Audit Account Lockout' is set to 'Success and Failure'"
  desc "Verify that 'Audit Account Lockout' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Account Lockout') { should eq 'Success and Failure' }
  end
end

# 128. Ensure 'Audit Group Membership' is set to 'Success'
control 'win2016-ensure-audit-group-membership' do
  title "Ensure 'Audit Group Membership' is set to 'Success'"
  desc "Verify that 'Audit Group Membership' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its('Group Membership') { should eq 'Success' }
  end
end

# 129. Ensure 'Audit Logoff' is set to 'Success'
control 'win2016-ensure-audit-logoff' do
  title "Ensure 'Audit Logoff' is set to 'Success'"
  desc "Verify that 'Audit Logoff' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its('Logoff') { should eq 'Success' }
  end
end

# 130. Ensure 'Audit Logon' is set to 'Success and Failure'
control 'win2016-ensure-audit-logon' do
  title "Ensure 'Audit Logon' is set to 'Success and Failure'"
  desc "Verify that 'Audit Logon' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Logon') { should eq 'Success and Failure' }
  end
end

# 131. Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
control 'win2016-ensure-audit-other-logon-logoff-events' do
  title "Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"
  desc "Verify that 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Other Logon/Logoff Events') { should eq 'Success and Failure' }
  end
end

# 132. Ensure 'Audit Special Logon' is set to 'Success'
control 'win2016-ensure-audit-special-logon' do
  title "Ensure 'Audit Special Logon' is set to 'Success'"
  desc "Verify that 'Audit Special Logon' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its('Special Logon') { should eq 'Success' }
  end
end

# 133. Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'
control 'win2016-ensure-audit-other-object-access-events' do
  title "Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'"
  desc "Verify that 'Audit Other Object Access Events' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Other Object Access Events') { should eq 'Success and Failure' }
  end
end

# 134. Ensure 'Audit Removable Storage' is set to 'Success and Failure'
control 'win2016-ensure-audit-removable-storage' do
  title "Ensure 'Audit Removable Storage' is set to 'Success and Failure'"
  desc "Verify that 'Audit Removable Storage' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Removable Storage') { should eq 'Success and Failure' }
  end
end

# 135. Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'
control 'win2016-ensure-audit-policy-change' do
  title "Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'"
  desc "Verify that 'Audit Audit Policy Change' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Audit Policy Change') { should eq 'Success and Failure' }
  end
end

# 136. Ensure 'Audit Authentication Policy Change' is set to 'Success'
control 'win2016-ensure-audit-authentication-policy-change' do
  title "Ensure 'Audit Authentication Policy Change' is set to 'Success'"
  desc "Verify that 'Audit Authentication Policy Change' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its('Authentication Policy Change') { should eq 'Success' }
  end
end

# 137. Ensure 'Audit Authorization Policy Change' is set to 'Success'
control 'win2016-ensure-audit-authorization-policy-change' do
  title "Ensure 'Audit Authorization Policy Change' is set to 'Success'"
  desc "Verify that 'Audit Authorization Policy Change' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its('Authorization Policy Change') { should eq 'Success' }
  end
end

# 138. Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
control 'win2016-ensure-audit-sensitive-privilege-use' do
  title "Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'"
  desc "Verify that 'Audit Sensitive Privilege Use' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Sensitive Privilege Use') { should eq 'Success and Failure' }
  end
end

# 139. Ensure 'Audit IPsec Driver' is set to 'Success and Failure'
control 'win2016-ensure-audit-ipsec-driver' do
  title "Ensure 'Audit IPsec Driver' is set to 'Success and Failure'"
  desc "Verify that 'Audit IPsec Driver' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('IPsec Driver') { should eq 'Success and Failure' }
  end
end

# 140. Ensure 'Audit Other System Events' is set to 'Success and Failure'
control 'win2016-ensure-audit-other-system-events' do
  title "Ensure 'Audit Other System Events' is set to 'Success and Failure'"
  desc "Verify that 'Audit Other System Events' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Other System Events') { should eq 'Success and Failure' }
  end
end

# 141. Ensure 'Audit Security State Change' is set to 'Success'
control 'win2016-ensure-audit-security-state-change' do
  title "Ensure 'Audit Security State Change' is set to 'Success'"
  desc "Verify that 'Audit Security State Change' is set to 'Success'."
  impact 1.0
  describe audit_policy do
    its('Security State Change') { should eq 'Success' }
  end
end

# 142. Ensure 'Audit Security System Extension' is set to 'Success and Failure'
control 'win2016-ensure-audit-security-system-extension' do
  title "Ensure 'Audit Security System Extension' is set to 'Success and Failure'"
  desc "Verify that 'Audit Security System Extension' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Security System Extension') { should eq 'Success and Failure' }
  end
end

# 143. Ensure 'Audit System Integrity' is set to 'Success and Failure'
control 'win2016-ensure-audit-system-integrity' do
  title "Ensure 'Audit System Integrity' is set to 'Success and Failure'"
  desc "Verify that 'Audit System Integrity' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('System Integrity') { should eq 'Success and Failure' }
  end
end

# 144. Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'
control 'win2016-ensure-prevent-lock-screen-camera' do
  title "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
  desc "Verify that 'Prevent enabling lock screen camera' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization') do
    its('NoLockScreenCamera') { should cmp 1 }
  end
end

# 145. Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
control 'win2016-ensure-prevent-lock-screen-slide-show' do
  title "Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
  desc "Verify that 'Prevent enabling lock screen slide show' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization') do
    its('NoLockScreenSlideShow') { should cmp 1 }
  end
end

# 146. Ensure 'Allow input personalization' is set to 'Disabled'
control 'win2016-ensure-allow-input-personalization' do
  title "Ensure 'Allow input personalization' is set to 'Disabled'"
  desc "Verify that 'Allow input personalization' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization') do
    its('AllowInputPersonalization') { should cmp 0 }
  end
end

# 147. Ensure 'Allow Online Tips' is set to 'Disabled'
control 'win2016-ensure-allow-online-tips' do
  title "Ensure 'Allow Online Tips' is set to 'Disabled'"
  desc "Verify that 'Allow Online Tips' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableSoftLanding') { should cmp 1 }
  end
end

# 148. Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'
control 'win2016-ensure-apply-uac-restrictions-local-accounts' do
  title "Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'"
  desc "Verify that 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('LocalAccountTokenFilterPolicy') { should cmp 0 }
  end
end

# 149. Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'
control 'win2016-ensure-configure-smb-v1-client-driver' do
  title "Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'"
  desc "Verify that 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MRxSmb10') do
    its('Start') { should cmp 4 }
  end
end

# 150. Ensure 'Configure SMB v1 server' is set to 'Disabled'
control 'win2016-ensure-configure-smb-v1-server' do
  title "Ensure 'Configure SMB v1 server' is set to 'Disabled'"
  desc "Verify that 'Configure SMB v1 server' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('SMB1') { should cmp 0 }
  end
end

# 151. Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'
control 'win2016-ensure-enable-sehop' do
  title "Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
  desc "Verify that 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\kernel') do
    its('DisableExceptionChainValidation') { should cmp 0 }
  end
end

# 152. Ensure 'WDigest Authentication' is set to 'Disabled'
control 'win2016-ensure-wdigest-authentication-disabled' do
  title "Ensure 'WDigest Authentication' is set to 'Disabled'"
  desc "Verify that 'WDigest Authentication' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest') do
    its('UseLogonCredential') { should cmp 0 }
  end
end

# 153. Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
control 'win2016-ensure-auto-admin-logon-disabled' do
  title "Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'"
  desc "Verify that 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon') do
    its('AutoAdminLogon') { should cmp 0 }
  end
end

# 154. Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
control 'win2016-ensure-disable-ip-source-routing-ipv6' do
  title "Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
  desc "Verify that 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters') do
    its('DisableIPSourceRouting') { should cmp 2 }
  end
end

# 155. Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
control 'win2016-ensure-disable-ip-source-routing' do
  title "Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
  desc "Verify that 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    its('DisableIPSourceRouting') { should cmp 2 }
  end
end

# 156. Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'
control 'win2016-ensure-enable-icmp-redirect-disabled' do
  title "Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
  desc "Verify that 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    its('EnableICMPRedirect') { should cmp 0 }
  end
end

# 157. Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'
control 'win2016-ensure-keep-alive-time' do
  title "Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'"
  desc "Verify that 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    its('KeepAliveTime') { should cmp 300000 }
  end
end

# 158. Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'
control 'win2016-ensure-no-name-release-on-demand' do
  title "Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
  desc "Verify that 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters') do
    its('NoNameReleaseOnDemand') { should cmp 1 }
  end
end

# 159. Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'
control 'win2016-ensure-perform-router-discovery-disabled' do
  title "Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'"
  desc "Verify that 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    its('PerformRouterDiscovery') { should cmp 0 }
  end
end

# 160. Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'
control 'win2016-ensure-safe-dll-search-mode' do
  title "Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'"
  desc "Verify that 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager') do
    its('SafeDllSearchMode') { should cmp 1 }
  end
end

# 161. Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'
control 'win2016-ensure-screensaver-grace-period' do
  title "Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'"
  desc "Verify that 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('ScreenSaverGracePeriod') { should cmp <= 5 }
  end
end

# 162. Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
control 'win2016-ensure-tcp-max-data-retransmissions-ipv6' do
  title "Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
  desc "Verify that 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters') do
    its('TcpMaxDataRetransmissions') { should cmp 3 }
  end
end

# 163. Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
control 'win2016-ensure-tcp-max-data-retransmissions' do
  title "Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
  desc "Verify that 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    its('TcpMaxDataRetransmissions') { should cmp 3 }
  end
end

# 164. Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'
control 'win2016-ensure-warning-level-security-event-log' do
  title "Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"
  desc "Verify that 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EventLog\Security') do
    its('WarningLevel') { should cmp <= 90 }
  end
end

# 165. Set 'NetBIOS node type' to 'P-node' (Ensure NetBT Parameter 'NodeType' is set to '0x2 (2)')
control 'win2016-ensure-netbios-node-type-p-node' do
  title "Set 'NetBIOS node type' to 'P-node'"
  desc "Ensure NetBT Parameter 'NodeType' is set to '0x2 (2)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters') do
    its('NodeType') { should cmp 0x2 }
  end
end

# 166. Ensure 'Turn off multicast name resolution' is set to 'Enabled'
control 'win2016-ensure-turn-off-multicast-name-resolution' do
  title "Ensure 'Turn off multicast name resolution' is set to 'Enabled'"
  desc "Verify that 'Turn off multicast name resolution' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD') do
    its('EnableMulticast') { should cmp 0 }
  end
end

# 167. Ensure 'Enable Font Providers' is set to 'Disabled'
control 'win2016-ensure-enable-font-providers-disabled' do
  title "Ensure 'Enable Font Providers' is set to 'Disabled'"
  desc "Verify that 'Enable Font Providers' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('EnableFontProviders') { should cmp 0 }
  end
end

# 168. Ensure 'Enable insecure guest logons' is set to 'Disabled'
control 'win2016-ensure-enable-insecure-guest-logons-disabled' do
  title "Ensure 'Enable insecure guest logons' is set to 'Disabled'"
  desc "Verify that 'Enable insecure guest logons' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation') do
    its('AllowInsecureGuestAuth') { should cmp 0 }
  end
end

# 169. Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'
control 'win2016-ensure-turn-on-mapper-io-driver-disabled' do
  title "Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'"
  desc "Verify that 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LLTDIO') do
    its('Start') { should cmp 4 }
  end
end

# 170. Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'
control 'win2016-ensure-turn-on-responder-driver-disabled' do
  title "Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'"
  desc "Verify that 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\RSPNDR') do
    its('Start') { should cmp 4 }
  end
end

# 171. Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'
control 'win2016-ensure-turn-off-peer-to-peer-networking-services' do
  title "Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'"
  desc "Verify that 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections') do
    its('NC_AllowNetBridge_NLA') { should cmp 0 }
  end
end

# 172. Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
control 'win2016-ensure-prohibit-network-bridge-dns-domain' do
  title "Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
  desc "Verify that 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections') do
    its('NC_AllowNetBridge_NLA') { should cmp 0 }
  end
end

# 173. Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
control 'win2016-prohibit-internet-connection-sharing' do
  title "Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
  desc "Verify that 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections') do
    its('NC_AllowICS_NLA') { should cmp 0 }
  end
end

# 174. Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'
control 'win2016-require-domain-users-elevate-network-location' do
  title "Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'"
  desc "Verify that 'Require domain users to elevate when setting a network's location' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections') do
    its('NC_StdDomainUserSetLocation') { should cmp 1 }
  end
end

# 175. Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'
control 'win2016-hardened-unc-paths' do
  title "Ensure 'Hardened UNC Paths' is set to 'Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares'"
  desc "Verify that 'Hardened UNC Paths' is set to 'Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths') do
    its('\\\\*\\NETLOGON') { should match /RequireMutualAuthentication=1, RequireIntegrity=1/ }
    its('\\\\*\\SYSVOL') { should match /RequireMutualAuthentication=1, RequireIntegrity=1/ }
  end
end

# 176. Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')
control 'win2016-disable-ipv6' do
  title "Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')"
  desc "Verify that TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\TCPIP6\Parameters') do
    its('DisabledComponents') { should cmp 0xff }
  end
end

# 177. Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'
control 'win2016-disable-wireless-settings-connect-now' do
  title "Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
  desc "Verify that 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Registrar') do
    its('DisableWcnConfigRegistrar') { should cmp 1 }
  end
end

# 178. Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'
control 'win2016-prohibit-windows-connect-now-wizards' do
  title "Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'"
  desc "Verify that 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Registrar') do
    its('DisableWcnWizard') { should cmp 1 }
  end
end

# 179. Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
control 'win2016-minimize-simultaneous-connections' do
  title "Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'"
  desc "Verify that 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy') do
    its('fMinimizeConnections') { should cmp 1 }
  end
end

# 180. Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'
control 'win2016-prohibit-non-domain-networks' do
  title "Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'"
  desc "Verify that 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy') do
    its('fBlockNonDomain') { should cmp 1 }
  end
end

# 181. Ensure 'Include command line in process creation events' is set to 'Enabled'
control 'win2016-include-command-line-process-events' do
  title "Ensure 'Include command line in process creation events' is set to 'Enabled'"
  desc "Verify that 'Include command line in process creation events' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit') do
    its('ProcessCreationIncludeCmdLine_Enabled') { should cmp 1 }
  end
end

# 182. Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'
control 'win2016-remote-host-delegation-non-exportable-credentials' do
  title "Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'"
  desc "Verify that 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredSSP\Parameters') do
    its('AllowNonExportable') { should cmp 1 }
  end
end

# 183. Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
control 'win2016-boot-start-driver-policy' do
  title "Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
  desc "Verify that 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies\EarlyLaunch') do
    its('DriverLoadPolicy') { should cmp 3 }
  end
end

# 184. Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
control 'win2016-configure-registry-policy-processing-background-false' do
  title "Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"
  desc "Verify that 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DisableBkGndGroupPolicy') { should cmp 0 }
  end
end

# 185. Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
control 'win2016-configure-registry-policy-processing-always' do
  title "Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
  desc "Verify that 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('GroupPolicyRefreshTime') { should cmp 1 }
  end
end

# 186. Ensure 'Continue experiences on this device' is set to 'Disabled'
control 'win2016-continue-experiences-disabled' do
  title "Ensure 'Continue experiences on this device' is set to 'Disabled'"
  desc "Verify that 'Continue experiences on this device' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('EnableCdp') { should cmp 0 }
  end
end

# 187. Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'
control 'win2016-turn-off-background-refresh-disabled' do
  title "Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'"
  desc "Verify that 'Turn off background refresh of Group Policy' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DisableBkGndGroupPolicy') { should cmp 0 }
  end
end

# 188. Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
control 'win2016-turn-off-download-print-drivers-http' do
  title "Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'"
  desc "Verify that 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers') do
    its('DisableHTTPPrinting') { should cmp 1 }
  end
end

# 189. Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
control 'win2016-turn-off-handwriting-data-sharing' do
  title "Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'"
  desc "Verify that 'Turn off handwriting personalization data sharing' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HandwritingErrorReports') do
    its('Enabled') { should cmp 0 }
  end
end

# 190. Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
control 'win2016-turn-off-handwriting-error-reporting' do
  title "Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'"
  desc "Verify that 'Turn off handwriting recognition error reporting' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HandwritingErrorReports') do
    its('Enabled') { should cmp 0 }
  end
end

# 191. Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
control 'win2016-turn-off-internet-connection-wizard' do
  title "Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'"
  desc "Verify that 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Internet Connection Wizard') do
    its('DisableICW') { should cmp 1 }
  end
end

# 192. Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
control 'win2016-turn-off-internet-download-wizards' do
  title "Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'"
  desc "Verify that 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoPublishingWizard') { should cmp 1 }
  end
end

# 193. Ensure 'Turn off printing over HTTP' is set to 'Enabled'
control 'win2016-turn-off-printing-http' do
  title "Ensure 'Turn off printing over HTTP' is set to 'Enabled'"
  desc "Verify that 'Turn off printing over HTTP' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers') do
    its('DisableHTTPPrinting') { should cmp 1 }
  end
end

# 194. Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
control 'win2016-turn-off-registration-microsoft' do
  title "Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'"
  desc "Verify that 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Registration Wizard Control') do
    its('NoRegistration') { should cmp 1 }
  end
end

# 195. Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
control 'win2016-turn-off-search-companion-updates' do
  title "Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'"
  desc "Verify that 'Turn off Search Companion content file updates' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SearchCompanion') do
    its('DisableContentFileUpdates') { should cmp 1 }
  end
end

# 196. Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
control 'win2016-turn-off-order-prints-task' do
  title "Ensure 'Turn off the \"Order Prints\" picture task' is set to 'Enabled'"
  desc "Verify that 'Turn off the \"Order Prints\" picture task' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoOnlinePrintsWizard') { should cmp 1 }
  end
end

# 197. Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
control 'win2016-turn-off-publish-to-web-task' do
  title "Ensure 'Turn off the \"Publish to Web\" task for files and folders' is set to 'Enabled'"
  desc "Verify that 'Turn off the \"Publish to Web\" task for files and folders' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoPublishingWizard') { should cmp 1 }
  end
end

# 198. Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
control 'win2016-turn-off-messenger-ceip' do
  title "Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'"
  desc "Verify that 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger\CEIP') do
    its('CEIP') { should cmp 0 }
  end
end

# 199. Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
control 'win2016-turn-off-windows-ceip' do
  title "Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'"
  desc "Verify that 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SQMClient') do
    its('CEIPEnable') { should cmp 0 }
  end
end

# 200. Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
control 'win2016-turn-off-error-reporting' do
  title "Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'"
  desc "Verify that 'Turn off Windows Error Reporting' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Error Reporting') do
    its('Disabled') { should cmp 1 }
  end
end

# 201. Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'
control 'win2016-support-device-authentication-certificate' do
  title "Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'"
  desc "Verify that 'Support device authentication using certificate' is set to 'Enabled: Automatic'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceAuthentication') do
    its('EnableDeviceAuth') { should cmp 2 }
  end
end

# 202. Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'
control 'win2016-disallow-copying-input-methods' do
  title "Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'"
  desc "Verify that 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Control Panel\International') do
    its('BlockUserInputMethodsForSystem') { should cmp 1 }
  end
end

# 203. Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'
control 'win2016-block-account-details-sign-in' do
  title "Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'"
  desc "Verify that 'Block user from showing account details on sign-in' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('BlockUserAccountDetails') { should cmp 1 }
  end
end

# 204. Ensure 'Do not display network selection UI' is set to 'Enabled'
control 'win2016-do-not-display-network-selection-ui' do
  title "Ensure 'Do not display network selection UI' is set to 'Enabled'"
  desc "Verify that 'Do not display network selection UI' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DontDisplayNetworkSelectionUI') { should cmp 1 }
  end
end

# 205. Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'
control 'win2016-do-not-enumerate-connected-users' do
  title "Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'"
  desc "Verify that 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DontEnumerateConnectedUsers') { should cmp 1 }
  end
end

# 206. Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'
control 'win2016-enumerate-local-users-disabled' do
  title "Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'"
  desc "Verify that 'Enumerate local users on domain-joined computers' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('EnumerateLocalUsers') { should cmp 0 }
  end
end

# 207. Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'
control 'win2016-turn-off-app-notifications-lock-screen' do
  title "Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'"
  desc "Verify that 'Turn off app notifications on the lock screen' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications') do
    its('NoToastApplicationNotificationOnLockScreen') { should cmp 1 }
  end
end

# 208. Ensure 'Turn off picture password sign-in' is set to 'Enabled'
control 'win2016-turn-off-picture-password-sign-in' do
  title "Ensure 'Turn off picture password sign-in' is set to 'Enabled'"
  desc "Verify that 'Turn off picture password sign-in' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('BlockPicturePassword') { should cmp 1 }
  end
end

# 209. Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
control 'win2016-turn-on-convenience-pin-disabled' do
  title "Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'"
  desc "Verify that 'Turn on convenience PIN sign-in' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('AllowConvenienceLogon') { should cmp 0 }
  end
end

# 210. Ensure 'Untrusted Font Blocking' is set to 'Enabled: Block untrusted fonts and log events'
control 'win2016-untrusted-font-blocking' do
  title "Ensure 'Untrusted Font Blocking' is set to 'Enabled: Block untrusted fonts and log events'"
  desc "Verify that 'Untrusted Font Blocking' is set to 'Enabled: Block untrusted fonts and log events'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\MitigationOptions') do
    its('MitigationOptions_Font') { should cmp 0x1000000000000 }
  end
end

# 211. Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'
control 'win2016-allow-network-connectivity-standby-battery-disabled' do
  title "Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'"
  desc "Verify that 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\Power') do
    its('AllowConnectedStandbyOnBattery') { should cmp 0 }
  end
end

# 212. Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'
control 'win2016-allow-network-connectivity-standby-plugged-disabled' do
  title "Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'"
  desc "Verify that 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\Power') do
    its('AllowConnectedStandbyPluggedIn') { should cmp 0 }
  end
end

# 213. Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'
control 'win2016-require-password-wake-battery-enabled' do
  title "Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'"
  desc "Verify that 'Require a password when a computer wakes (on battery)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\Power') do
    its('PromptPasswordOnWakeOnBattery') { should cmp 1 }
  end
end

# 214. Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'
control 'win2016-require-password-wake-plugged-enabled' do
  title "Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'"
  desc "Verify that 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\Power') do
    its('PromptPasswordOnWakePluggedIn') { should cmp 1 }
  end
end

# 215. Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
control 'win2016-configure-offer-remote-assistance-disabled' do
  title "Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
  desc "Verify that 'Configure Offer Remote Assistance' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fAllowUnsolicited') { should cmp 0 }
  end
end

# 216. Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
control 'win2016-configure-solicited-remote-assistance-disabled' do
  title "Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
  desc "Verify that 'Configure Solicited Remote Assistance' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fAllowToGetHelp') { should cmp 0 }
  end
end

# 217. Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'
control 'win2016-enable-rpc-endpoint-mapper-authentication' do
  title "Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'"
  desc "Verify that 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('EnableAuthEpMapper') { should cmp 1 }
  end
end

# 218. Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'
control 'win2016-restrict-unauthenticated-rpc-clients' do
  title "Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'"
  desc "Verify that 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('RestrictRemoteClients') { should cmp 1 }
  end
end

# 219. Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'
control 'win2016-turn-off-msdt-interactive-communication' do
  title "Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'"
  desc "Verify that 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy') do
    its('EnableUserCommunication') { should cmp 0 }
  end
end

# 220. Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'
control 'win2016-disable-perftrack' do
  title "Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'"
  desc "Verify that 'Enable/Disable PerfTrack' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WDI') do
    its('DisableWdi') { should cmp 1 }
  end
end

# 221. Ensure 'Turn off the advertising ID' is set to 'Enabled'
control 'win2016-turn-off-advertising-id' do
  title "Ensure 'Turn off the advertising ID' is set to 'Enabled'"
  desc "Verify that 'Turn off the advertising ID' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AdvertisingInfo') do
    its('Disabled') { should cmp 1 }
  end
end

# 222. Ensure 'Enable Windows NTP Client' is set to 'Enabled'
control 'win2016-enable-windows-ntp-client' do
  title "Ensure 'Enable Windows NTP Client' is set to 'Enabled'"
  desc "Verify that 'Enable Windows NTP Client' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\W32Time\Parameters') do
    its('NtpClientEnabled') { should cmp 1 }
  end
end

# 223. Ensure 'Enable Windows NTP Server' is set to 'Disabled'
control 'win2016-disable-windows-ntp-server' do
  title "Ensure 'Enable Windows NTP Server' is set to 'Disabled'"
  desc "Verify that 'Enable Windows NTP Server' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\W32Time\Parameters') do
    its('NtpServerEnabled') { should cmp 0 }
  end
end

# 224. Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'
control 'win2016-disable-app-data-sharing-between-users' do
  title "Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'"
  desc "Verify that 'Allow a Windows app to share application data between users' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy') do
    its('SharedUserAppData') { should cmp 0 }
  end
end

# 225. Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
control 'win2016-allow-microsoft-accounts-optional' do
  title "Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
  desc "Verify that 'Allow Microsoft accounts to be optional' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('AllowMicrosoftAccountSignIn') { should cmp 1 }
  end
end

# 226. Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
control 'win2016-disallow-autoplay-non-volume-devices' do
  title "Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
  desc "Verify that 'Disallow Autoplay for non-volume devices' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoAutoplayNonVolume') { should cmp 1 }
  end
end

# 227. Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
control 'win2016-set-default-behavior-autorun' do
  title "Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'"
  desc "Verify that 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoAutorun') { should cmp 1 }
  end
end

# 228. Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
control 'win2016-turn-off-autoplay-all-drives' do
  title "Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'"
  desc "Verify that 'Turn off Autoplay' is set to 'Enabled: All drives'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoDriveTypeAutoRun') { should cmp 255 }
  end
end

# 229. Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'
control 'win2016-configure-enhanced-anti-spoofing' do
  title "Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'"
  desc "Verify that 'Configure enhanced anti-spoofing' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Biometrics') do
    its('EnhancedAntiSpoofing') { should cmp 1 }
  end
end

# 230. Ensure 'Allow Use of Camera' is set to 'Disabled'
control 'win2016-allow-use-of-camera-disabled' do
  title "Ensure 'Allow Use of Camera' is set to 'Disabled'"
  desc "Verify that 'Allow Use of Camera' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Camera') do
    its('AllowCamera') { should cmp 0 }
  end
end

# 231. Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'
control 'win2016-turn-off-microsoft-consumer-experiences' do
  title "Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
  desc "Verify that 'Turn off Microsoft consumer experiences' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableWindowsConsumerFeatures') { should cmp 1 }
  end
end

# 232. Ensure 'Require pin for pairing' is set to 'Enabled'
control 'win2016-require-pin-for-pairing' do
  title "Ensure 'Require pin for pairing' is set to 'Enabled'"
  desc "Verify that 'Require pin for pairing' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DevicePairing') do
    its('RequirePinForPairing') { should cmp 1 }
  end
end

# 233. Ensure 'Do not display the password reveal button' is set to 'Enabled'
control 'win2016-do-not-display-password-reveal-button' do
  title "Ensure 'Do not display the password reveal button' is set to 'Enabled'"
  desc "Verify that 'Do not display the password reveal button' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI') do
    its('DisablePasswordReveal') { should cmp 1 }
  end
end

# 234. Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
control 'win2016-enumerate-admin-accounts-elevation-disabled' do
  title "Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
  desc "Verify that 'Enumerate administrator accounts on elevation' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('EnumerateAdministrators') { should cmp 0 }
  end
end

# 235. Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'
control 'win2016-allow-telemetry' do
  title "Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'"
  desc "Verify that 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection') do
    its('AllowTelemetry') { should cmp <= 1 }
  end
end

# 236. Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'
control 'win2016-configure-authenticated-proxy-telemetry' do
  title "Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'"
  desc "Verify that 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection') do
    its('DisableAuthProxy') { should cmp 1 }
  end
end

# 237. Ensure 'Disable pre-release features or settings' is set to 'Disabled'
control 'win2016-disable-pre-release-features-disabled' do
  title "Ensure 'Disable pre-release features or settings' is set to 'Disabled'"
  desc "Verify that 'Disable pre-release features or settings' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PreviewBuilds') do
    its('EnablePreviewBuilds') { should cmp 0 }
  end
end

# 238. Ensure 'Do not show feedback notifications' is set to 'Enabled'
control 'win2016-do-not-show-feedback-notifications' do
  title "Ensure 'Do not show feedback notifications' is set to 'Enabled'"
  desc "Verify that 'Do not show feedback notifications' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\FeedbackNotifications') do
    its('Disabled') { should cmp 1 }
  end
end

# 239. Ensure 'Toggle user control over Insider builds' is set to 'Disabled'
control 'win2016-toggle-user-control-insider-builds-disabled' do
  title "Ensure 'Toggle user control over Insider builds' is set to 'Disabled'"
  desc "Verify that 'Toggle user control over Insider builds' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PreviewBuilds') do
    its('AllowBuildPreview') { should cmp 0 }
  end
end

# 240. Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
control 'win2016-application-control-event-log-disabled' do
  title "Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc "Verify that 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application') do
    its('Retention') { should cmp 0 }
  end
end

# 241. Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
control 'win2016-application-max-log-file-size' do
  title "Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc "Verify that 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application') do
    its('MaxSize') { should cmp >= 32768 }
  end
end

# 242. Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
control 'win2016-security-control-event-log-disabled' do
  title "Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc "Verify that 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security') do
    its('Retention') { should cmp 0 }
  end
end

# 243. Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
control 'win2016-security-max-log-file-size' do
  title "Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'"
  desc "Verify that 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security') do
    its('MaxSize') { should cmp >= 196608 }
  end
end

# 244. Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
control 'win2016-setup-control-event-log-disabled' do
  title "Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc "Verify that 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup') do
    its('Retention') { should cmp 0 }
  end
end

# 245. Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
control 'win2016-setup-max-log-file-size' do
  title "Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc "Verify that 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup') do
    its('MaxSize') { should cmp >= 32768 }
  end
end

# 246. Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
control 'win2016-system-control-event-log-disabled' do
  title "Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc "Verify that 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System') do
    its('Retention') { should cmp 0 }
  end
end

# 247. Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
control 'win2016-system-max-log-file-size' do
  title "Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc "Verify that 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System') do
    its('MaxSize') { should cmp >= 32768 }
  end
end

# 248. Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
control 'win2016-turn-off-dep-explorer-disabled' do
  title "Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"
  desc "Verify that 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoDataExecutionPrevention') { should cmp 0 }
  end
end

# 249. Ensure 'Turn off heap termination on corruption' is set to 'Disabled'
control 'win2016-turn-off-heap-termination-disabled' do
  title "Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"
  desc "Verify that 'Turn off heap termination on corruption' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoHeapTerminationOnCorruption') { should cmp 0 }
  end
end

# 250. Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'
control 'win2016-turn-off-shell-protocol-protected-mode-disabled' do
  title "Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'"
  desc "Verify that 'Turn off shell protocol protected mode' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoShellProtocolProtectedMode') { should cmp 0 }
  end
end

# 251. Ensure 'Turn off location' is set to 'Enabled'
control 'win2016-turn-off-location-enabled' do
  title "Ensure 'Turn off location' is set to 'Enabled'"
  desc "Verify that 'Turn off location' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors') do
    its('DisableLocation') { should cmp 1 }
  end
end

# 252. Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'
control 'win2016-allow-message-service-cloud-sync-disabled' do
  title "Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'"
  desc "Verify that 'Allow Message Service Cloud Sync' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Messaging') do
    its('AllowCloudSync') { should cmp 0 }
  end
end

# 253. Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'
control 'win2016-block-consumer-microsoft-account-authentication' do
  title "Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'"
  desc "Verify that 'Block all consumer Microsoft account user authentication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('BlockMicrosoftAccount') { should cmp 1 }
  end
end

# 254. Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'
control 'win2016-prevent-onedrive-file-storage' do
  title "Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'"
  desc "Verify that 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\OneDrive') do
    its('DisableFileSync') { should cmp 1 }
  end
end

# 255. Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
control 'win2016-do-not-allow-passwords-saved' do
  title "Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
  desc "Verify that 'Do not allow passwords to be saved' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI') do
    its('DisablePasswordSaving') { should cmp 1 }
  end
end

# 256. Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'
control 'win2016-restrict-rds-single-session' do
  title "Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'"
  desc "Verify that 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fSingleSessionPerUser') { should cmp 1 }
  end
end

# 257. Ensure 'Do not allow COM port redirection' is set to 'Enabled'
control 'win2016-do-not-allow-com-port-redirection' do
  title "Ensure 'Do not allow COM port redirection' is set to 'Enabled'"
  desc "Verify that 'Do not allow COM port redirection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('DisableComPortRedirection') { should cmp 1 }
  end
end

# 258. Ensure 'Do not allow drive redirection' is set to 'Enabled'
control 'win2016-do-not-allow-drive-redirection' do
  title "Ensure 'Do not allow drive redirection' is set to 'Enabled'"
  desc "Verify that 'Do not allow drive redirection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('DisableDriveRedirection') { should cmp 1 }
  end
end

# 259. Ensure 'Do not allow LPT port redirection' is set to 'Enabled'
control 'win2016-do-not-allow-lpt-port-redirection' do
  title "Ensure 'Do not allow LPT port redirection' is set to 'Enabled'"
  desc "Verify that 'Do not allow LPT port redirection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('DisableLPTPortRedirection') { should cmp 1 }
  end
end

# 260. Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'
control 'win2016-do-not-allow-pnp-device-redirection' do
  title "Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'"
  desc "Verify that 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('DisablePnPRedirection') { should cmp 1 }
  end
end

# 261. Ensure 'Require secure RPC communication' is set to 'Enabled'
control 'win2016-require-secure-rpc-communication' do
  title "Ensure 'Require secure RPC communication' is set to 'Enabled'"
  desc "Verify that 'Require secure RPC communication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('EnableSecureRpc') { should cmp 1 }
  end
end

# 262. Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
control 'win2016-set-client-connection-encryption-high' do
  title "Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
  desc "Verify that 'Set client connection encryption level' is set to 'Enabled: High Level'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('MinEncryptionLevel') { should cmp 3 }
  end
end

# 263. Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'
control 'win2016-set-time-limit-idle-rds-sessions' do
  title "Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'"
  desc "Verify that 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('MaxIdleTime') { should cmp <= 900000 }
  end
end

# 264. Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
control 'win2016-do-not-delete-temp-folders-disabled' do
  title "Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'"
  desc "Verify that 'Do not delete temp folders upon exit' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TempFolders') do
    its('DoNotDeleteTempFolders') { should cmp 0 }
  end
end

# 265. Ensure 'Do not use temporary folders per session' is set to 'Disabled'
control 'win2016-do-not-use-temp-folders-per-session-disabled' do
  title "Ensure 'Do not use temporary folders per session' is set to 'Disabled'"
  desc "Verify that 'Do not use temporary folders per session' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TempFolders') do
    its('DoNotUseTempFoldersPerSession') { should cmp 0 }
  end
end

# 266. Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
control 'win2016-prevent-downloading-enclosures-enabled' do
  title "Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"
  desc "Verify that 'Prevent downloading of enclosures' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Enclosures') do
    its('PreventDownloading') { should cmp 1 }
  end
end

# 267. Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'
control 'win2016-allow-cloud-search-disabled' do
  title "Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'"
  desc "Verify that 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudSearch') do
    its('DisableCloudSearch') { should cmp 1 }
  end
end

# 268. Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
control 'win2016-allow-indexing-encrypted-files-disabled' do
  title "Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
  desc "Verify that 'Allow indexing of encrypted files' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Indexing') do
    its('AllowIndexingEncryptedFiles') { should cmp 0 }
  end
end

# 269. Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'
control 'win2016-turn-off-kms-client-avs-validation-enabled' do
  title "Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'"
  desc "Verify that 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\KMSClient') do
    its('DisableAVSValidation') { should cmp 1 }
  end
end

# 270. Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'
control 'win2016-allow-suggested-apps-ink-workspace-disabled' do
  title "Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'"
  desc "Verify that 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\InkWorkspace') do
    its('AllowSuggestedApps') { should cmp 0 }
  end
end

# 271. Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'
control 'win2016-allow-windows-ink-workspace' do
  title "Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'"
  desc "Verify that 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\InkWorkspace') do
    its('AllowWindowsInkWorkspace') { should cmp 1 }
    its('AllowAboveLock') { should cmp 0 }
  end
end

# 272. Ensure 'Allow user control over installs' is set to 'Disabled'
control 'win2016-allow-user-control-installs-disabled' do
  title "Ensure 'Allow user control over installs' is set to 'Disabled'"
  desc "Verify that 'Allow user control over installs' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer') do
    its('AllowUserControlOverInstalls') { should cmp 0 }
  end
end

# 273. Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'
control 'win2016-prevent-ie-security-prompt-installer-disabled' do
  title "Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'"
  desc "Verify that 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer') do
    its('DisableIEInstallerSecurityPrompt') { should cmp 0 }
  end
end

# 274. Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'
control 'win2016-sign-in-last-user-restart-disabled' do
  title "Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'"
  desc "Verify that 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DisableAutomaticRestartSignOn') { should cmp 1 }
  end
end

# 275. Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'
control 'win2016-turn-on-powershell-script-block-logging-enabled' do
  title "Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'"
  desc "Verify that 'Turn on PowerShell Script Block Logging' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging') do
    its('EnableModuleLogging') { should cmp 1 }
  end
end

# 276. Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'
control 'win2016-turn-on-powershell-transcription-disabled' do
  title "Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'"
  desc "Verify that 'Turn on PowerShell Transcription' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Transcription') do
    its('EnableTranscription') { should cmp 0 }
  end
end

# 277. Ensure 'Allow unencrypted traffic' is set to 'Disabled'
control 'win2016-allow-unencrypted-traffic-disabled' do
  title "Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
  desc "Disabling unencrypted traffic ensures secure communication."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM') do
    its('AllowUnencrypted') { should eq 0 }
  end
end

# 278. Ensure 'Disallow Digest authentication' is set to 'Enabled'
control 'win2016-disallow-digest-authentication-enabled' do
  title "Ensure 'Disallow Digest authentication' is set to 'Enabled'"
  desc "Verify that 'Disallow Digest authentication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM') do
    its('DisallowDigest') { should cmp 1 }
  end
end

# 279. Ensure 'Allow Basic authentication' is set to 'Disabled'
control 'win2016-allow-basic-authentication-disabled' do
  title "Ensure 'Allow Basic authentication' is set to 'Disabled'"
  desc "Verify that 'Allow Basic authentication' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM') do
    its('AllowBasic') { should cmp 0 }
  end
end

# 280. Ensure 'Allow remote server management through WinRM' is set to 'Disabled'
control 'win2016-allow-remote-server-management-winrm-disabled' do
  title "Ensure 'Allow remote server management through WinRM' is set to 'Disabled'"
  desc "Verify that 'Allow remote server management through WinRM' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service') do
    its('AllowRemoteServerManagement') { should cmp 0 }
  end
end

# 281. Ensure 'Allow unencrypted traffic' is set to 'Disabled'
control 'win2016-allow-unencrypted-traffic-disabled' do
  title "Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
  desc "Verify that 'Allow unencrypted traffic' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM') do
    its('AllowUnencrypted') { should cmp 0 }
  end
end

# 282. Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
control 'win2016-disallow-winrm-store-runas-credentials-enabled' do
  title "Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"
  desc "Verify that 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service') do
    its('DisableRunAs') { should cmp 1 }
  end
end

# 283. Ensure 'Allow Remote Shell Access' is set to 'Disabled'
control 'win2016-allow-remote-shell-access-disabled' do
  title "Ensure 'Allow Remote Shell Access' is set to 'Disabled'"
  desc "Verify that 'Allow Remote Shell Access' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service') do
    its('AllowRemoteShellAccess') { should cmp 0 }
  end
end

# 284. Ensure 'Manage preview builds' is set to 'Disabled: Disable preview builds'
control 'win2016-manage-preview-builds-disabled' do
  title "Ensure 'Manage preview builds' is set to 'Disabled: Disable preview builds'"
  desc "Verify that 'Manage preview builds' is set to 'Disabled: Disable preview builds'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PreviewBuilds') do
    its('ManagePreviewBuilds') { should cmp 0 }
  end
end

# 285. Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'
control 'win2016-select-preview-builds-feature-updates' do
  title "Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'"
  desc "Verify that 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate') do
    its('DeferFeatureUpdates') { should cmp 1 }
    its('DeferFeatureUpdatesPeriodInDays') { should cmp >= 180 }
  end
end

# 286. Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'
control 'win2016-select-quality-updates-0-days' do
  title "Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'"
  desc "Verify that 'Select when Quality Updates are received' is set to 'Enabled: 0 days'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate') do
    its('DeferQualityUpdates') { should cmp 1 }
    its('DeferQualityUpdatesPeriodInDays') { should cmp 0 }
  end
end

# 287. Ensure 'Configure Automatic Updates' is set to 'Enabled'
control 'win2016-configure-automatic-updates-enabled' do
  title "Ensure 'Configure Automatic Updates' is set to 'Enabled'"
  desc "Verify that 'Configure Automatic Updates' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU') do
    its('NoAutoUpdate') { should cmp 0 }
  end
end

# 288. Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'
control 'win2016-configure-automatic-updates-scheduled-day' do
  title "Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'"
  desc "Verify that 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU') do
    its('ScheduledInstallDay') { should cmp 0 }
  end
end

# 289. Ensure 'Enable screen saver' is set to 'Enabled'
control 'win2016-enable-screen-saver' do
  title "Ensure 'Enable screen saver' is set to 'Enabled'"
  desc "Verify that 'Enable screen saver' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_CURRENT_USER\Control Panel\Desktop') do
    its('ScreenSaveActive') { should cmp '1' }
  end
end

# 290. Ensure 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'
control 'win2016-force-specific-screen-saver' do
  title "Ensure 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'"
  desc "Verify that 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'."
  impact 1.0
  describe registry_key('HKEY_CURRENT_USER\Control Panel\Desktop') do
    its('SCRNSAVE.EXE') { should cmp 'scrnsave.scr' }
  end
end

# 291. Ensure 'Password protect the screen saver' is set to 'Enabled'
control 'win2016-password-protect-screen-saver-enabled' do
  title "Ensure 'Password protect the screen saver' is set to 'Enabled'"
  desc "Verify that 'Password protect the screen saver' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_CURRENT_USER\Control Panel\Desktop') do
    its('ScreenSaverIsSecure') { should cmp '1' }
  end
end

# 292. Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'
control 'win2016-screen-saver-timeout-enabled' do
  title "Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'"
  desc "Verify that 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'."
  impact 1.0
  describe registry_key('HKEY_CURRENT_USER\Control Panel\Desktop') do
    its('ScreenSaveTimeOut') { should cmp <= 900 }
    its('ScreenSaveTimeOut') { should cmp > 0 }
  end
end

# 293. Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'
control 'win2016-turn-off-toast-notifications-lock-screen-enabled' do
  title "Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'"
  desc "Verify that 'Turn off toast notifications on the lock screen' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications') do
    its('NoToastApplicationNotificationOnLockScreen') { should cmp 1 }
  end
end

# 294. Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'
control 'win2016-turn-off-help-experience-improvement-program-enabled' do
  title "Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'"
  desc "Verify that 'Turn off Help Experience Improvement Program' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Assistance\Client\1.0') do
    its('HelpExperienceImprovementProgram') { should cmp 0 }
  end
end

# 295. Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'
control 'win2016-do-not-preserve-zone-information-disabled' do
  title "Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'"
  desc "Verify that 'Do not preserve zone information in file attachments' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments') do
    its('SaveZoneInformation') { should cmp 1 }
  end
end

# 296. Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'
control 'win2016-notify-antivirus-opening-attachments-enabled' do
  title "Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'"
  desc "Verify that 'Notify antivirus programs when opening attachments' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments') do
    its('ScanWithAntiVirus') { should cmp 1 }
  end
end

# 297. Ensure 'Configure Windows spotlight on lock screen' is set to 'Disabled'
control 'win2016-configure-windows-spotlight-lock-screen-disabled' do
  title "Ensure 'Configure Windows spotlight on lock screen' is set to 'Disabled'"
  desc "Verify that 'Configure Windows spotlight on lock screen' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableWindowsSpotlightOnLockScreen') { should cmp 1 }
  end
end

# 298. Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'
control 'win2016-do-not-suggest-third-party-content-enabled' do
  title "Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'"
  desc "Verify that 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableThirdPartySuggestions') { should cmp 1 }
  end
end

# 299. Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'
control 'win2016-do-not-use-diagnostic-data-tailored-experiences-enabled' do
  title "Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'"
  desc "Verify that 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableTailoredExperiencesWithDiagnosticData') { should cmp 1 }
  end
end

# 300. Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'
control 'win2016-turn-off-all-windows-spotlight-features-enabled' do
  title "Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'"
  desc "Verify that 'Turn off all Windows spotlight features' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableWindowsSpotlightFeatures') { should cmp 1 }
  end
end

# 301. Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'
control 'win2016-prevent-users-sharing-files-profile-enabled' do
  title "Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'"
  desc "Verify that 'Prevent users from sharing files within their profile.' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WorkFolders') do
    its('BlockSharing') { should cmp 1 }
  end
end

# 302. Ensure 'Always install with elevated privileges' is set to 'Disabled'
control 'win2016-always-install-elevated-privileges-disabled' do
  title "Ensure 'Always install with elevated privileges' is set to 'Disabled'"
  desc "Verify that 'Always install with elevated privileges' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer') do
    its('AlwaysInstallElevated') { should cmp 0 }
  end
end

# 303. Ensure 'Prevent Codec Download' is set to 'Enabled'
control 'win2016-prevent-codec-download-enabled' do
  title "Ensure 'Prevent Codec Download' is set to 'Enabled'"
  desc "Verify that 'Prevent Codec Download' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\MediaPlayer') do
    its('PreventCodecDownload') { should cmp 1 }
  end
end

# 304. Antivirus software is not installed
control 'win2016-antivirus-software-not-installed' do
  title "Antivirus software is not installed"
  desc "Verify that antivirus software is installed."
  impact 1.0
  describe package('Antivirus Software') do
    it { should be_installed }
  end
end

# 305. Ensure 'Turn off notifications network usage' is set to 'Enabled' (Automated)
control 'win2016-turn-off-notifications-network-usage-enabled' do
  title "Ensure 'Turn off notifications network usage' is set to 'Enabled' (Automated)"
  desc "Verify that 'Turn off notifications network usage' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications') do
    its('TurnOffToastNetworkUsage') { should cmp 1 }
  end
end

# 306. Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'
control 'win2016-require-specific-security-layer-rdp-ssl' do
  title "Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'"
  desc "Verify that 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp') do
    its('SecurityLayer') { should cmp 2 }
  end
end

# 307. Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled' (Automated)
control 'win2016-require-user-authentication-nla-enabled' do
  title "Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled' (Automated)"
  desc "Verify that 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server') do
    its('UserAuthentication') { should cmp 1 }
  end
end

# 308. Ensure 'Audit Detailed File Share' is set to include 'Failure'
control 'win2016-audit-detailed-file-share-failure' do
  title "Ensure 'Audit Detailed File Share' is set to include 'Failure'"
  desc "Verify that 'Audit Detailed File Share' is set to include 'Failure'."
  impact 1.0
  describe audit_policy do
    its(['Detailed File Share']) { should include 'Failure' }
  end
end

# 309. Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure' (Automated)
control 'win2016-audit-mpssvc-rule-policy-change-success-failure' do
  title "Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure' (Automated)"
  desc "Verify that 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['MPSSVC Rule-Level Policy Change']) { should include 'Success' }
    its(['MPSSVC Rule-Level Policy Change']) { should include 'Failure' }
  end
end

# 310. Ensure 'Audit Other Policy Change Events' is set to include 'Failure' (Automated)
control 'win2016-audit-other-policy-change-events-failure' do
  title "Ensure 'Audit Other Policy Change Events' is set to include 'Failure' (Automated)"
  desc "Verify that 'Audit Other Policy Change Events' is set to include 'Failure'."
  impact 1.0
  describe audit_policy do
    its(['Other Policy Change Events']) { should include 'Failure' }
  end
end

# 311. Ensure 'Turn On Virtualization Based Security' is set to 'Enabled' (Automated)
control 'win2016-turn-on-virtualization-based-security-enabled' do
  title "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled' (Automated)"
  desc "Verify that 'Turn On Virtualization Based Security' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard') do
    its('EnableVirtualizationBasedSecurity') { should cmp 1 }
  end
end

# 312. Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection' (Automated)
control 'win2016-turn-on-vbs-platform-security-level' do
  title "Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection' (Automated)"
  desc "Verify that 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard') do
    its('RequirePlatformSecurityFeatures') { should cmp 3 }
  end
end

# 313. Ensure 'Audit File Share' is set to 'Success and Failure'
control 'win2016-audit-file-share-success-failure' do
  title "Ensure 'Audit File Share' is set to 'Success and Failure'"
  desc "Verify that 'Audit File Share' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['File Share']) { should include 'Success' }
    its(['File Share']) { should include 'Failure' }
  end
end

# 314. Ensure 'Audit Credential Validation' is set to 'Success and Failure' (Automated)
control 'win2016-audit-credential-validation-success-failure' do
  title "Ensure 'Audit Credential Validation' is set to 'Success and Failure' (Automated)"
  desc "Verify that 'Audit Credential Validation' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Credential Validation']) { should include 'Success' }
    its(['Credential Validation']) { should include 'Failure' }
  end
end

# 315. Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure' (DC Only) (Automated)
control 'win2016-audit-kerberos-service-ticket-operations-success-failure' do
  title "Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure' (DC Only) (Automated)"
  desc "Verify that 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Kerberos Service Ticket Operations']) { should include 'Success' }
    its(['Kerberos Service Ticket Operations']) { should include 'Failure' }
  end
end

# 316. Ensure 'Scan all downloaded files and attachments' is set to 'Enabled' (Automated)
control 'win2016-scan-downloaded-files-attachments-enabled' do
  title "Ensure 'Scan all downloaded files and attachments' is set to 'Enabled' (Automated)"
  desc "Verify that 'Scan all downloaded files and attachments' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Attachments') do
    its('ScanWithAntiVirus') { should cmp 1 }
  end
end

# 317. Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (MS only) (Automated)
control 'win2016-print-spooler-disabled' do
  title "Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (MS only) (Automated)"
  desc "Verify that 'Print Spooler (Spooler)' is set to 'Disabled'."
  impact 1.0
  describe service('Spooler') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end

# 318. Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt' (Automated)
control 'win2016-point-print-restrictions-warning-elevation-prompt' do
  title "Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt' (Automated)"
  desc "Verify that 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint') do
    its('UpdatePromptSettings') { should cmp 1 }
  end
end

# 319. Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled' (Automated)
control 'win2016-allow-print-spooler-client-connections-disabled' do
  title "Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled' (Automated)"
  desc "Verify that 'Allow Print Spooler to accept client connections' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print') do
    its('EnableClientSpooler') { should cmp 0 }
  end
end

# 320. Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled' (Automated)
control 'win2016-prevent-device-metadata-retrieval-internet-enabled' do
  title "Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled' (Automated)"
  desc "Verify that 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Device Metadata') do
    its('PreventDeviceMetadataFromNetwork') { should cmp 1 }
  end
end

# 321. Ensure 'Limits print driver installation to Administrators' is set to 'Enabled' (Automated)
control 'win2016-limits-print-driver-installation-administrators-enabled' do
  title "Ensure 'Limits print driver installation to Administrators' is set to 'Enabled' (Automated)"
  desc "Verify that 'Limits print driver installation to Administrators' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint') do
    its('RestrictDriverInstallationToAdministrators') { should cmp 1 }
  end
end

# 322. Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher (Automated)
control 'win2016-configure-dns-over-https-allow-doh-enabled' do
  title "Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher (Automated)"
  desc "Verify that 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DNSClient') do
    its('EnableAutoDoh') { should cmp 1 }
  end
end

# 323. Ensure 'Turn off cloud consumer account state content' is set to 'Enabled' (Automated)
control 'win2016-turn-off-cloud-consumer-account-state-content-enabled' do
  title "Ensure 'Turn off cloud consumer account state content' is set to 'Enabled' (Automated)"
  desc "Verify that 'Turn off cloud consumer account state content' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableCloudConsumerAccountStateContent') { should cmp 1 }
  end
end

# 324. Ensure 'Enable OneSettings Auditing' is set to 'Enabled'
control 'win2016-enable-onesettings-auditing-enabled' do
  title "Ensure 'Enable OneSettings Auditing' is set to 'Enabled'"
  desc "Verify that 'Enable OneSettings Auditing' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\OneSettings') do
    its('EnableAuditing') { should cmp 1 }
  end
end

# 325. Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled'
control 'win2016-limit-diagnostic-log-collection-enabled' do
  title "Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled'"
  desc "Verify that 'Limit Diagnostic Log Collection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection') do
    its('LimitDiagnosticLogCollection') { should cmp 1 }
  end
end

# 326. Ensure 'Limit Dump Collection' is set to 'Enabled'
control 'win2016-limit-dump-collection-enabled' do
  title "Ensure 'Limit Dump Collection' is set to 'Enabled'"
  desc "Verify that 'Limit Dump Collection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection') do
    its('LimitDumpCollection') { should cmp 1 }
  end
end

# 327. Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled' (Manual)
control 'win2016-turn-off-spotlight-collection-desktop-enabled' do
  title "Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled' (Manual)"
  desc "Verify that 'Turn off Spotlight collection on Desktop' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableSpotlightCollectionDesktop') { should cmp 1 }
  end
end

# 328. Ensure 'Disable OneSettings Downloads' is set to 'Enabled' (Automated)
control 'win2016-disable-onesettings-downloads-enabled' do
  title "Ensure 'Disable OneSettings Downloads' is set to 'Enabled' (Automated)"
  desc "Verify that 'Disable OneSettings Downloads' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\OneSettings') do
    its('DisableDownloads') { should cmp 1 }
  end
end

# 329. Ensure to turn on Module Logging
control 'win2016-turn-on-module-logging' do
  title "Ensure to turn on Module Logging"
  desc "Verify that Module Logging is turned on."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging') do
    its('EnableModuleLogging') { should cmp 1 }
  end
end

# 330. Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure' (DC Only) (Automated)
control 'win2016-audit-kerberos-authentication-service-success-failure' do
  title "Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure' (DC Only) (Automated)"
  desc "Verify that 'Audit Kerberos Authentication Service' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its(['Kerberos Authentication Service']) { should include 'Success' }
    its(['Kerberos Authentication Service']) { should include 'Failure' }
  end
end

# 331. Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt' (Automated)
control 'win2016-point-print-restrictions-new-connection-warning-elevation-prompt' do
  title "Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt' (Automated)"
  desc "Verify that 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint') do
    its('NewConnectionPromptSettings') { should cmp 1 }
  end
end

# 332. Ensure active User ID's which were not logged in for more than 90 days or never is to be disabled
control 'win2016-disable-inactive-user-ids' do
  title "Ensure active User ID's which were not logged in for more than 90 days or never is to be disabled"
  desc "Verify that active User IDs which were not logged in for more than 90 days or never are disabled."
  impact 1.0
  describe command("Get-ADUser -Filter {LastLogonDate -lt (Get-Date).AddDays(-90)}") do
    its('stdout') { should match /Disabled/ }
  end
end

# 333. Ensure no Users are present in Administrator group except Profiles ID
control 'win2016-no-users-in-administrator-group-except-profiles-id' do
  title "Ensure no Users are present in Administrator group except Profiles ID"
  desc "Verify that no users are present in the Administrator group except Profiles ID."
  impact 1.0
  describe command("Get-LocalGroupMember -Group 'Administrators' | Where-Object { $_.Name -ne 'Profiles ID' }") do
    its('stdout') { should eq '' }
  end
end

# 334. Ensure System Files are not having write permissions to Everyone
control 'win2016-system-files-no-write-permissions-everyone' do
  title "Ensure System Files are not having write permissions to Everyone"
  desc "Verify that System Files do not have write permissions to Everyone."
  impact 1.0
  describe command("icacls 'C:\Windows\System32' | FindStr /C:'Everyone:(F)'") do
    its('stdout') { should eq '' }
  end
end

# 335. Disable Automounting
control 'win2016-disable-automounting' do
  title "Disable Automounting"
  desc "Verify that Automounting is disabled."
  impact 1.0
  describe command("diskpart /s automount disable") do
    its('stdout') { should match /disabled/ }
  end
end

# 336. Disable USB Storage
control 'win2016-disable-usb-storage' do
  title "Disable USB Storage"
  desc "Verify that USB Storage is disabled."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\USBSTOR') do
    its('Start') { should cmp 4 }
  end
end

# 337. Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'
control 'win2016-configure-rpc-packet-level-privacy-enabled' do
  title "Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'"
  desc "Verify that 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('EnablePacketPrivacy') { should cmp 1 }
  end
end

# 338. Ensure 'LSA Protection' is set to 'Enabled'
control 'win2016-lsa-protection-enabled' do
  title "Ensure 'LSA Protection' is set to 'Enabled'"
  desc "Verify that 'LSA Protection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('RunAsPPL') { should cmp 1 }
  end
end

# 339. Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'
control 'win2016-configure-netbios-settings-disable-public-networks' do
  title "Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'"
  desc "Verify that 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters') do
    its('EnableNetbiosOnPublicNetworks') { should cmp 0 }
  end
end

# 340. Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'
control 'win2016-configure-redirection-guard-enabled' do
  title "Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'"
  desc "Verify that 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RedirectionGuard') do
    its('EnableRedirectionGuard') { should cmp 1 }
  end
end

# 341. Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'
control 'win2016-configure-rpc-protocol-outgoing-tcp' do
  title "Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'"
  desc "Verify that 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('ProtocolForOutgoingConnections') { should cmp 'TCP' }
  end
end

# 342. Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'
control 'win2016-configure-rpc-authentication-outgoing-default' do
  title "Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'"
  desc "Verify that 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('UseAuthenticationForOutgoingConnections') { should cmp 'Default' }
  end
end

# 343. Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'
control 'win2016-configure-rpc-protocol-incoming-tcp' do
  title "Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'"
  desc "Verify that 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('ProtocolsForIncomingConnections') { should cmp 'TCP' }
  end
end

# 344. Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher
control 'win2016-configure-rpc-authentication-incoming-negotiate' do
  title "Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher"
  desc "Verify that 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('AuthenticationProtocolForIncomingConnections') { should cmp >= 'Negotiate' }
  end
end

# 345. Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0'
control 'win2016-configure-rpc-tcp-port-0' do
  title "Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0'"
  desc "Verify that 'Configure RPC over TCP port' is set to 'Enabled: 0'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc') do
    its('TcpPort') { should cmp 0 }
  end
end

# 346. Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'
control 'win2016-manage-queue-specific-files-color-profiles' do
  title "Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'"
  desc "Verify that 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\QueueSpecificFiles') do
    its('LimitQueueSpecificFiles') { should cmp 'ColorProfiles' }
  end
end

# 347. Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'
control 'win2016-turn-on-vbs-code-integrity-uefi-lock' do
  title "Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'"
  desc "Verify that 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\VBS') do
    its('CodeIntegrityProtection') { should cmp 'UEFILock' }
  end
end

# 348. Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'
control 'win2016-turn-on-vbs-uefi-memory-attributes-table' do
  title "Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'"
  desc "Verify that 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\VBS') do
    its('RequireUEFIMemoryAttributesTable') { should cmp 1 }
  end
end

# 349. Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock' (MS Only)
control 'win2016-turn-on-vbs-credential-guard-uefi-lock' do
  title "Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock' (MS Only)"
  desc "Verify that 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock' (MS Only)."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\VBS') do
    its('CredentialGuardConfiguration') { should cmp 'UEFILock' }
  end
end

# 350. Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'
control 'win2016-turn-on-vbs-secure-launch-enabled' do
  title "Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'"
  desc "Verify that 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\VBS') do
    its('SecureLaunchConfiguration') { should cmp 1 }
  end
end

# 351. Ensure 'Allow search highlights' is set to 'Disabled'
control 'win2016-allow-search-highlights-disabled' do
  title "Ensure 'Allow search highlights' is set to 'Disabled'"
  desc "Verify that 'Allow search highlights' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Search') do
    its('AllowSearchHighlights') { should cmp 0 }
  end
end

# 352. Ensure 'Allow Administrator account lockout' is set to 'Enabled'
control 'win2016-allow-admin-account-lockout-enabled' do
  title "Ensure 'Allow Administrator account lockout' is set to 'Enabled'"
  desc "Verify that 'Allow Administrator account lockout' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AccountLockout') do
    its('AllowAdminAccountLockout') { should cmp 1 }
  end
end

# 353. Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'
control 'win2016-restrict-ntlm-audit-incoming-all-accounts' do
  title "Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'"
  desc "Verify that 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('AuditIncomingNTLM') { should cmp 'AllAccounts' }
  end
end

# 354. Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher
control 'win2016-restrict-ntlm-outgoing-remote-servers-audit-all' do
  title "Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher"
  desc "Verify that 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('OutgoingNTLMTraffic') { should cmp >= 'AuditAll' }
  end
end

# 355. Ensure 'Enable Certificate Padding' is set to 'Enabled'
control 'win2016-enable-certificate-padding-enabled' do
  title "Ensure 'Enable Certificate Padding' is set to 'Enabled'"
  desc "Verify that 'Enable Certificate Padding' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CertificatePadding') do
    its('EnableCertificatePadding') { should cmp 1 }
  end
end

