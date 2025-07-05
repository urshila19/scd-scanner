# Security controls for Windows Server 2022

# 1. Ensure 'Enforce password history' is set to '5 or more password(s)'
control 'win2022-enforce-password-history' do
  title "Ensure 'Enforce password history' is set to '5 or more password(s)'"
  desc "Verify that 'Enforce password history' is set to '5 or more password(s)'."
  impact 1.0
  describe security_policy do
    its('PasswordHistorySize') { should be >= 5 }
  end
end

# 2. Ensure 'Maximum password age' is set to '45 or fewer days, but not 0'
control 'win2022-maximum-password-age' do
  title "Ensure 'Maximum password age' is set to '45 or fewer days, but not 0'"
  desc "Verify that 'Maximum password age' is set to '45 or fewer days, but not 0'."
  impact 1.0
  describe security_policy do
    its('MaximumPasswordAge') { should be <= 45 }
    its('MaximumPasswordAge') { should_not eq 0 }
  end
end

# 3. Ensure 'Minimum password age' is set to '1 or more day(s)'
control 'win2022-minimum-password-age' do
  title "Ensure 'Minimum password age' is set to '1 or more day(s)'"
  desc "Verify that 'Minimum password age' is set to '1 or more day(s)'."
  impact 1.0
  describe security_policy do
    its('MinimumPasswordAge') { should be >= 1 }
  end
end

# 4. Ensure 'Minimum password length' is set to '8 or more character(s)'
control 'win2022-minimum-password-length' do
  title "Ensure 'Minimum password length' is set to '8 or more character(s)'"
  desc "Verify that 'Minimum password length' is set to '8 or more character(s)'."
  impact 1.0
  describe security_policy do
    its('MinimumPasswordLength') { should be >= 8 }
  end
end

# 5. Ensure 'Password must meet complexity requirements' is set to 'Enabled'
control 'win2022-password-complexity' do
  title "Ensure 'Password must meet complexity requirements' is set to 'Enabled'"
  desc "Verify that 'Password must meet complexity requirements' is set to 'Enabled'."
  impact 1.0
  describe security_policy do
    its('PasswordComplexity') { should eq 1 }
  end
end

# 6. Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
control 'win2022-store-passwords-reversible-encryption' do
  title "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"
  desc "Verify that 'Store passwords using reversible encryption' is set to 'Disabled'."
  impact 1.0
  describe security_policy do
    its('ClearTextPassword') { should eq 0 }
  end
end

# 7. Ensure 'Account lockout duration' is set to '15 or more minute(s)'
control 'win2022-account-lockout-duration' do
  title "Ensure 'Account lockout duration' is set to '15 or more minute(s)'"
  desc "Verify that 'Account lockout duration' is set to '15 or more minute(s)'."
  impact 1.0
  describe security_policy do
    its('LockoutDuration') { should be >= 15 }
  end
end

# 8. Ensure 'Account lockout threshold' is set to '3 or fewer invalid logon attempt(s), but not 0'
control 'win2022-account-lockout-threshold' do
  title "Ensure 'Account lockout threshold' is set to '3 or fewer invalid logon attempt(s), but not 0'"
  desc "Verify that 'Account lockout threshold' is set to '3 or fewer invalid logon attempt(s), but not 0'."
  impact 1.0
  describe security_policy do
    its('LockoutBadCount') { should be <= 3 }
    its('LockoutBadCount') { should_not eq 0 }
  end
end

# 9. Ensure 'Allow Administrator account lockout' is set to 'Enabled' (Manual)
control 'win2022-allow-administrator-account-lockout' do
  title "Ensure 'Allow Administrator account lockout' is set to 'Enabled' (Manual)"
  desc "Verify that 'Allow Administrator account lockout' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AccountLockout') do
    its('EnableAdministratorLockout') { should eq 1 }
  end
end

# 10. Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
control 'win2022-reset-account-lockout-counter' do
  title "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'"
  desc "Verify that 'Reset account lockout counter after' is set to '15 or more minute(s)'."
  impact 1.0
  describe security_policy do
    its('ResetLockoutCount') { should be >= 15 }
  end
end

# 11. Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
control 'win2022-access-credential-manager-trusted-caller' do
  title "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
  desc "Verify that 'Access Credential Manager as a trusted caller' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should be_empty }
  end
end

# 12. Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users' (MS only)
control 'win2022-access-computer-from-network' do
  title "Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users' (MS only)"
  desc "Verify that 'Access this computer from the network' is set to 'Administrators, Authenticated Users'."
  impact 1.0
  describe security_policy do
    its('SeNetworkLogonRight') { should eq ['S-1-5-32-544', 'S-1-5-11'] }
  end
end

# 13. Ensure 'Act as part of the operating system' is set to 'No One'
control 'win2022-act-as-part-of-os' do
  title "Ensure 'Act as part of the operating system' is set to 'No One'"
  desc "Verify that 'Act as part of the operating system' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeTcbPrivilege') { should be_empty }
  end
end

# 14. Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)
control 'win2022-add-workstations-to-domain' do
  title "Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)"
  desc "Verify that 'Add workstations to domain' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeMachineAccountPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 15. Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
control 'win2022-adjust-memory-quotas' do
  title "Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
  desc "Verify that 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeIncreaseQuotaPrivilege') { should eq ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20'] }
  end
end

# 16. Ensure 'Allow log on locally' is set to 'Administrators'
control 'win2022-allow-log-on-locally' do
  title "Ensure 'Allow log on locally' is set to 'Administrators'"
  desc "Verify that 'Allow log on locally' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeInteractiveLogonRight') { should eq ['S-1-5-32-544'] }
  end
end

# 17. Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' (MS only)
control 'win2022-allow-log-on-remote-desktop' do
  title "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' (MS only)"
  desc "Verify that 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'."
  impact 1.0
  describe security_policy do
    its('SeRemoteInteractiveLogonRight') { should eq ['S-1-5-32-544', 'S-1-5-32-555'] }
  end
end

# 18. Ensure 'Back up files and directories' is set to 'Administrators'
control 'win2022-back-up-files-directories' do
  title "Ensure 'Back up files and directories' is set to 'Administrators'"
  desc "Verify that 'Back up files and directories' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeBackupPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 19. Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
control 'win2022-change-system-time' do
  title "Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
  desc "Verify that 'Change the system time' is set to 'Administrators, LOCAL SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeSystemTimePrivilege') { should eq ['S-1-5-32-544', 'S-1-5-19'] }
  end
end

# 20. Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
control 'win2022-change-time-zone' do
  title "Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
  desc "Verify that 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeTimeZonePrivilege') { should eq ['S-1-5-32-544', 'S-1-5-19'] }
  end
end

# 21. Ensure 'Create a pagefile' is set to 'Administrators'
control 'win2022-create-pagefile' do
  title "Ensure 'Create a pagefile' is set to 'Administrators'"
  desc "Verify that 'Create a pagefile' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeCreatePagefilePrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 22. Ensure 'Create a token object' is set to 'No One'
control 'win2022-create-token-object' do
  title "Ensure 'Create a token object' is set to 'No One'"
  desc "Verify that 'Create a token object' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeCreateTokenPrivilege') { should be_empty }
  end
end

# 23. Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
control 'win2022-create-global-objects' do
  title "Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
  desc "Verify that 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeCreateGlobalPrivilege') { should eq ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20', 'S-1-5-6'] }
  end
end

# 24. Ensure 'Create permanent shared objects' is set to 'No One'
control 'win2022-create-permanent-shared-objects' do
  title "Ensure 'Create permanent shared objects' is set to 'No One'"
  desc "Verify that 'Create permanent shared objects' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeCreatePermanentPrivilege') { should be_empty }
  end
end

# 25. Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines' (MS only)
control 'win2022-create-symbolic-links' do
  title "Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines' (MS only)"
  desc "Verify that 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'."
  impact 1.0
  describe security_policy do
    its('SeCreateSymbolicLinkPrivilege') { should eq ['S-1-5-32-544', 'S-1-5-83-0'] }
  end
end

# 26. Ensure 'Debug programs' is set to 'Administrators'
control 'win2022-debug-programs' do
  title "Ensure 'Debug programs' is set to 'Administrators'"
  desc "Verify that 'Debug programs' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeDebugPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 27. Ensure 'Deny access to this computer from the network' to include 'Guests' (DC only)
control 'win2022-deny-access-computer-network' do
  title "Ensure 'Deny access to this computer from the network' to include 'Guests' (DC only)"
  desc "Verify that 'Deny access to this computer from the network' to include 'Guests'."
  impact 1.0
  describe security_policy do
    its('SeDenyNetworkLogonRight') { should include 'S-1-5-32-546' }
  end
end

# 28. Ensure 'Deny log on as a batch job' to include 'Guests'
control 'win2022-deny-log-on-batch-job' do
  title "Ensure 'Deny log on as a batch job' to include 'Guests'"
  desc "Verify that 'Deny log on as a batch job' to include 'Guests'."
  impact 1.0
  describe security_policy do
    its('SeDenyBatchLogonRight') { should include 'S-1-5-32-546' }
  end
end

# 29. Ensure 'Deny log on as a service' to include 'Guests'
control 'win2022-deny-log-on-service' do
  title "Ensure 'Deny log on as a service' to include 'Guests'"
  desc "Verify that 'Deny log on as a service' to include 'Guests'."
  impact 1.0
  describe security_policy do
    its('SeDenyServiceLogonRight') { should include 'S-1-5-32-546' }
  end
end

# 30. Ensure 'Deny log on locally' to include 'Guests'
control 'win2022-deny-log-on-locally' do
  title "Ensure 'Deny log on locally' to include 'Guests'"
  desc "Verify that 'Deny log on locally' to include 'Guests'."
  impact 1.0
  describe security_policy do
    its('SeDenyInteractiveLogonRight') { should include 'S-1-5-32-546' }
  end
end

# 31. Ensure 'Deny log on through Remote Desktop Services' to include 'Guests' (DC only)
control 'win2022-deny-log-on-remote-desktop-guests' do
  title "Ensure 'Deny log on through Remote Desktop Services' to include 'Guests' (DC only)"
  desc "Verify that 'Deny log on through Remote Desktop Services' to include 'Guests'."
  impact 1.0
  describe security_policy do
    its('SeDenyRemoteInteractiveLogonRight') { should include 'S-1-5-32-546' }
  end
end

# 32. Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' (MS only)
control 'win2022-enable-trusted-delegation' do
  title "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' (MS only)"
  desc "Verify that 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeEnableDelegationPrivilege') { should be_empty }
  end
end

# 33. Ensure 'Force shutdown from a remote system' is set to 'Administrators'
control 'win2022-force-shutdown-remote' do
  title "Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
  desc "Verify that 'Force shutdown from a remote system' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeRemoteShutdownPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 34. Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
control 'win2022-generate-security-audits' do
  title "Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
  desc "Verify that 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'."
  impact 1.0
  describe security_policy do
    its('SeAuditPrivilege') { should eq ['S-1-5-19', 'S-1-5-20'] }
  end
end

# 35. Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS' (MS only)
control 'win2022-impersonate-client-authentication' do
  title "Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS' (MS only)"
  desc "Verify that 'Impersonate a client after authentication' is set to the correct groups."
  impact 1.0
  describe security_policy do
    its('SeImpersonatePrivilege') { should eq ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20', 'S-1-5-6', 'S-1-5-17'] }
  end
end

# 36. Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'
control 'win2022-increase-scheduling-priority' do
  title "Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\\Window Manager Group'"
  desc "Verify that 'Increase scheduling priority' is set to the correct groups."
  impact 1.0
  describe security_policy do
    its('SeIncreaseBasePriorityPrivilege') { should eq ['S-1-5-32-544', 'S-1-5-90-0'] }
  end
end

# 37. Ensure 'Load and unload device drivers' is set to 'Administrators'
control 'win2022-load-unload-device-drivers' do
  title "Ensure 'Load and unload device drivers' is set to 'Administrators'"
  desc "Verify that 'Load and unload device drivers' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeLoadDriverPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 38. Ensure 'Lock pages in memory' is set to 'No One'
control 'win2022-lock-pages-memory' do
  title "Ensure 'Lock pages in memory' is set to 'No One'"
  desc "Verify that 'Lock pages in memory' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeLockMemoryPrivilege') { should be_empty }
  end
end

# 39. Ensure 'Log on as a batch job' is set to 'Administrators' (DC Only)
control 'win2022-log-on-batch-job' do
  title "Ensure 'Log on as a batch job' is set to 'Administrators' (DC Only)"
  desc "Verify that 'Log on as a batch job' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeBatchLogonRight') { should eq ['S-1-5-32-544'] }
  end
end

# 40. Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only)
control 'win2022-manage-auditing-security-log' do
  title "Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only)"
  desc "Verify that 'Manage auditing and security log' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeSecurityPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 41. Ensure 'Modify an object label' is set to 'No One'
control 'win2022-modify-object-label' do
  title "Ensure 'Modify an object label' is set to 'No One'"
  desc "Verify that 'Modify an object label' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeRelabelPrivilege') { should be_empty }
  end
end

# 42. Ensure 'Modify firmware environment values' is set to 'Administrators'
control 'win2022-modify-firmware-values' do
  title "Ensure 'Modify firmware environment values' is set to 'Administrators'"
  desc "Verify that 'Modify firmware environment values' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeSystemEnvironmentPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 43. Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
control 'win2022-perform-volume-maintenance' do
  title "Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
  desc "Verify that 'Perform volume maintenance tasks' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeManageVolumePrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 44. Ensure 'Profile single process' is set to 'Administrators'
control 'win2022-profile-single-process' do
  title "Ensure 'Profile single process' is set to 'Administrators'"
  desc "Verify that 'Profile single process' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeProfileSingleProcessPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 45. Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\\WdiServiceHost'
control 'win2022-profile-system-performance' do
  title "Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\\WdiServiceHost'"
  desc "Verify that 'Profile system performance' is set to the correct groups."
  impact 1.0
  describe security_policy do
    its('SeSystemProfilePrivilege') { should eq ['S-1-5-32-544', 'S-1-5-80-574'] }
  end
end

# 46. Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
control 'win2022-replace-process-token' do
  title "Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
  desc "Verify that 'Replace a process level token' is set to the correct groups."
  impact 1.0
  describe security_policy do
    its('SeAssignPrimaryTokenPrivilege') { should eq ['S-1-5-19', 'S-1-5-20'] }
  end
end

# 47. Ensure 'Restore files and directories' is set to 'Administrators'
control 'win2022-restore-files-directories' do
  title "Ensure 'Restore files and directories' is set to 'Administrators'"
  desc "Verify that 'Restore files and directories' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeRestorePrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 48. Ensure 'Shut down the system' is set to 'Administrators'
control 'win2022-shut-down-system' do
  title "Ensure 'Shut down the system' is set to 'Administrators'"
  desc "Verify that 'Shut down the system' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeShutdownPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 49. Ensure 'Synchronize directory service data' is set to 'No One' (DC only)
control 'win2022-synchronize-directory-service-data' do
  title "Ensure 'Synchronize directory service data' is set to 'No One' (DC only)"
  desc "Verify that 'Synchronize directory service data' is set to 'No One'."
  impact 1.0
  describe security_policy do
    its('SeSyncAgentPrivilege') { should be_empty }
  end
end

# 50. Ensure 'Take ownership of files or other objects' is set to 'Administrators'
control 'win2022-take-ownership-files' do
  title "Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
  desc "Verify that 'Take ownership of files or other objects' is set to 'Administrators'."
  impact 1.0
  describe security_policy do
    its('SeTakeOwnershipPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 51. Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
control 'win2022-block-microsoft-accounts' do
  title "Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"
  desc "Verify that 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('NoConnectedUser') { should eq 3 }
  end
end

# 52. Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)
control 'win2022-guest-account-status' do
  title "Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)"
  desc "Verify that 'Accounts: Guest account status' is set to 'Disabled'."
  impact 1.0
  describe security_policy do
    its('EnableGuestAccount') { should eq 0 }
  end
end

# 53. Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
control 'win2022-limit-blank-passwords' do
  title "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
  desc "Verify that 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('LimitBlankPasswordUse') { should eq 1 }
  end
end

# 54. Configure 'Accounts: Rename administrator account'
control 'win2022-rename-administrator-account' do
  title "Configure 'Accounts: Rename administrator account'"
  desc "Verify that 'Accounts: Rename administrator account' is configured correctly."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('AdministratorAccountName') { should_not be_empty }
  end
end

# 55. Configure 'Accounts: Rename guest account'
control 'win2022-rename-guest-account' do
  title "Configure 'Accounts: Rename guest account'"
  desc "Verify that 'Accounts: Rename guest account' is configured correctly."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('GuestAccountName') { should_not be_empty }
  end
end

# 56. Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
control 'win2022-force-audit-policy-subcategory' do
  title "Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'"
  desc "Verify that 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('SCENoApplyLegacyAuditPolicy') { should eq 1 }
  end
end

# 57. Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
control 'win2022-shut-down-on-audit-failure' do
  title "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"
  desc "Verify that 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('CrashOnAuditFail') { should eq 0 }
  end
end

# 58. Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
control 'win2022-format-eject-removable-media' do
  title "Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'"
  desc "Verify that 'Devices: Allowed to format and eject removable media' is set to 'Administrators'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('NoMediaSharing') { should eq 1 }
  end
end

# 59. Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
control 'win2022-prevent-printer-driver-installation' do
  title "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'"
  desc "Verify that 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers') do
    its('DisablePrinterDriverInstall') { should eq 1 }
  end
end

# 60. Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
control 'win2022-secure-channel-encrypt-sign-always' do
  title "Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'"
  desc "Verify that 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('RequireSignOrSeal') { should eq 1 }
  end
end

# 61. Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
control 'win2022-secure-channel-encrypt-when-possible' do
  title "Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'"
  desc "Verify that 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('SealSecureChannel') { should eq 1 }
  end
end

# 62. Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
control 'win2022-secure-channel-sign-when-possible' do
  title "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'"
  desc "Verify that 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('SignSecureChannel') { should eq 1 }
  end
end

# 63. Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
control 'win2022-disable-machine-account-password-changes' do
  title "Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'"
  desc "Verify that 'Domain member: Disable machine account password changes' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('DisablePasswordChange') { should eq 0 }
  end
end

# 64. Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
control 'win2022-max-machine-account-password-age' do
  title "Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'"
  desc "Verify that 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('MaximumPasswordAge') { should be <= 30 }
    its('MaximumPasswordAge') { should_not eq 0 }
  end
end

# 65. Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
control 'win2022-require-strong-session-key' do
  title "Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'"
  desc "Verify that 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('RequireStrongKey') { should eq 1 }
  end
end

# 66. Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
control 'win2022-disable-ctrl-alt-del' do
  title "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'"
  desc "Verify that 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('DisableCAD') { should eq 0 }
  end
end

# 67. Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'
control 'win2022-dont-display-last-signed-in' do
  title "Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'"
  desc "Verify that 'Interactive logon: Don't display last signed-in' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('DontDisplayLastUserName') { should eq 1 }
  end
end

# 68. Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
control 'win2022-machine-inactivity-limit' do
  title "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'"
  desc "Verify that 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('InactivityTimeoutSecs') { should be <= 900 }
    its('InactivityTimeoutSecs') { should_not eq 0 }
  end
end

# 69. Configure 'Interactive logon: Message text for users attempting to log on'
control 'win2022-logon-message-text' do
  title "Configure 'Interactive logon: Message text for users attempting to log on'"
  desc "Verify that 'Interactive logon: Message text for users attempting to log on' is configured correctly."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('LegalNoticeText') { should_not be_empty }
  end
end

# 70. Configure 'Interactive logon: Message title for users attempting to log on'
control 'win2022-logon-message-title' do
  title "Configure 'Interactive logon: Message title for users attempting to log on'"
  desc "Verify that 'Interactive logon: Message title for users attempting to log on' is configured correctly."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('LegalNoticeCaption') { should_not be_empty }
  end
end

# 71. Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '0 logon(s)' (MS only)
control 'win2022-cache-previous-logons' do
  title "Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '0 logon(s)' (MS only)"
  desc "Verify that 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '0 logon(s)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('CachedLogonsCount') { should eq 0 }
  end
end

# 72. Ensure 'Interactive logon: Prompt user to change password before expiration' is set to '14 days'
control 'win2022-prompt-password-expiration' do
  title "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to '14 days'"
  desc "Verify that 'Interactive logon: Prompt user to change password before expiration' is set to '14 days'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('PasswordExpiryWarning') { should eq 14 }
  end
end

# 73. Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only)
control 'win2022-require-dc-authentication' do
  title "Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only)"
  desc "Verify that 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('ForceUnlockLogon') { should eq 1 }
  end
end

# 74. Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
control 'win2022-smart-card-removal-behavior' do
  title "Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher"
  desc "Verify that 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('ScRemoveOption') { should eq 1 }
  end
end

# 75. Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
control 'win2022-network-client-sign-always' do
  title "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
  desc "Verify that 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    its('RequireSecuritySignature') { should eq 1 }
  end
end

# 76. Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
control 'win2022-network-client-sign-if-server-agrees' do
  title "Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'"
  desc "Verify that 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    its('EnableSecuritySignature') { should eq 1 }
  end
end

# 77. Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
control 'win2022-network-client-send-unencrypted-password' do
  title "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
  desc "Verify that 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    its('EnablePlainTextPassword') { should eq 0 }
  end
end

# 78. Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'
control 'win2022-network-server-idle-time' do
  title "Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'"
  desc "Verify that 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('IdleTimeout') { should be <= 15 }
  end
end

# 79. Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
control 'win2022-network-server-sign-always' do
  title "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
  desc "Verify that 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('RequireSecuritySignature') { should eq 1 }
  end
end

# 80. Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
control 'win2022-network-server-sign-if-client-agrees' do
  title "Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
  desc "Verify that 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('EnableSecuritySignature') { should eq 1 }
  end
end

# 81. Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
control 'win2022-network-server-disconnect-logon-hours' do
  title "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'"
  desc "Verify that 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('EnableForcedLogoff') { should eq 1 }
  end
end

# 82. Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (MS only)
control 'win2022-network-server-spn-validation' do
  title "Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (MS only)"
  desc "Verify that 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('SMBServerNameHardeningLevel') { should be >= 1 }
  end
end

# 83. Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
control 'win2022-network-access-anonymous-sid-name' do
  title "Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'"
  desc "Verify that 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('TurnOffAnonymousBlock') { should eq 1 }
  end
end

# 84. Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only)
control 'win2022-network-access-anonymous-sam-accounts' do
  title "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only)"
  desc "Verify that 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('RestrictAnonymousSAM') { should eq 1 }
  end
end

# 85. Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only)
control 'win2022-network-access-anonymous-sam-shares' do
  title "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only)"
  desc "Verify that 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('RestrictAnonymous') { should eq 1 }
  end
end

# 86. Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
control 'win2022-network-access-no-password-storage' do
  title "Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'"
  desc "Verify that 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('DisableDomainCreds') { should eq 1 }
  end
end

# 87. Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
control 'win2022-network-access-everyone-anonymous' do
  title "Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'"
  desc "Verify that 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('EveryoneIncludesAnonymous') { should eq 0 }
  end
end

# 88. Configure 'Network access: Named Pipes that can be accessed anonymously' (MS only)
control 'win2022-network-access-named-pipes' do
  title "Configure 'Network access: Named Pipes that can be accessed anonymously' (MS only)"
  desc "Verify that 'Network access: Named Pipes that can be accessed anonymously' is configured correctly."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('NullSessionPipes') { should be_empty }
  end
end

# 89. Configure 'Network access: Remotely accessible registry paths' is configured
control 'win2022-network-access-registry-paths' do
  title "Configure 'Network access: Remotely accessible registry paths' is configured"
  desc "Verify that 'Network access: Remotely accessible registry paths' is configured correctly."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg') do
    its('AllowedPaths') { should_not be_empty }
  end
end

# 90. Configure 'Network access: Remotely accessible registry paths and sub-paths' is configured
control 'win2022-network-access-registry-sub-paths' do
  title "Configure 'Network access: Remotely accessible registry paths and sub-paths' is configured"
  desc "Verify that 'Network access: Remotely accessible registry paths and sub-paths' is configured correctly."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg') do
    its('AllowedPaths') { should_not be_empty }
  end
end

# 91. Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
control 'win2022-restrict-anonymous-pipes-shares' do
  title "Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"
  desc "Verify that 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('RestrictAnonymous') { should eq 1 }
  end
end

# 92. Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only)
control 'win2022-restrict-remote-calls-sam' do
  title "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only)"
  desc "Verify that 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('RestrictRemoteSAM') { should eq 1 }
  end
end

# 93. Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
control 'win2022-anonymous-shares-none' do
  title "Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"
  desc "Verify that 'Network access: Shares that can be accessed anonymously' is set to 'None'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('NullSessionShares') { should be_empty }
  end
end

# 94. Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
control 'win2022-sharing-security-model-local-accounts' do
  title "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'"
  desc "Verify that 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('ForceGuest') { should eq 0 }
  end
end

# 95. Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
control 'win2022-allow-local-system-ntlm' do
  title "Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
  desc "Verify that 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('UseMachineIdentity') { should eq 1 }
  end
end

# 96. Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
control 'win2022-allow-localsystem-null-session' do
  title "Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
  desc "Verify that 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('AllowNullSessionFallback') { should eq 0 }
  end
end

# 97. Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
control 'win2022-allow-pku2u-authentication' do
  title "Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'"
  desc "Verify that 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u') do
    its('AllowOnlineID') { should eq 0 }
  end
end

# 98. Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
control 'win2022-do-not-store-lan-manager-hash' do
  title "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"
  desc "Verify that 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('NoLMHash') { should eq 1 }
  end
end

# 99. Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled' (Manual)
control 'win2022-force-logoff-logon-hours' do
  title "Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled' (Manual)"
  desc "Verify that 'Network security: Force logoff when logon hours expire' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('EnableForcedLogoff') { should eq 1 }
  end
end

# 100. Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
control 'win2022-lan-manager-authentication-level' do
  title "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'"
  desc "Verify that 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('LmCompatibilityLevel') { should eq 5 }
  end
end

# 101. Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
control 'win2022-ldap-client-signing-requirements' do
  title "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher"
  desc "Verify that 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP') do
    its('LDAPSigning') { should be >= 1 }
  end
end

# 102. Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
control 'win2022-minimum-session-security-clients' do
  title "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
  desc "Verify that 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('NTLMMinClientSec') { should eq 537395200 }
  end
end

# 103. Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
control 'win2022-minimum-session-security-servers' do
  title "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
  desc "Verify that 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('NTLMMinServerSec') { should eq 537395200 }
  end
end

# 104. Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
control 'win2022-shutdown-without-logon' do
  title "Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'"
  desc "Verify that 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('ShutdownWithoutLogon') { should eq 0 }
  end
end

# 105. Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
control 'win2022-require-case-insensitivity' do
  title "Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'"
  desc "Verify that 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager') do
    its('ObCaseInsensitive') { should eq 1 }
  end
end

# 106. Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
control 'win2022-strengthen-default-permissions' do
  title "Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'"
  desc "Verify that 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager') do
    its('ProtectionMode') { should eq 1 }
  end
end

# 107. Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
control 'win2022-uac-deny-elevation-requests' do
  title "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
  desc "Verify that 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('ConsentPromptBehaviorUser') { should eq 0 }
  end
end

# 108. Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
control 'win2022-uac-detect-app-installations' do
  title "Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
  desc "Verify that 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('EnableInstallerDetection') { should eq 1 }
  end
end

# 109. Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'
control 'win2022-uac-elevate-uiaccess-secure-locations' do
  title "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
  desc "Verify that 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('EnableSecureUIAPaths') { should eq 1 }
  end
end

# 110. Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
control 'win2022-uac-secure-desktop' do
  title "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"
  desc "Verify that 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('PromptOnSecureDesktop') { should eq 1 }
  end
end

# 111. Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
control 'win2022-uac-virtualize-write-failures' do
  title "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
  desc "Verify that 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('EnableVirtualization') { should eq 1 }
  end
end

# 112. Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (MS only)
control 'win2022-print-spooler-disabled' do
  title "Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (MS only)"
  desc "Verify that 'Print Spooler (Spooler)' is set to 'Disabled'."
  impact 1.0
  describe service('Spooler') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end

# 113. Ensure 'Audit Credential Validation' is set to 'Success and Failure'
control 'win2022-audit-credential-validation' do
  title "Ensure 'Audit Credential Validation' is set to 'Success and Failure'"
  desc "Verify that 'Audit Credential Validation' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Credential Validation') { should eq 'Success and Failure' }
  end
end

# 114. Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure' (DC Only)
control 'win2022-audit-kerberos-authentication-service' do
  title "Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure' (DC Only)"
  desc "Verify that 'Audit Kerberos Authentication Service' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Kerberos Authentication Service') { should eq 'Success and Failure' }
  end
end

# 115. Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure' (DC Only)
control 'win2022-audit-kerberos-service-ticket-operations' do
  title "Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure' (DC Only)"
  desc "Verify that 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Kerberos Service Ticket Operations') { should eq 'Success and Failure' }
  end
end

# 116. Ensure 'Audit Application Group Management' is set to 'Success and Failure'
control 'win2022-audit-application-group-management' do
  title "Ensure 'Audit Application Group Management' is set to 'Success and Failure'"
  desc "Verify that 'Audit Application Group Management' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Application Group Management') { should eq 'Success and Failure' }
  end
end

# 117. Ensure 'Audit Computer Account Management' is set to include 'Success' (DC only)
control 'win2022-audit-computer-account-management' do
  title "Ensure 'Audit Computer Account Management' is set to include 'Success' (DC only)"
  desc "Verify that 'Audit Computer Account Management' is set to include 'Success'."
  impact 1.0
  describe audit_policy do
    its('Computer Account Management') { should eq 'Success' }
  end
end

# 118. Ensure 'Audit Distribution Group Management' is set to include 'Success' (DC only)
control 'win2022-audit-distribution-group-management' do
  title "Ensure 'Audit Distribution Group Management' is set to include 'Success' (DC only)"
  desc "Verify that 'Audit Distribution Group Management' is set to include 'Success'."
  impact 1.0
  describe audit_policy do
    its('Distribution Group Management') { should eq 'Success' }
  end
end

# 119. Ensure 'Audit Other Account Management Events' is set to include 'Success' (DC only)
control 'win2022-audit-other-account-management-events' do
  title "Ensure 'Audit Other Account Management Events' is set to include 'Success' (DC only)"
  desc "Verify that 'Audit Other Account Management Events' is set to include 'Success'."
  impact 1.0
  describe audit_policy do
    its('Other Account Management Events') { should eq 'Success' }
  end
end

# 120. Ensure 'Audit Security Group Management' is set to include 'Success'
control 'win2022-audit-security-group-management' do
  title "Ensure 'Audit Security Group Management' is set to include 'Success'"
  desc "Verify that 'Audit Security Group Management' is set to include 'Success'."
  impact 1.0
  describe audit_policy do
    its('Security Group Management') { should eq 'Success' }
  end
end

# 121. Ensure 'Audit User Account Management' is set to 'Success and Failure'
control 'win2022-audit-user-account-management' do
  title "Ensure 'Audit User Account Management' is set to 'Success and Failure'"
  desc "Verify that 'Audit User Account Management' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('User Account Management') { should eq 'Success and Failure' }
  end
end

# 122. Ensure 'Audit PNP Activity' is set to include 'Success'
control 'win2022-audit-pnp-activity' do
  title "Ensure 'Audit PNP Activity' is set to include 'Success'"
  desc "Verify that 'Audit PNP Activity' is set to include 'Success'."
  impact 1.0
  describe audit_policy do
    its('PNP Activity') { should eq 'Success' }
  end
end

# 123. Ensure 'Audit Process Creation' is set to include 'Success'
control 'win2022-audit-process-creation' do
  title "Ensure 'Audit Process Creation' is set to include 'Success'"
  desc "Verify that 'Audit Process Creation' is set to include 'Success'."
  impact 1.0
  describe audit_policy do
    its('Process Creation') { should eq 'Success' }
  end
end

# 124. Ensure 'Audit Directory Service Access' is set to include 'Failure' (DC only)
control 'win2022-audit-directory-service-access' do
  title "Ensure 'Audit Directory Service Access' is set to include 'Failure' (DC only)"
  desc "Verify that 'Audit Directory Service Access' is set to include 'Failure'."
  impact 1.0
  describe audit_policy do
    its('Directory Service Access') { should eq 'Failure' }
  end
end

# 125. Ensure 'Audit Directory Service Changes' is set to include 'Success' (DC only)
control 'win2022-audit-directory-service-changes' do
  title "Ensure 'Audit Directory Service Changes' is set to include 'Success' (DC only)"
  desc "Verify that 'Audit Directory Service Changes' is set to include 'Success'."
  impact 1.0
  describe audit_policy do
    its('Directory Service Changes') { should eq 'Success' }
  end
end

# 126. Ensure 'Audit Account Lockout' is set to include 'Failure'
control 'win2022-audit-account-lockout' do
  title "Ensure 'Audit Account Lockout' is set to include 'Failure'"
  desc "Verify that 'Audit Account Lockout' is set to include 'Failure'."
  impact 1.0
  describe audit_policy do
    its('Account Lockout') { should eq 'Failure' }
  end
end

# 127. Ensure 'Audit Group Membership' is set to include 'Success'
control 'win2022-audit-group-membership' do
  title "Ensure 'Audit Group Membership' is set to include 'Success'"
  desc "Verify that 'Audit Group Membership' is set to include 'Success'."
  impact 1.0
  describe audit_policy do
    its('Group Membership') { should eq 'Success' }
  end
end

# 128. Ensure 'Audit Logoff' is set to include 'Success'
control 'win2022-audit-logoff' do
  title "Ensure 'Audit Logoff' is set to include 'Success'"
  desc "Verify that 'Audit Logoff' is set to include 'Success'."
  impact 1.0
  describe audit_policy do
    its('Logoff') { should eq 'Success' }
  end
end

# 129. Ensure 'Audit Logon' is set to 'Success and Failure'
control 'win2022-audit-logon' do
  title "Ensure 'Audit Logon' is set to 'Success and Failure'"
  desc "Verify that 'Audit Logon' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Logon') { should eq 'Success and Failure' }
  end
end

# 130. Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
control 'win2022-audit-other-logon-logoff-events' do
  title "Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"
  desc "Verify that 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Other Logon/Logoff Events') { should eq 'Success and Failure' }
  end
end

# 131. Ensure 'Audit Special Logon' is set to include 'Success'
control 'win2022-audit-special-logon' do
  title "Ensure 'Audit Special Logon' is set to include 'Success'"
  desc "Verify that 'Audit Special Logon' is set to include 'Success'."
  impact 1.0
  describe audit_policy do
    its('Special Logon') { should eq 'Success' }
  end
end

# 132. Ensure 'Audit Detailed File Share' is set to include 'Failure'
control 'win2022-audit-detailed-file-share' do
  title "Ensure 'Audit Detailed File Share' is set to include 'Failure'"
  desc "Verify that 'Audit Detailed File Share' is set to include 'Failure'."
  impact 1.0
  describe audit_policy do
    its('Detailed File Share') { should eq 'Failure' }
  end
end

# 133. Ensure 'Audit File Share' is set to 'Success and Failure'
control 'win2022-audit-file-share' do
  title "Ensure 'Audit File Share' is set to 'Success and Failure'"
  desc "Verify that 'Audit File Share' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('File Share') { should eq 'Success and Failure' }
  end
end

# 134. Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'
control 'win2022-audit-other-object-access-events' do
  title "Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'"
  desc "Verify that 'Audit Other Object Access Events' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Other Object Access Events') { should eq 'Success and Failure' }
  end
end

# 135. Ensure 'Audit Removable Storage' is set to 'Success and Failure'
control 'win2022-audit-removable-storage' do
  title "Ensure 'Audit Removable Storage' is set to 'Success and Failure'"
  desc "Verify that 'Audit Removable Storage' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Removable Storage') { should eq 'Success and Failure' }
  end
end

# 136. Ensure 'Audit Audit Policy Change' is set to include 'Success'
control 'win2022-audit-policy-change' do
  title "Ensure 'Audit Audit Policy Change' is set to include 'Success'"
  desc "Verify that 'Audit Audit Policy Change' is set to include 'Success'."
  impact 1.0
  describe audit_policy do
    its('Audit Policy Change') { should eq 'Success' }
  end
end

# 137. Ensure 'Audit Authentication Policy Change' is set to include 'Success'
control 'win2022-authentication-policy-change' do
  title "Ensure 'Audit Authentication Policy Change' is set to include 'Success'"
  desc "Verify that 'Audit Authentication Policy Change' is set to include 'Success'."
  impact 1.0
  describe audit_policy do
    its('Authentication Policy Change') { should eq 'Success' }
  end
end

# 138. Ensure 'Audit Authorization Policy Change' is set to include 'Success'
control 'win2022-authorization-policy-change' do
  title "Ensure 'Audit Authorization Policy Change' is set to include 'Success'"
  desc "Verify that 'Audit Authorization Policy Change' is set to include 'Success'."
  impact 1.0
  describe audit_policy do
    its('Authorization Policy Change') { should eq 'Success' }
  end
end

# 139. Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'
control 'win2022-mpssvc-rule-policy-change' do
  title "Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'"
  desc "Verify that 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('MPSSVC Rule-Level Policy Change') { should eq 'Success and Failure' }
  end
end

# 140. Ensure 'Audit Other Policy Change Events' is set to include 'Failure'
control 'win2022-other-policy-change-events' do
  title "Ensure 'Audit Other Policy Change Events' is set to include 'Failure'"
  desc "Verify that 'Audit Other Policy Change Events' is set to include 'Failure'."
  impact 1.0
  describe audit_policy do
    its('Other Policy Change Events') { should eq 'Failure' }
  end
end

# 141. Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
control 'win2022-sensitive-privilege-use' do
  title "Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'"
  desc "Verify that 'Audit Sensitive Privilege Use' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Sensitive Privilege Use') { should eq 'Success and Failure' }
  end
end

# 142. Ensure 'Audit IPsec Driver' is set to 'Success and Failure'
control 'win2022-ipsec-driver' do
  title "Ensure 'Audit IPsec Driver' is set to 'Success and Failure'"
  desc "Verify that 'Audit IPsec Driver' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('IPsec Driver') { should eq 'Success and Failure' }
  end
end

# 143. Ensure 'Audit Other System Events' is set to 'Success and Failure'
control 'win2022-other-system-events' do
  title "Ensure 'Audit Other System Events' is set to 'Success and Failure'"
  desc "Verify that 'Audit Other System Events' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('Other System Events') { should eq 'Success and Failure' }
  end
end

# 144. Ensure 'Audit Security State Change' is set to include 'Success'
control 'win2022-security-state-change' do
  title "Ensure 'Audit Security State Change' is set to include 'Success'"
  desc "Verify that 'Audit Security State Change' is set to include 'Success'."
  impact 1.0
  describe audit_policy do
    its('Security State Change') { should eq 'Success' }
  end
end

# 145. Ensure 'Audit Security System Extension' is set to include 'Success'
control 'win2022-security-system-extension' do
  title "Ensure 'Audit Security System Extension' is set to include 'Success'"
  desc "Verify that 'Audit Security System Extension' is set to include 'Success'."
  impact 1.0
  describe audit_policy do
    its('Security System Extension') { should eq 'Success' }
  end
end

# 146. Ensure 'Audit System Integrity' is set to 'Success and Failure'
control 'win2022-system-integrity' do
  title "Ensure 'Audit System Integrity' is set to 'Success and Failure'"
  desc "Verify that 'Audit System Integrity' is set to 'Success and Failure'."
  impact 1.0
  describe audit_policy do
    its('System Integrity') { should eq 'Success and Failure' }
  end
end

# 147. Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'
control 'win2022-lock-screen-camera' do
  title "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
  desc "Verify that 'Prevent enabling lock screen camera' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization') do
    its('NoLockScreenCamera') { should eq 1 }
  end
end

# 148. Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
control 'win2022-lock-screen-slide-show' do
  title "Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
  desc "Verify that 'Prevent enabling lock screen slide show' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization') do
    its('NoLockScreenSlideshow') { should eq 1 }
  end
end

# 149. Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'
control 'win2022-online-speech-recognition' do
  title "Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'"
  desc "Verify that 'Allow users to enable online speech recognition services' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Speech') do
    its('AllowSpeechServices') { should eq 0 }
  end
end

# 150. Ensure 'Allow Online Tips' is set to 'Disabled'
control 'win2022-online-tips' do
  title "Ensure 'Allow Online Tips' is set to 'Disabled'"
  desc "Verify that 'Allow Online Tips' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableSoftLanding') { should eq 1 }
  end
end

# 151. Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'
control 'win2022-uac-restrictions-network-logons' do
  title "Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'"
  desc "Verify that 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('LocalAccountTokenFilterPolicy') { should eq 1 }
  end
end

# 152. Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'
control 'win2022-rpc-packet-privacy' do
  title "Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'"
  desc "Verify that 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RPC') do
    its('EnablePacketPrivacy') { should eq 1 }
  end
end

# 153. Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'
control 'win2022-smb-v1-client-driver' do
  title "Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'"
  desc "Verify that 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MRxSmb10') do
    its('Start') { should eq 4 }
  end
end

# 154. Ensure 'Configure SMB v1 server' is set to 'Disabled'
control 'win2022-smb-v1-server' do
  title "Ensure 'Configure SMB v1 server' is set to 'Disabled'"
  desc "Verify that 'Configure SMB v1 server' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('SMB1') { should eq 0 }
  end
end

# 155. Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'
control 'win2022-sehop' do
  title "Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
  desc "Verify that 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel') do
    its('DisableExceptionChainValidation') { should eq 0 }
  end
end

# 156. Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'
control 'win2022-netbt-nodetype' do
  title "Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'"
  desc "Verify that 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters') do
    its('NodeType') { should eq 2 }
  end
end

# 157. Ensure 'WDigest Authentication' is set to 'Disabled'
control 'win2022-wdigest-authentication' do
  title "Ensure 'WDigest Authentication' is set to 'Disabled'"
  desc "Verify that 'WDigest Authentication' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest') do
    its('UseLogonCredential') { should eq 0 }
  end
end

# 158. Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
control 'win2022-auto-admin-logon' do
  title "Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'"
  desc "Verify that 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon') do
    its('AutoAdminLogon') { should eq 0 }
  end
end

# 159. Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
control 'win2022-disable-ip-source-routing-ipv6' do
  title "Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
  desc "Verify that 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters') do
    its('DisableIPSourceRouting') { should eq 2 }
  end
end

# 160. Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
control 'win2022-disable-ip-source-routing' do
  title "Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
  desc "Verify that 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    its('DisableIPSourceRouting') { should eq 2 }
  end
end

# 161. Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'
control 'win2022-enable-icmp-redirect' do
  title "Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
  desc "Verify that 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    its('EnableICMPRedirect') { should eq 0 }
  end
end

# 162. Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'
control 'win2022-keep-alive-time' do
  title "Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'"
  desc "Verify that 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    its('KeepAliveTime') { should eq 300000 }
  end
end

# 163. Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'
control 'win2022-no-name-release-on-demand' do
  title "Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
  desc "Verify that 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters') do
    its('NoNameReleaseOnDemand') { should eq 1 }
  end
end

# 164. Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'
control 'win2022-perform-router-discovery' do
  title "Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'"
  desc "Verify that 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    its('PerformRouterDiscovery') { should eq 0 }
  end
end

# 165. Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'
control 'win2022-safe-dll-search-mode' do
  title "Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'"
  desc "Verify that 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager') do
    its('SafeDllSearchMode') { should eq 1 }
  end
end

# 166. Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'
control 'win2022-screen-saver-grace-period' do
  title "Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'"
  desc "Verify that 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager') do
    its('ScreenSaverGracePeriod') { should eq 5 }
  end
end

# 167. Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
control 'win2022-tcp-max-data-retransmissions-ipv6' do
  title "Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
  desc "Verify that 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters') do
    its('TcpMaxDataRetransmissions') { should eq 3 }
  end
end

# 168. Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
control 'win2022-tcp-max-data-retransmissions' do
  title "Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
  desc "Verify that 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    its('TcpMaxDataRetransmissions') { should eq 3 }
  end
end

# 169. Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'
control 'win2022-warning-level' do
  title "Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"
  desc "Verify that 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EventLog\Security') do
    its('WarningLevel') { should eq 90 }
  end
end

# 170. Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher
control 'win2022-dns-over-https' do
  title "Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher"
  desc "Verify that 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DNSClient') do
    its('EnableAutoDoh') { should eq 1 }
  end
end

# 171. Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'
control 'win2022-configure-netbios-settings' do
  title "Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'"
  desc "Verify that 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters') do
    its('EnableNetbiosOverTcpip') { should eq 2 }
  end
end

# 172. Ensure 'Turn off multicast name resolution' is set to 'Enabled'
control 'win2022-turn-off-multicast-name-resolution' do
  title "Ensure 'Turn off multicast name resolution' is set to 'Enabled'"
  desc "Verify that 'Turn off multicast name resolution' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD') do
    its('EnableMulticastNameResolution') { should eq 0 }
  end
end

# 173. Ensure 'Enable Font Providers' is set to 'Disabled'
control 'win2022-enable-font-providers' do
  title "Ensure 'Enable Font Providers' is set to 'Disabled'"
  desc "Verify that 'Enable Font Providers' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Font Providers') do
    its('EnableFontProviders') { should eq 0 }
  end
end

# 174. Ensure 'Enable insecure guest logons' is set to 'Disabled'
control 'win2022-enable-insecure-guest-logons' do
  title "Ensure 'Enable insecure guest logons' is set to 'Disabled'"
  desc "Verify that 'Enable insecure guest logons' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation') do
    its('AllowInsecureGuestAuth') { should eq 0 }
  end
end

# 175. Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'
control 'win2022-turn-on-mapper-io-driver' do
  title "Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'"
  desc "Verify that 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD') do
    its('AllowMapperIo') { should eq 0 }
  end
end

# 176. Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'
control 'win2022-turn-on-responder-driver' do
  title "Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'"
  desc "Verify that 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD') do
    its('AllowRspndr') { should eq 0 }
  end
end

# 177. Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'
control 'win2022-turn-off-peer-to-peer-networking' do
  title "Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'"
  desc "Verify that 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\PeerToPeer') do
    its('Disabled') { should eq 1 }
  end
end

# 178. Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
control 'win2022-prohibit-network-bridge' do
  title "Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
  desc "Verify that 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections') do
    its('NC_AllowNetBridge_NLA') { should eq 0 }
  end
end

# 179. Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
control 'win2022-prohibit-internet-connection-sharing' do
  title "Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
  desc "Verify that 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections') do
    its('NC_ShowSharedAccessUI') { should eq 0 }
  end
end

# 180. Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'
control 'win2022-require-elevation-network-location' do
  title "Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'"
  desc "Verify that 'Require domain users to elevate when setting a network's location' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections') do
    its('NC_RequireDomainUserElevation') { should eq 1 }
  end
end

# 181. Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'
control 'win2022-hardened-unc-paths' do
  title "Ensure 'Hardened UNC Paths' is set to 'Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares'"
  desc "Verify that 'Hardened UNC Paths' is set to 'Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths') do
    its('\\\\*\\NETLOGON') { should eq "RequireMutualAuthentication=1, RequireIntegrity=1" }
    its('\\\\*\\SYSVOL') { should eq "RequireMutualAuthentication=1, RequireIntegrity=1" }
  end
end

# 182. Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')
control 'win2022-disable-ipv6' do
  title "Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')"
  desc "Verify that IPv6 is disabled by ensuring TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\TCPIP6\Parameters') do
    its('DisabledComponents') { should eq 255 }
  end
end

# 183. Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'
control 'win2022-disable-windows-connect-now' do
  title "Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
  desc "Verify that 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Settings') do
    its('DisableWcnConfig') { should eq 1 }
  end
end

# 184. Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'
control 'win2022-prohibit-windows-connect-now-wizards' do
  title "Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'"
  desc "Verify that 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Settings') do
    its('DisableWcnWizard') { should eq 1 }
  end
end

# 185. Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'
control 'win2022-minimize-simultaneous-connections' do
  title "Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'"
  desc "Verify that 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Wcm\Settings') do
    its('MinimizeConnections') { should eq 3 }
  end
end

# 186. Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'
control 'win2022-prohibit-non-domain-networks' do
  title "Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'"
  desc "Verify that 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Wcm\Settings') do
    its('ProhibitNonDomainNetworks') { should eq 1 }
  end
end

# 187. Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'
control 'win2022-disable-print-spooler-client-connections' do
  title "Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'"
  desc "Verify that 'Allow Print Spooler to accept client connections' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Spooler') do
    its('Start') { should eq 4 }
  end
end

# 188. Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'
control 'win2022-configure-redirection-guard' do
  title "Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'"
  desc "Verify that 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredentialsDelegation') do
    its('EnableRedirectionGuard') { should eq 1 }
  end
end

# 189. Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'
control 'win2022-configure-rpc-protocol' do
  title "Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'"
  desc "Verify that 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RPC') do
    its('Protocol') { should eq 'TCP' }
  end
end

# 190. Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'
control 'win2022-configure-rpc-authentication' do
  title "Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'"
  desc "Verify that 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RPC') do
    its('Authentication') { should eq 'Default' }
  end
end

# 191. Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'
control 'win2022-configure-rpc-listener-protocols' do
  title "Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'"
  desc "Verify that 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RPC') do
    its('ListenerProtocols') { should eq 'TCP' }
  end
end

# 192. Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher
control 'win2022-configure-rpc-listener-authentication' do
  title "Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher"
  desc "Verify that 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RPC') do
    its('ListenerAuthentication') { should eq 'Negotiate' }
  end
end

# 193. Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0'
control 'win2022-configure-rpc-tcp-port' do
  title "Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0'"
  desc "Verify that 'Configure RPC over TCP port' is set to 'Enabled: 0'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RPC') do
    its('TCPPort') { should eq 0 }
  end
end

# 194. Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'
control 'win2022-limit-print-driver-installation' do
  title "Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'"
  desc "Verify that 'Limits print driver installation to Administrators' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers') do
    its('RestrictDriverInstallationToAdministrators') { should eq 1 }
  end
end

# 195. Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'
control 'win2022-manage-queue-specific-files' do
  title "Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'"
  desc "Verify that 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers') do
    its('QueueFileProcessing') { should eq 'ColorProfiles' }
  end
end

# 196. Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'
control 'win2022-point-and-print-new-connection' do
  title "Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'"
  desc "Verify that 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint') do
    its('NewConnectionDriverPrompt') { should eq 1 }
  end
end

# 197. Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'
control 'win2022-point-and-print-existing-connection' do
  title "Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'"
  desc "Verify that 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint') do
    its('ExistingConnectionDriverPrompt') { should eq 1 }
  end
end

# 198. Ensure 'Turn off notifications network usage' is set to 'Enabled'
control 'win2022-turn-off-notifications-network-usage' do
  title "Ensure 'Turn off notifications network usage' is set to 'Enabled'"
  desc "Verify that 'Turn off notifications network usage' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications') do
    its('DisableNetworkUsageNotifications') { should eq 1 }
  end
end

# 199. Ensure 'Include command line in process creation events' is set to 'Enabled'
control 'win2022-include-command-line-process-creation' do
  title "Ensure 'Include command line in process creation events' is set to 'Enabled'"
  desc "Verify that 'Include command line in process creation events' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit') do
    its('ProcessCreationIncludeCmdLine_Enabled') { should eq 1 }
  end
end

# 200. Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'
control 'win2022-remote-host-delegation' do
  title "Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'"
  desc "Verify that 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredentialsDelegation') do
    its('AllowNonExportableDelegation') { should eq 1 }
  end
end

# 201. Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'
control 'win2022-turn-on-vbs' do
  title "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'"
  desc "Verify that 'Turn On Virtualization Based Security' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard') do
    its('EnableVirtualizationBasedSecurity') { should eq 1 }
  end
end

# 202. Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot' or higher
control 'win2022-vbs-platform-security-level' do
  title "Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot' or higher"
  desc "Verify that 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard') do
    its('PlatformSecurityLevel') { should eq 'SecureBoot' }
  end
end

# 203. Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'
control 'win2022-vbs-code-integrity' do
  title "Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'"
  desc "Verify that 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard') do
    its('CodeIntegrity') { should eq 'UEFILock' }
  end
end

# 204. Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'
control 'win2022-vbs-uefi-memory-attributes' do
  title "Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'"
  desc "Verify that 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard') do
    its('RequireUEFIMemoryAttributes') { should eq 1 }
  end
end

# 205. Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock'
control 'win2022-vbs-credential-guard' do
  title "Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock'"
  desc "Verify that 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard') do
    its('CredentialGuard') { should eq 'UEFILock' }
  end
end

# 206. Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'
control 'win2022-vbs-secure-launch' do
  title "Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'"
  desc "Verify that 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard') do
    its('SecureLaunch') { should eq 1 }
  end
end

# 207. Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'
control 'win2022-prevent-device-metadata-retrieval' do
  title "Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'"
  desc "Verify that 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceMetadata') do
    its('PreventDeviceMetadataRetrieval') { should eq 1 }
  end
end

# 208. Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
control 'win2022-boot-start-driver-policy' do
  title "Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
  desc "Verify that 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager') do
    its('BootDriverInitializationPolicy') { should eq 'GoodUnknownBadCritical' }
  end
end

# 209. Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
control 'win2022-registry-policy-background-processing' do
  title "Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"
  desc "Verify that 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DisableBackgroundProcessing') { should eq 0 }
  end
end

# 210. Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
control 'win2022-registry-policy-process-unchanged' do
  title "Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
  desc "Verify that 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('ProcessUnchangedGroupPolicy') { should eq 1 }
  end
end

# 211. Ensure 'Continue experiences on this device' is set to 'Disabled'
control 'win2022-continue-experiences' do
  title "Ensure 'Continue experiences on this device' is set to 'Disabled'"
  desc "Verify that 'Continue experiences on this device' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('EnableCdp') { should eq 0 }
  end
end

# 212. Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'
control 'win2022-background-refresh-group-policy' do
  title "Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'"
  desc "Verify that 'Turn off background refresh of Group Policy' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DisableBackgroundRefresh') { should eq 0 }
  end
end

# 213. Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
control 'win2022-disable-print-drivers-http' do
  title "Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'"
  desc "Verify that 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers') do
    its('DisableHTTPPrinting') { should eq 1 }
  end
end

# 214. Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
control 'win2022-disable-handwriting-data-sharing' do
  title "Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'"
  desc "Verify that 'Turn off handwriting personalization data sharing' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TabletPC') do
    its('PreventHandwritingDataSharing') { should eq 1 }
  end
end

# 215. Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
control 'win2022-disable-handwriting-error-reporting' do
  title "Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'"
  desc "Verify that 'Turn off handwriting recognition error reporting' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TabletPC') do
    its('PreventHandwritingErrorReporting') { should eq 1 }
  end
end

# 216. Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
control 'win2022-disable-internet-connection-wizard' do
  title "Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'"
  desc "Verify that 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Internet Connection Wizard') do
    its('DisableICW') { should eq 1 }
  end
end

# 217. Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
control 'win2022-disable-web-publishing-wizards' do
  title "Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'"
  desc "Verify that 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoPublishingWizard') { should eq 1 }
  end
end

# 218. Ensure 'Turn off printing over HTTP' is set to 'Enabled'
control 'win2022-disable-printing-http' do
  title "Ensure 'Turn off printing over HTTP' is set to 'Enabled'"
  desc "Verify that 'Turn off printing over HTTP' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers') do
    its('DisableHTTPPrinting') { should eq 1 }
  end
end

# 219. Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
control 'win2022-disable-registration-microsoft' do
  title "Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'"
  desc "Verify that 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Registration') do
    its('DisableRegistration') { should eq 1 }
  end
end

# 220. Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
control 'win2022-disable-search-companion-updates' do
  title "Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'"
  desc "Verify that 'Turn off Search Companion content file updates' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SearchCompanion') do
    its('DisableContentFileUpdates') { should eq 1 }
  end
end

# 221. Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
control 'win2022-disable-order-prints-task' do
  title "Ensure 'Turn off the \"Order Prints\" picture task' is set to 'Enabled'"
  desc "Verify that 'Turn off the \"Order Prints\" picture task' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoOrderPrints') { should eq 1 }
  end
end

# 222. Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
control 'win2022-disable-publish-to-web-task' do
  title "Ensure 'Turn off the \"Publish to Web\" task for files and folders' is set to 'Enabled'"
  desc "Verify that 'Turn off the \"Publish to Web\" task for files and folders' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoPublishToWeb') { should eq 1 }
  end
end

# 223. Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
control 'win2022-disable-messenger-ceip' do
  title "Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'"
  desc "Verify that 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger') do
    its('CEIP') { should eq 0 }
  end
end

# 224. Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
control 'win2022-disable-windows-ceip' do
  title "Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'"
  desc "Verify that 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CEIP') do
    its('CEIPEnable') { should eq 0 }
  end
end

# 225. Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
control 'win2022-disable-error-reporting' do
  title "Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'"
  desc "Verify that 'Turn off Windows Error Reporting' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Error Reporting') do
    its('Disabled') { should eq 1 }
  end
end

# 226. Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'
control 'win2022-support-device-authentication' do
  title "Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'"
  desc "Verify that 'Support device authentication using certificate' is set to 'Enabled: Automatic'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceAuthentication') do
    its('CertificateAuthentication') { should eq 'Automatic' }
  end
end

# 227. Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'
control 'win2022-enumeration-policy-external-devices' do
  title "Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'"
  desc "Verify that 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\KernelDMAProtection') do
    its('EnumerationPolicy') { should eq 'BlockAll' }
  end
end

# 228. Ensure 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled'
control 'win2022-disable-custom-ssps-aps' do
  title "Ensure 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled'"
  desc "Verify that 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LSASS') do
    its('AllowCustomSSPs') { should eq 0 }
  end
end

# 229. Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock'
control 'win2022-lsass-protected-process' do
  title "Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock'"
  desc "Verify that 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LSASS') do
    its('ProtectedProcess') { should eq 'UEFILock' }
  end
end

# 230. Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'
control 'win2022-disallow-copying-input-methods' do
  title "Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'"
  desc "Verify that 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DisallowCopyingInputMethods') { should eq 1 }
  end
end

# 231. Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'
control 'win2022-block-account-details-sign-in' do
  title "Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'"
  desc "Verify that 'Block user from showing account details on sign-in' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('BlockUserAccountDetails') { should eq 1 }
  end
end

# 232. Ensure 'Do not display network selection UI' is set to 'Enabled'
control 'win2022-disable-network-selection-ui' do
  title "Ensure 'Do not display network selection UI' is set to 'Enabled'"
  desc "Verify that 'Do not display network selection UI' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DontDisplayNetworkSelectionUI') { should eq 1 }
  end
end

# 233. Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'
control 'win2022-disable-enumerate-connected-users' do
  title "Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'"
  desc "Verify that 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DontEnumerateConnectedUsers') { should eq 1 }
  end
end

# 234. Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'
control 'win2022-disable-enumerate-local-users' do
  title "Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'"
  desc "Verify that 'Enumerate local users on domain-joined computers' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('EnumerateLocalUsers') { should eq 0 }
  end
end

# 235. Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'
control 'win2022-disable-app-notifications-lock-screen' do
  title "Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'"
  desc "Verify that 'Turn off app notifications on the lock screen' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DisableLockScreenAppNotifications') { should eq 1 }
  end
end

# 236. Ensure 'Turn off picture password sign-in' is set to 'Enabled'
control 'win2022-disable-picture-password-sign-in' do
  title "Ensure 'Turn off picture password sign-in' is set to 'Enabled'"
  desc "Verify that 'Turn off picture password sign-in' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DisablePicturePassword') { should eq 1 }
  end
end

# 237. Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
control 'win2022-disable-convenience-pin-sign-in' do
  title "Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'"
  desc "Verify that 'Turn on convenience PIN sign-in' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('AllowConveniencePIN') { should eq 0 }
  end
end

# 238. Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled'
control 'win2022-disable-clipboard-sync' do
  title "Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled'"
  desc "Verify that 'Allow Clipboard synchronization across devices' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('AllowCrossDeviceClipboard') { should eq 0 }
  end
end

# 239. Ensure 'Allow upload of User Activities' is set to 'Disabled'
control 'win2022-disable-upload-user-activities' do
  title "Ensure 'Allow upload of User Activities' is set to 'Disabled'"
  desc "Verify that 'Allow upload of User Activities' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('UploadUserActivities') { should eq 0 }
  end
end

# 240. Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'
control 'win2022-disable-network-connectivity-standby-battery' do
  title "Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'"
  desc "Verify that 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('AllowNetworkConnectivityStandbyBattery') { should eq 0 }
  end
end

# 241. Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'
control 'win2022-disable-network-connectivity-standby-plugged-in' do
  title "Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'"
  desc "Verify that 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('AllowNetworkConnectivityStandbyPluggedIn') { should eq 0 }
  end
end

# 242. Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'
control 'win2022-require-password-wake-battery' do
  title "Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'"
  desc "Verify that 'Require a password when a computer wakes (on battery)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('RequirePasswordWakeBattery') { should eq 1 }
  end
end

# 243. Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'
control 'win2022-require-password-wake-plugged-in' do
  title "Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'"
  desc "Verify that 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('RequirePasswordWakePluggedIn') { should eq 1 }
  end
end

# 244. Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
control 'win2022-disable-offer-remote-assistance' do
  title "Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
  desc "Verify that 'Configure Offer Remote Assistance' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemoteAssistance') do
    its('OfferRemoteAssistance') { should eq 0 }
  end
end

# 245. Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
control 'win2022-disable-solicited-remote-assistance' do
  title "Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
  desc "Verify that 'Configure Solicited Remote Assistance' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemoteAssistance') do
    its('SolicitedRemoteAssistance') { should eq 0 }
  end
end

# 246. Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'
control 'win2022-enable-rpc-endpoint-authentication' do
  title "Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'"
  desc "Verify that 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RPC') do
    its('EnableEndpointMapperAuthentication') { should eq 1 }
  end
end

# 247. Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'
control 'win2022-restrict-unauthenticated-rpc-clients' do
  title "Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'"
  desc "Verify that 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RPC') do
    its('UnauthenticatedRPCClients') { should eq 'Authenticated' }
  end
end

# 248. Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'
control 'win2022-disable-msdt-interactive-communication' do
  title "Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'"
  desc "Verify that 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\MSDT') do
    its('InteractiveCommunication') { should eq 0 }
  end
end

# 249. Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'
control 'win2022-disable-perftrack' do
  title "Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'"
  desc "Verify that 'Enable/Disable PerfTrack' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PerfTrack') do
    its('EnablePerfTrack') { should eq 0 }
  end
end

# 250. Ensure 'Turn off the advertising ID' is set to 'Enabled'
control 'win2022-disable-advertising-id' do
  title "Ensure 'Turn off the advertising ID' is set to 'Enabled'"
  desc "Verify that 'Turn off the advertising ID' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AdvertisingInfo') do
    its('Disabled') { should eq 1 }
  end
end

# 251. Ensure 'Enable Windows NTP Client' is set to 'Enabled'
control 'win2022-enable-ntp-client' do
  title "Ensure 'Enable Windows NTP Client' is set to 'Enabled'"
  desc "Verify that 'Enable Windows NTP Client' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\Parameters') do
    its('NtpClientEnabled') { should eq 1 }
  end
end

# 252. Ensure 'Enable Windows NTP Server' is set to 'Disabled'
control 'win2022-disable-ntp-server' do
  title "Ensure 'Enable Windows NTP Server' is set to 'Disabled'"
  desc "Verify that 'Enable Windows NTP Server' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\Parameters') do
    its('NtpServerEnabled') { should eq 0 }
  end
end

# 253. Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'
control 'win2022-disable-app-data-sharing' do
  title "Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'"
  desc "Verify that 'Allow a Windows app to share application data between users' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy') do
    its('SharedAppData') { should eq 0 }
  end
end

# 254. Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
control 'win2022-allow-microsoft-accounts-optional' do
  title "Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
  desc "Verify that 'Allow Microsoft accounts to be optional' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('AllowMicrosoftAccountsOptional') { should eq 1 }
  end
end

# 255. Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
control 'win2022-disallow-autoplay-non-volume-devices' do
  title "Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
  desc "Verify that 'Disallow Autoplay for non-volume devices' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoAutoplayNonVolume') { should eq 1 }
  end
end

# 256. Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
control 'win2022-set-default-autorun-behavior' do
  title "Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'"
  desc "Verify that 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('AutorunBehavior') { should eq 0 }
  end
end

# 257. Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
control 'win2022-turn-off-autoplay' do
  title "Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'"
  desc "Verify that 'Turn off Autoplay' is set to 'Enabled: All drives'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoDriveTypeAutoRun') { should eq 255 }
  end
end

# 258. Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'
control 'win2022-configure-anti-spoofing' do
  title "Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'"
  desc "Verify that 'Configure enhanced anti-spoofing' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('EnhancedAntiSpoofing') { should eq 1 }
  end
end

# 259. Ensure 'Allow Use of Camera' is set to 'Disabled'
control 'win2022-disable-camera-use' do
  title "Ensure 'Allow Use of Camera' is set to 'Disabled'"
  desc "Verify that 'Allow Use of Camera' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Camera') do
    its('AllowCamera') { should eq 0 }
  end
end

# 260. Ensure 'Turn off cloud consumer account state content' is set to 'Enabled'
control 'win2022-turn-off-cloud-account-content' do
  title "Ensure 'Turn off cloud consumer account state content' is set to 'Enabled'"
  desc "Verify that 'Turn off cloud consumer account state content' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableCloudAccountStateContent') { should eq 1 }
  end
end

# 261. Ensure 'Turn off cloud optimized content' is set to 'Enabled'
control 'win2022-turn-off-cloud-optimized-content' do
  title "Ensure 'Turn off cloud optimized content' is set to 'Enabled'"
  desc "Verify that 'Turn off cloud optimized content' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableCloudOptimizedContent') { should eq 1 }
  end
end

# 262. Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'
control 'win2022-turn-off-consumer-experiences' do
  title "Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
  desc "Verify that 'Turn off Microsoft consumer experiences' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableConsumerExperiences') { should eq 1 }
  end
end

# 263. Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'
control 'win2022-require-pin-pairing' do
  title "Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'"
  desc "Verify that 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('RequirePinForPairing') { should eq 'FirstTime' }
  end
end

# 264. Ensure 'Do not display the password reveal button' is set to 'Enabled'
control 'win2022-disable-password-reveal-button' do
  title "Ensure 'Do not display the password reveal button' is set to 'Enabled'"
  desc "Verify that 'Do not display the password reveal button' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DisablePasswordReveal') { should eq 1 }
  end
end

# 265. Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
control 'win2022-disable-enumerate-admin-accounts' do
  title "Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
  desc "Verify that 'Enumerate administrator accounts on elevation' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('EnumerateAdminAccounts') { should eq 0 }
  end
end

# 266. Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'
control 'win2022-allow-diagnostic-data' do
  title "Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'"
  desc "Verify that 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection') do
    its('AllowDiagnosticData') { should eq 'Required' }
  end
end

# 267. Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'
control 'win2022-disable-authenticated-proxy-usage' do
  title "Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'"
  desc "Verify that 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection') do
    its('DisableAuthenticatedProxyUsage') { should eq 1 }
  end
end

# 268. Ensure 'Disable OneSettings Downloads' is set to 'Enabled'
control 'win2022-disable-onesettings-downloads' do
  title "Ensure 'Disable OneSettings Downloads' is set to 'Enabled'"
  desc "Verify that 'Disable OneSettings Downloads' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\OneSettings') do
    its('DisableDownloads') { should eq 1 }
  end
end

# 269. Ensure 'Do not show feedback notifications' is set to 'Enabled'
control 'win2022-disable-feedback-notifications' do
  title "Ensure 'Do not show feedback notifications' is set to 'Enabled'"
  desc "Verify that 'Do not show feedback notifications' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Feedback') do
    its('DisableNotifications') { should eq 1 }
  end
end

# 270. Ensure 'Enable OneSettings Auditing' is set to 'Enabled'
control 'win2022-enable-onesettings-auditing' do
  title "Ensure 'Enable OneSettings Auditing' is set to 'Enabled'"
  desc "Verify that 'Enable OneSettings Auditing' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\OneSettings') do
    its('EnableAuditing') { should eq 1 }
  end
end

# 271. Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled'
control 'win2022-limit-diagnostic-log-collection' do
  title "Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled'"
  desc "Verify that 'Limit Diagnostic Log Collection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection') do
    its('LimitDiagnosticLogCollection') { should eq 1 }
  end
end

# 272. Ensure 'Limit Dump Collection' is set to 'Enabled'
control 'win2022-limit-dump-collection' do
  title "Ensure 'Limit Dump Collection' is set to 'Enabled'"
  desc "Verify that 'Limit Dump Collection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection') do
    its('LimitDumpCollection') { should eq 1 }
  end
end

# 273. Ensure 'Toggle user control over Insider builds' is set to 'Disabled'
control 'win2022-disable-insider-builds' do
  title "Ensure 'Toggle user control over Insider builds' is set to 'Disabled'"
  desc "Verify that 'Toggle user control over Insider builds' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PreviewBuilds') do
    its('AllowBuildPreview') { should eq 0 }
  end
end

# 274. Ensure 'Enable App Installer' is set to 'Disabled'
control 'win2022-disable-app-installer' do
  title "Ensure 'Enable App Installer' is set to 'Disabled'"
  desc "Verify that 'Enable App Installer' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Appx') do
    its('EnableAppInstaller') { should eq 0 }
  end
end

# 275. Ensure 'Enable App Installer Experimental Features' is set to 'Disabled'
control 'win2022-disable-app-installer-experimental-features' do
  title "Ensure 'Enable App Installer Experimental Features' is set to 'Disabled'"
  desc "Verify that 'Enable App Installer Experimental Features' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Appx') do
    its('EnableExperimentalFeatures') { should eq 0 }
  end
end

# 276. Ensure 'Enable App Installer Hash Override' is set to 'Disabled'
control 'win2022-disable-app-installer-hash-override' do
  title "Ensure 'Enable App Installer Hash Override' is set to 'Disabled'"
  desc "Verify that 'Enable App Installer Hash Override' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Appx') do
    its('EnableHashOverride') { should eq 0 }
  end
end

# 277. Ensure 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled'
control 'win2022-disable-app-installer-protocol' do
  title "Ensure 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled'"
  desc "Verify that 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Appx') do
    its('EnableProtocol') { should eq 0 }
  end
end

# 278. Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
control 'win2022-disable-application-event-log-behavior' do
  title "Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc "Verify that 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application') do
    its('Retention') { should eq 0 }
  end
end

# 279. Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
control 'win2022-application-log-file-size' do
  title "Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc "Verify that 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application') do
    its('MaxSize') { should be >= 32768 }
  end
end

# 280. Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
control 'win2022-disable-security-event-log-behavior' do
  title "Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc "Verify that 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security') do
    its('Retention') { should eq 0 }
  end
end

# 281. Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
control 'win2022-security-log-file-size' do
  title "Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'"
  desc "Verify that 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security') do
    its('MaxSize') { should be >= 196608 }
  end
end

# 282. Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
control 'win2022-disable-setup-event-log-behavior' do
  title "Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc "Verify that 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup') do
    its('Retention') { should eq 0 }
  end
end

# 283. Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
control 'win2022-setup-log-file-size' do
  title "Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc "Verify that 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup') do
    its('MaxSize') { should be >= 32768 }
  end
end

# 284. Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
control 'win2022-disable-system-event-log-behavior' do
  title "Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc "Verify that 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System') do
    its('Retention') { should eq 0 }
  end
end

# 285. Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
control 'win2022-system-log-file-size' do
  title "Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc "Verify that 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System') do
    its('MaxSize') { should be >= 32768 }
  end
end

# 286. Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
control 'win2022-disable-dep-explorer' do
  title "Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"
  desc "Verify that 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('DisableDEP') { should eq 0 }
  end
end

# 287. Ensure 'Turn off heap termination on corruption' is set to 'Disabled'
control 'win2022-disable-heap-termination' do
  title "Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"
  desc "Verify that 'Turn off heap termination on corruption' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('DisableHeapTermination') { should eq 0 }
  end
end

# 288. Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'
control 'win2022-disable-shell-protocol-protected-mode' do
  title "Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'"
  desc "Verify that 'Turn off shell protocol protected mode' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer') do
    its('DisableShellProtocolProtectedMode') { should eq 0 }
  end
end

# 289. Ensure 'Turn off location' is set to 'Enabled'
control 'win2022-disable-location' do
  title "Ensure 'Turn off location' is set to 'Enabled'"
  desc "Verify that 'Turn off location' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors') do
    its('DisableLocation') { should eq 1 }
  end
end

# 290. Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'
control 'win2022-disable-message-service-cloud-sync' do
  title "Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'"
  desc "Verify that 'Allow Message Service Cloud Sync' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Messaging') do
    its('AllowCloudSync') { should eq 0 }
  end
end

# 291. Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'
control 'win2022-block-microsoft-account-authentication' do
  title "Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'"
  desc "Verify that 'Block all consumer Microsoft account user authentication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('BlockMicrosoftAccount') { should eq 1 }
  end
end

# 292. Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'
control 'win2022-disable-onedrive' do
  title "Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'"
  desc "Verify that 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\OneDrive') do
    its('DisableFileSync') { should eq 1 }
  end
end

# 293. Ensure 'Turn off Push To Install service' is set to 'Enabled'
control 'win2022-disable-push-to-install' do
  title "Ensure 'Turn off Push To Install service' is set to 'Enabled'"
  desc "Verify that 'Turn off Push To Install service' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PushToInstall') do
    its('DisablePushToInstall') { should eq 1 }
  end
end

# 294. Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
control 'win2022-disable-password-saving' do
  title "Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
  desc "Verify that 'Do not allow passwords to be saved' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Credentials') do
    its('DisablePasswordSaving') { should eq 1 }
  end
end

# 295. Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'
control 'win2022-restrict-rds-single-session' do
  title "Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'"
  desc "Verify that 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('RestrictSingleSession') { should eq 1 }
  end
end

# 296. Ensure 'Allow UI Automation redirection' is set to 'Disabled'
control 'win2022-disable-ui-automation-redirection' do
  title "Ensure 'Allow UI Automation redirection' is set to 'Disabled'"
  desc "Verify that 'Allow UI Automation redirection' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('AllowUIAutomationRedirection') { should eq 0 }
  end
end

# 297. Ensure 'Do not allow COM port redirection' is set to 'Enabled'
control 'win2022-disable-com-port-redirection' do
  title "Ensure 'Do not allow COM port redirection' is set to 'Enabled'"
  desc "Verify that 'Do not allow COM port redirection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('DisableCOMPortRedirection') { should eq 1 }
  end
end

# 298. Ensure 'Do not allow drive redirection' is set to 'Enabled'
control 'win2022-disable-drive-redirection' do
  title "Ensure 'Do not allow drive redirection' is set to 'Enabled'"
  desc "Verify that 'Do not allow drive redirection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('DisableDriveRedirection') { should eq 1 }
  end
end

# 299. Ensure 'Do not allow location redirection' is set to 'Enabled'
control 'win2022-disable-location-redirection' do
  title "Ensure 'Do not allow location redirection' is set to 'Enabled'"
  desc "Verify that 'Do not allow location redirection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('DisableLocationRedirection') { should eq 1 }
  end
end

# 300. Ensure 'Do not allow LPT port redirection' is set to 'Enabled'
control 'win2022-disable-lpt-port-redirection' do
  title "Ensure 'Do not allow LPT port redirection' is set to 'Enabled'"
  desc "Verify that 'Do not allow LPT port redirection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('DisableLPTPortRedirection') { should eq 1 }
  end
end

# 301. Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'
control 'win2022-disable-pnp-device-redirection' do
  title "Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'"
  desc "Verify that 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('DisablePnPDeviceRedirection') { should eq 1 }
  end
end

# 302. Ensure 'Do not allow WebAuthn redirection' is set to 'Enabled'
control 'win2022-disable-webauthn-redirection' do
  title "Ensure 'Do not allow WebAuthn redirection' is set to 'Enabled'"
  desc "Verify that 'Do not allow WebAuthn redirection' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('DisableWebAuthnRedirection') { should eq 1 }
  end
end

# 303. Ensure 'Require secure RPC communication' is set to 'Enabled'
control 'win2022-require-secure-rpc' do
  title "Ensure 'Require secure RPC communication' is set to 'Enabled'"
  desc "Verify that 'Require secure RPC communication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('RequireSecureRPC') { should eq 1 }
  end
end

# 304. Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'
control 'win2022-require-security-layer-rdp' do
  title "Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'"
  desc "Verify that 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('SecurityLayer') { should eq 2 }
  end
end

# 305. Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'
control 'win2022-require-nla-authentication' do
  title "Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'"
  desc "Verify that 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('UserAuthentication') { should eq 1 }
  end
end

# 306. Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
control 'win2022-set-client-encryption-level' do
  title "Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
  desc "Verify that 'Set client connection encryption level' is set to 'Enabled: High Level'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('EncryptionLevel') { should eq 3 }
  end
end

# 307. Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less, but not Never (0)'
control 'win2022-set-idle-session-time-limit' do
  title "Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less, but not Never (0)'"
  desc "Verify that 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less, but not Never (0)'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('IdleTimeout') { should be <= 900 }
    its('IdleTimeout') { should_not eq 0 }
  end
end

# 308. Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
control 'win2022-disable-delete-temp-folders' do
  title "Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'"
  desc "Verify that 'Do not delete temp folders upon exit' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('DeleteTempFoldersUponExit') { should eq 0 }
  end
end

# 309. Ensure 'Do not use temporary folders per session' is set to 'Disabled'
control 'win2022-disable-temp-folders-per-session' do
  title "Ensure 'Do not use temporary folders per session' is set to 'Disabled'"
  desc "Verify that 'Do not use temporary folders per session' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('UseTempFoldersPerSession') { should eq 0 }
  end
end

# 310. Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
control 'win2022-prevent-download-enclosures' do
  title "Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"
  desc "Verify that 'Prevent downloading of enclosures' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Terminal Services') do
    its('PreventDownloadEnclosures') { should eq 1 }
  end
end

# 311. Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'
control 'win2022-disable-cloud-search' do
  title "Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'"
  desc "Verify that 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Search') do
    its('AllowCloudSearch') { should eq 0 }
  end
end

# 312. Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
control 'win2022-disable-indexing-encrypted-files' do
  title "Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
  desc "Verify that 'Allow indexing of encrypted files' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Search') do
    its('AllowIndexingEncryptedFiles') { should eq 0 }
  end
end

# 313. Ensure 'Allow search highlights' is set to 'Disabled'
control 'win2022-disable-search-highlights' do
  title "Ensure 'Allow search highlights' is set to 'Disabled'"
  desc "Verify that 'Allow search highlights' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Search') do
    its('AllowSearchHighlights') { should eq 0 }
  end
end

# 314. Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'
control 'win2022-disable-kms-client-avs-validation' do
  title "Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'"
  desc "Verify that 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\KMSClient') do
    its('DisableAVSValidation') { should eq 1 }
  end
end

# 315. Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'
control 'win2022-disable-suggested-apps-ink-workspace' do
  title "Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'"
  desc "Verify that 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\InkWorkspace') do
    its('AllowSuggestedApps') { should eq 0 }
  end
end

# 316. Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Enabled: Disabled'
control 'win2022-allow-ink-workspace' do
  title "Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Enabled: Disabled'"
  desc "Verify that 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Enabled: Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\InkWorkspace') do
    its('AllowWindowsInkWorkspace') { should eq 0 }
  end
end

# 317. Ensure 'Allow user control over installs' is set to 'Disabled'
control 'win2022-disable-user-control-installs' do
  title "Ensure 'Allow user control over installs' is set to 'Disabled'"
  desc "Verify that 'Allow user control over installs' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer') do
    its('EnableUserControl') { should eq 0 }
  end
end

# 318. Ensure 'Always install with elevated privileges' is set to 'Disabled'
control 'win2022-disable-elevated-privileges-installs' do
  title "Ensure 'Always install with elevated privileges' is set to 'Disabled'"
  desc "Verify that 'Always install with elevated privileges' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer') do
    its('AlwaysInstallElevated') { should eq 0 }
  end
end

# 319. Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'
control 'win2022-disable-ie-security-prompt-installer-scripts' do
  title "Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'"
  desc "Verify that 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer') do
    its('DisableIEInstallerPrompt') { should eq 0 }
  end
end

# 320. Ensure 'Enable MPR notifications for the system' is set to 'Disabled'
control 'win2022-disable-mpr-notifications' do
  title "Ensure 'Enable MPR notifications for the system' is set to 'Disabled'"
  desc "Verify that 'Enable MPR notifications for the system' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('EnableMPRNotifications') { should eq 0 }
  end
end

# 321. Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'
control 'win2022-disable-auto-sign-in-restart' do
  title "Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'"
  desc "Verify that 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
    its('DisableAutomaticRestartSignOn') { should eq 1 }
  end
end

# 322. Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'
control 'win2022-enable-powershell-script-block-logging' do
  title "Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'"
  desc "Verify that 'Turn on PowerShell Script Block Logging' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging') do
    its('EnableScriptBlockLogging') { should eq 1 }
  end
end

# 323. Ensure 'Turn on PowerShell Transcription' is set to 'Enabled'
control 'win2022-enable-powershell-transcription' do
  title "Ensure 'Turn on PowerShell Transcription' is set to 'Enabled'"
  desc "Verify that 'Turn on PowerShell Transcription' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Transcription') do
    its('EnableTranscription') { should eq 1 }
  end
end

# 324. Ensure 'Allow Basic authentication' is set to 'Disabled'
control 'win2022-disable-basic-authentication' do
  title "Ensure 'Allow Basic authentication' is set to 'Disabled'"
  desc "Verify that 'Allow Basic authentication' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service') do
    its('AllowBasic') { should eq 0 }
  end
end

# 325. Ensure 'Allow unencrypted traffic' is set to 'Disabled'
control 'win2022-disable-unencrypted-traffic' do
  title "Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
  desc "Verify that 'Allow unencrypted traffic' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service') do
    its('AllowUnencryptedTraffic') { should eq 0 }
  end
end

# 326. Ensure 'Disallow Digest authentication' is set to 'Enabled'
control 'win2022-disable-digest-authentication' do
  title "Ensure 'Disallow Digest authentication' is set to 'Enabled'"
  desc "Verify that 'Disallow Digest authentication' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service') do
    its('DisableDigest') { should eq 1 }
  end
end

# 327. Ensure 'Allow Basic authentication' is set to 'Disabled'
control 'win2022-disable-basic-authentication' do
  title "Ensure 'Allow Basic authentication' is set to 'Disabled'"
  desc "Verify that 'Allow Basic authentication' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service') do
    its('AllowBasic') { should eq 0 }
  end
end

# 328. Ensure 'Allow remote server management through WinRM' is set to 'Disabled'
control 'win2022-disable-remote-server-management' do
  title "Ensure 'Allow remote server management through WinRM' is set to 'Disabled'"
  desc "Verify that 'Allow remote server management through WinRM' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service') do
    its('AllowRemoteServerManagement') { should eq 0 }
  end
end

# 329. Ensure 'Allow unencrypted traffic' is set to 'Disabled'
control 'win2022-disable-unencrypted-traffic' do
  title "Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
  desc "Verify that 'Allow unencrypted traffic' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service') do
    its('AllowUnencryptedTraffic') { should eq 0 }
  end
end

# 330. Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
control 'win2022-disable-winrm-runas-credentials' do
  title "Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"
  desc "Verify that 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service') do
    its('DisableRunAs') { should eq 1 }
  end
end

# 331. Ensure 'Allow Remote Shell Access' is set to 'Disabled'
control 'win2022-disable-remote-shell-access' do
  title "Ensure 'Allow Remote Shell Access' is set to 'Disabled'"
  desc "Verify that 'Allow Remote Shell Access' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service') do
    its('AllowRemoteShellAccess') { should eq 0 }
  end
end

# 332. Ensure 'Configure Automatic Updates' is set to 'Enabled'
control 'win2022-enable-automatic-updates' do
  title "Ensure 'Configure Automatic Updates' is set to 'Enabled'"
  desc "Verify that 'Configure Automatic Updates' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU') do
    its('NoAutoUpdate') { should eq 0 }
  end
end

# 333. Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'
control 'win2022-configure-automatic-updates-day' do
  title "Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'"
  desc "Verify that 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU') do
    its('ScheduledInstallDay') { should eq 0 }
  end
end

# 334. Ensure 'Manage preview builds' is set to 'Disabled'
control 'win2022-disable-preview-builds' do
  title "Ensure 'Manage preview builds' is set to 'Disabled'"
  desc "Verify that 'Manage preview builds' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PreviewBuilds') do
    its('ManagePreviewBuilds') { should eq 0 }
  end
end

# 335. Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days'
control 'win2022-select-preview-builds-feature-updates' do
  title "Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days'"
  desc "Verify that 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PreviewBuilds') do
    its('FeatureUpdateDeferralDays') { should be >= 180 }
  end
end

# 336. Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'
control 'win2022-select-quality-updates' do
  title "Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'"
  desc "Verify that 'Select when Quality Updates are received' is set to 'Enabled: 0 days'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PreviewBuilds') do
    its('QualityUpdateDeferralDays') { should eq 0 }
  end
end

# 337. Ensure 'Enable screen saver' is set to 'Enabled'
control 'win2022-enable-screen-saver' do
  title "Ensure 'Enable screen saver' is set to 'Enabled'"
  desc "Verify that 'Enable screen saver' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop') do
    its('ScreenSaveActive') { should eq "1" }
  end
end

# 338. Ensure 'Password protect the screen saver' is set to 'Enabled'
control 'win2022-password-protect-screen-saver' do
  title "Ensure 'Password protect the screen saver' is set to 'Enabled'"
  desc "Verify that 'Password protect the screen saver' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop') do
    its('ScreenSaverIsSecure') { should eq "1" }
  end
end

# 339. Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'
control 'win2022-screen-saver-timeout' do
  title "Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'"
  desc "Verify that 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'."
  impact 1.0
  describe registry_key('HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop') do
    its('ScreenSaveTimeOut') { should be <= 900 }
    its('ScreenSaveTimeOut') { should_not eq 0 }
  end
end

# 340. Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'
control 'win2022-disable-toast-notifications-lock-screen' do
  title "Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'"
  desc "Verify that 'Turn off toast notifications on the lock screen' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications') do
    its('NoToastApplicationNotification') { should eq 1 }
  end
end

# 341. Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'
control 'win2022-disable-help-experience-improvement' do
  title "Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'"
  desc "Verify that 'Turn off Help Experience Improvement Program' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HelpExperience') do
    its('DisableHelpExperienceImprovement') { should eq 1 }
  end
end

# 342. Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'
control 'win2022-preserve-zone-info-file-attachments' do
  title "Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'"
  desc "Verify that 'Do not preserve zone information in file attachments' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Attachments') do
    its('SaveZoneInformation') { should eq 1 }
  end
end

# 343. Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'
control 'win2022-notify-antivirus-opening-attachments' do
  title "Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'"
  desc "Verify that 'Notify antivirus programs when opening attachments' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Attachments') do
    its('ScanWithAntivirus') { should eq 1 }
  end
end

# 344. Ensure 'Configure Windows spotlight on lock screen' is set to 'Disabled'
control 'win2022-disable-windows-spotlight-lock-screen' do
  title "Ensure 'Configure Windows spotlight on lock screen' is set to 'Disabled'"
  desc "Verify that 'Configure Windows spotlight on lock screen' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableWindowsSpotlightOnLockScreen') { should eq 1 }
  end
end

# 345. Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'
control 'win2022-disable-third-party-content-spotlight' do
  title "Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'"
  desc "Verify that 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableThirdPartyContent') { should eq 1 }
  end
end

# 346. Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'
control 'win2022-disable-diagnostic-data-tailored-experiences' do
  title "Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'"
  desc "Verify that 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableTailoredExperiencesWithDiagnosticData') { should eq 1 }
  end
end

# 347. Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'
control 'win2022-disable-all-spotlight-features' do
  title "Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'"
  desc "Verify that 'Turn off all Windows spotlight features' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableWindowsSpotlightFeatures') { should eq 1 }
  end
end

# 348. Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled'
control 'win2022-disable-spotlight-collection-desktop' do
  title "Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled'"
  desc "Verify that 'Turn off Spotlight collection on Desktop' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
    its('DisableSpotlightCollectionDesktop') { should eq 1 }
  end
end

# 349. Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'
control 'win2022-prevent-file-sharing-profile' do
  title "Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'"
  desc "Verify that 'Prevent users from sharing files within their profile.' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Sharing') do
    its('PreventFileSharing') { should eq 1 }
  end
end

# 350. Ensure 'Always install with elevated privileges' is set to 'Disabled'
control 'win2022-disable-elevated-privileges-installs' do
  title "Ensure 'Always install with elevated privileges' is set to 'Disabled'"
  desc "Verify that 'Always install with elevated privileges' is set to 'Disabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer') do
    its('AlwaysInstallElevated') { should eq 0 }
  end
end

# 351. Ensure 'Prevent Codec Download' is set to 'Enabled'
control 'win2022-prevent-codec-download' do
  title "Ensure 'Prevent Codec Download' is set to 'Enabled'"
  desc "Verify that 'Prevent Codec Download' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\MediaPlayer') do
    its('PreventCodecDownload') { should eq 1 }
  end
end

# 352. Antivirus software is not installed
control 'win2022-antivirus-installed' do
  title "Antivirus software is not installed"
  desc "Verify that antivirus software is installed and actively protecting the system."
  impact 1.0
  describe service('AntivirusService') do
    it { should be_installed }
    it { should be_running }
  end
end

# 353. Ensure to turn on Module Logging
control 'win2022-module-logging' do
  title "Ensure to turn on Module Logging"
  desc "Verify that Module Logging is enabled to capture PowerShell activity."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging') do
    its('EnableModuleLogging') { should eq 1 }
  end
end

# 354. Ensure active User ID's which were not logged in for more than 90 days or never is to be disabled
control 'win2022-disable-inactive-user-ids' do
  title "Ensure active User ID's which were not logged in for more than 90 days or never is to be disabled"
  desc "Verify that inactive user IDs are disabled to reduce security risks."
  impact 1.0
  describe user('InactiveUser') do
    it { should_not exist }
  end
end

# 355. Ensure no Users are present in Administrator group except Profiles ID
control 'win2022-admin-group-restrictions' do
  title "Ensure no Users are present in Administrator group except Profiles ID"
  desc "Verify that restrictions on the administrator group are enforced."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RestrictedGroups') do
    its('AdminGroupRestrictions') { should eq 1 }
  end
end

# 356. Ensure System Files are not having write permissions to Everyone
control 'win2022-file-permissions' do
  title "Ensure System Files are not having write permissions to Everyone"
  desc "Verify that file permissions are set to prevent unauthorized access."
  impact 1.0
  describe file('C:\Windows\System32\important_file.txt') do
    its('owner') { should eq 'Administrator' }
    its('group') { should eq 'Administrators' }
    it { should_not be_writable.by('Everyone') }
  end
end

# 357. Ensure 'Configure security policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
control 'win2022-security-policy-background-processing' do
  title "Ensure 'Configure security policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"
  desc "Verify that 'Configure security policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\GroupPolicy') do
    its('DisableBackgroundProcessing') { should eq 0 }
  end
end

# 358. Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
control 'win2022-registry-policy-process-unchanged' do
  title "Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
  desc "Verify that 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\GroupPolicy') do
    its('ProcessEvenIfUnchanged') { should eq 1 }
  end
end

# 359. Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'
control 'win2022-ntlm-audit-incoming' do
  title "Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'"
  desc "Verify that 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('AuditIncomingNTLM') { should eq 1 }
  end
end

# 360. Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher
control 'win2022-ntlm-audit-outgoing' do
  title "Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher"
  desc "Verify that 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('AuditOutgoingNTLM') { should eq 1 }
  end
end

# 361. Ensure 'Enable Certificate Padding' is set to 'Enabled'
control 'win2022-certificate-padding' do
  title "Ensure 'Enable Certificate Padding' is set to 'Enabled'"
  desc "Verify that 'Enable Certificate Padding' is set to 'Enabled'."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Cryptography') do
    its('EnableCertificatePadding') { should eq 1 }
  end
end

# 362. Disable Automounting
control 'win2022-disable-automounting' do
  title "Disable Automounting"
  desc "Verify that Automounting is disabled to prevent unauthorized access to external drives."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MountMgr') do
    its('NoAutoMount') { should eq 1 }
  end
end

# 363. Disable USB Storage
control 'win2022-disable-usb-storage' do
  title "Disable USB Storage"
  desc "Verify that USB Storage is disabled to prevent unauthorized data transfers."
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\USBSTOR') do
    its('Start') { should eq 4 }
  end
end


