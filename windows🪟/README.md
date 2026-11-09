# Windows Hardening and Monitoring Scripts

### winrm\_disable.ps1
Disables WinRM. Make sure this is allowed on the system.

### winrm\_enable.ps1
Enables WinRM back on.

### remove\_descriptions.ps1
This script strips every user account of it's description.
Run with -WhatIf to see changes before running. 
Make sure this script complies with company policy before running.

### break\_glass.ps1
Unlocks all users. 
We will use this if we accidentally lock all but one user.

### healthCheck.ps1
Base code from [Windows-Security-Health-Check by A-rjun-saji](https://github.com/A-rjun-saji/Windows-Security-Health-Check).
Lists admin users, running processes, firewall status, update status, Windows Defender status, recent security events, password policy, disk encryption status, unused services, and open and closed ports. 

### optimal\_security.ps1
Sets AD password policy. 

### shield\_n\_restore.ps1
Makes a backup of the AD users.
We then check these users for very common passwords.
If personal identifiable information is discovered, it is removed from the user account. 
Check local domain privilages of users.
We will use this script to audit an domain machines. 

### WindowsManualMonitor.ps1
A script to help us monitor accessed users, update our Windows machines, check AD user permissions, and check for active connections.
The Windows update function is sourced from BYU's public CCDC repository
Sets up canaries in the script executee's desktop and documents directories, as well as the Windows temporary directory.
This will help us detect if attackers are modifying files or scanning for PII, monitoring with Windows Events.
It can also roll the Kerberos TGT user password to prevent repeated kerberostrating (it's inevitable).

### AD-Hardening.ps1
Script originally developed by BYU, modified to fit NCCDC 2026 ruleset. Use at the beginning of the competition to harden the AD system.
Performs firewall backup and configuration, disabling unnecessary services, enabling advanced auditing, SMB upgrades, Splunk installation and configuration, and patching of EternalBlue and Mimikatz.
Also detects OS version, logging of script completion and errors, and script error handling.

### advancedAuditing.ps1
Script developed by BYU. Use by the AD-Hardening script to enable advanced auditing on the AD.

### gpos.zip
Group Policy Objects developed by BYU. Secured GPOs to be used on AD, intended to be installed with Microsoft Security Compliance Toolkit (MSCT).

### patchURLs.json
JSON file is to be easily parsed by the AD-Hardening script developed by BYU. Contains Windows Update catalog download links.

### ports.json
JSON file is to be easily parsed by the AD-Hardening script developed by BYU. Contains common ports with their description, port number, status, and protocol type.
