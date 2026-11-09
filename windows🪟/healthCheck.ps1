# Define the report file path
$reportFile = "C:\Users\loop\Desktop\SecurityHealthCheckReport.txt"

# Initialize the report
$report = "Security Health Check Report - $(Get-Date)"
$report | Out-File -FilePath $reportFile

# Function to get Admin Users
function Get-AdminUsers {
    "--------------------" | Out-File -Append -FilePath $reportFile
    "1. Admin Users:" | Out-File -Append -FilePath $reportFile
    Get-LocalGroupMember -Group "Administrators" | 
    Select-Object Name, PrincipalSource | 
    ForEach-Object { $_.Name } | 
    Out-File -Append -FilePath $reportFile
}

# Function to get Running Processes
function Get-RunningProcesses {
    "--------------------" | Out-File -Append -FilePath $reportFile
    "2. Running Processes:" | Out-File -Append -FilePath $reportFile
    Get-Process | 
    Select-Object Name, Id, CPU, StartTime | 
    Out-File -Append -FilePath $reportFile
}

# Function to check Firewall Status
function Get-FirewallStatus {
    "--------------------" | Out-File -Append -FilePath $reportFile
    "3. Firewall Status:" | Out-File -Append -FilePath $reportFile
    Get-NetFirewallProfile | 
    Select-Object Name, Enabled | 
    ForEach-Object { "$($_.Name): Enabled=$($_.Enabled)" } | 
    Out-File -Append -FilePath $reportFile
}

# Function to check Windows Update Status
function Get-UpdateStatus {
    "--------------------" | Out-File -Append -FilePath $reportFile
    "4. Windows Update Status:" | Out-File -Append -FilePath $reportFile
    Get-HotFix | 
    Select-Object InstalledOn, Description | 
    Sort-Object InstalledOn -Descending | 
    Select-Object -First 5 | 
    Out-File -Append -FilePath $reportFile
}

# Function to get Windows Defender Status
function Get-DefenderStatus {
    "--------------------" | Out-File -Append -FilePath $reportFile
    "5. Windows Defender Status:" | Out-File -Append -FilePath $reportFile
    Get-MpComputerStatus | 
    Select-Object AMRunningMode, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, QuickScanEndTime | 
    Out-File -Append -FilePath $reportFile
}

# Function to get Recent Security Events
function Get-SecurityEvents {
    "--------------------" | Out-File -Append -FilePath $reportFile
    "6. Recent Security Events:" | Out-File -Append -FilePath $reportFile
    Get-WinEvent -LogName Security -MaxEvents 10 | 
    Select-Object TimeCreated, Id, Message | 
    Out-File -Append -FilePath $reportFile
}

# Function to check Password Policy
function Get-PasswordPolicy {
    "--------------------" | Out-File -Append -FilePath $reportFile
    "7. Password Policy:" | Out-File -Append -FilePath $reportFile

    # Run net accounts to get password policy details
    $passwordPolicy = net accounts

    # Output the results to the report
    $passwordPolicy | Out-File -Append -FilePath $reportFile
}

# Function to check Disk Encryption Status
function Get-BitLockerStatus {
    "--------------------" | Out-File -Append -FilePath $reportFile
    "8. Disk Encryption Status:" | Out-File -Append -FilePath $reportFile
    Get-BitLockerVolume | 
    Select-Object VolumeStatus, EncryptionMethod | 
    Out-File -Append -FilePath $reportFile
}

# Function to get Unused Services
function Get-UnusedServices {
    "--------------------" | Out-File -Append -FilePath $reportFile
    "9. Unused Services (Running but Disabled):" | Out-File -Append -FilePath $reportFile
    Get-Service | 
    Where-Object { $_.Status -eq 'Running' -and $_.StartType -eq 'Disabled' } | 
    Select-Object Name, Status | 
    Out-File -Append -FilePath $reportFile
}

function Show-Ports {
    "--------------------" | Out-File -Append -FilePath $reportFile
    "10. Open Ports:" | Out-File -Append -FilePath $reportFile
    netstat -an | 
    Select-String "LISTENING" | 
    ForEach-Object { $_.Line } | 
    Out-File -Append -FilePath $reportFile
    "--------------------" | Out-File -Append -FilePath $reportFile
    "11. Closed Ports:" | Out-File -Append -FilePath $reportFile
    netstat -an | 
    Select-String "CLOSE_WAIT" |
    ForEach-Object { $_.Line } | 
    Out-File -Append -FilePath $reportFile
}

# Execute all functions to generate the report
Get-AdminUsers
Get-RunningProcesses
Get-FirewallStatus
Get-UpdateStatus
Get-DefenderStatus
Get-SecurityEvents
Get-PasswordPolicy
Get-BitLockerStatus
Get-UnusedServices
Show-Ports

# Final output to complete the report
"--------------------" | Out-File -Append -FilePath $reportFile
"Security health check complete. Report saved to $reportFile" | Out-File -Append -FilePath $reportFile

Write-Host "Security Health Check complete. Report saved to $reportFile"