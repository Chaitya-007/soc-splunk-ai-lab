# Run in an ELEVATED PowerShell on the Windows 10 lab VM (lab only).
# Enables the logging the detections need and creates a test account.

# 1. Logon auditing (4624 / 4625) and process creation (4688)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable   # scheduled tasks (4698)

# 2. Include command line in 4688 events
$auditKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $auditKey -Force | Out-Null
Set-ItemProperty -Path $auditKey -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# 3. PowerShell Script Block Logging (4104)
$psKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $psKey -Force | Out-Null
Set-ItemProperty -Path $psKey -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# 4. Allow SMB from the attacker VM (lab network only)
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes

# 5. Test account for brute-force scenarios (lab password only)
net user labuser "LabPass#2026" /add

Write-Host "Done. Install Sysmon next, then start Splunk." -ForegroundColor Green
