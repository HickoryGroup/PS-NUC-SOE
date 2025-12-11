<#
.SYNOPSIS
Configure Intel NUC for management role based on provided standards.
Creates a transcript log and reboots after setup.
#>


# -------------------------------
# Start Transcript Logging
# -------------------------------
$ErrorActionPreference = 'SilentlyContinue'
$LogPath = ".\NUC_Setup_Log.txt"
Start-Transcript -Path $LogPath -Append

Install-Module -Name PSWindowsUpdate -Force
Import-Module PSWindowsUpdate

    # -------------------------------
    # 1. Naming Convention & Hostname
    # -------------------------------
    $SerialNumber = (Get-WmiObject Win32_BIOS).SerialNumber
    $NewHostname = "NUC-MGMT-$SerialNumber"
    Rename-Computer -NewName $NewHostname -Force

    # -------------------------------
    # 2. Network Configuration (DHCP)
    # -------------------------------
    Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Set-NetIPInterface -Dhcp Enabled

    # -------------------------------
    # 3. Time Configuration (NTP)
    # -------------------------------
    w32tm /config /manualpeerlist:"au.pool.ntp.org" /syncfromflags:manual /reliable:YES /update
    Restart-Service w32time

    # -------------------------------
    # 4. Firewall Configuration
    # -------------------------------
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    New-NetFirewallRule -DisplayName "Allow PRTG Probe" -Direction Inbound -Protocol TCP -LocalPort 23560 -Action Allow
    Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled False

    # -------------------------------
    # 5. Remote Access (TeamViewer)
    # -------------------------------
    


Write-Host "Installing TeamViewer..."
$NUCAlias = "NUC-$SerialNumber"
Start-Process msiexec.exe -Wait -NoNewWindow -ArgumentList "/i `"D:\TeamViewer_Host.msi`" /qn APITOKEN=20897627-2TdOP4FmMRSmUhY6VmDg CUSTOMCONFIGID=6pdx2k3 ASSIGNMENTOPTIONS=`"--grant-easy-access --alias $NewHostname`""



write-host "install sophos"
    # -------------------------------
    # 7. Software Baseline (Sophos AV)
    # -------------------------------
    Start-Process ".\SophosSetup.exe" -ArgumentList "--quiet" -Wait


write-host "setting windows patch"
    # -------------------------------
    # 8. Windows Updates & Patching
    # -------------------------------
    Set-Service -Name wuauserv -StartupType Automatic
    $TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "Install-WindowsUpdate -AcceptAll -AutoReboot"
    $TaskTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Saturday -At 23:00
    Register-ScheduledTask -TaskName "AutoPatch" -Action $TaskAction -Trigger $TaskTrigger -RunLevel Highest

    # -------------------------------
    # 9. Security Hardening
    # -------------------------------
    # Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -PasswordProtector
    # Confirm-SecureBootUEFI

write-host "setting auditlog"
    # -------------------------------
    # 10. Logging & Auditing
    # -------------------------------
    wevtutil sl Security /ms:838860800
    wevtutil sl System /ms:838860800
    wevtutil sl Application /ms:838860800

write-host "setting power settings"
    # -------------------------------
    # 11. Power Settings
    # -------------------------------
    powercfg -setactive SCHEME_MIN
    powercfg -hibernate off
    powercfg -change -standby-timeout-ac 0
    powercfg -change -monitor-timeout-ac 0
    Set-NetAdapterAdvancedProperty -Name "Ethernet" -DisplayName "Wake on Magic Packet" -DisplayValue "Enabled"

write-host "create reboot schedule"
    # -------------------------------
    # 12. Scheduled Weekly Reboot
    # -------------------------------
    $RebootAction = New-ScheduledTaskAction -Execute "shutdown.exe" -Argument "/r /t 0"
    $RebootTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 03:00
    Register-ScheduledTask -TaskName "WeeklyReboot" -Action $RebootAction -Trigger $RebootTrigger -RunLevel Highest

write-host "disable services"
    # -------------------------------
    # 13. Disable Unused Services
    # -------------------------------
    

    # List of services to disable
    $ServicesToDisable = @(
        "Spooler",              # Print Spooler
        "bthserv",              # Bluetooth Support
        "Fax",                  # Fax Service
        "WerSvc",               # Windows Error Reporting
        "TermService",          # Remote Desktop Services
        "fdPHost",              # Function Discovery Provider Host
        "FDResPub",             # Function Discovery Resource Publication
        "WMPNetworkSvc",        # Windows Media Player Network Sharing
        "XpsService",           # XPS Service
        "TabletInputService",   # Tablet PC Input
        "WaaSMedicSvc",         # Windows Update Medic
        "RemoteRegistry"        # Remote Registry
    )

    foreach ($svc in $ServicesToDisable) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Write-Host "Disabling service: $svc"
            Stop-Service -Name $svc -Force
            Set-Service -Name $svc -StartupType Disabled
        } else {
            Write-Host "Service $svc not found on this system."
        }
    }
    

write-host "uninstall bloatware"
    # -------------------------------
    # 14. Remove Bloatware
    # -------------------------------
    $AppsToRemove = @(
        "Microsoft.Office.Desktop","Microsoft.WindowsCamera","Microsoft.WindowsCalculator",
        "Microsoft.WindowsMail","Microsoft.ZuneMusic","Microsoft.OneDrive","Microsoft.Teams",
        "Microsoft.News","Microsoft.People","Microsoft.Photos","Microsoft.PowerAutomateDesktop",
        "Microsoft.MicrosoftSolitaireCollection","Microsoft.XboxApp","Microsoft.XboxGameOverlay",
        "Microsoft.XboxGamingOverlay","Microsoft.XboxIdentityProvider","Microsoft.WindowsSoundRecorder",
        "Microsoft.MicrosoftStickyNotes", "Microsoft.OneDriveSync", "MSTeams", "Microsoft.Copilot",
        "Microsoft.BingWeather","Microsoft.BingNews","Microsoft.BingSearch","Microsoft.MicrosoftOfficeHub",
        "Microsoft.OutlookForWindows","Microsoft.WindowsStore"
        
    )
    foreach ($App in $AppsToRemove) {
        Get-AppxPackage -Name $App | Remove-AppxPackage
    }

    winget uninstall --id Microsoft.OneDrive --force --accept-source-agreements
    winget uninstall --id Microsoft.Office --force --accept-source-agreements --silent --disable-interactivity


write-host "disable windows hello"
    # -------------------------------
    # 15. Disabling windows hello
    # -------------------------------

Write-Host "Disabling Windows Hello and biometrics..." -ForegroundColor Yellow

# Disable Biometrics (Fingerprint, Face Recognition)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Value 0 -Type DWord -Force

# Disable Windows Hello for Business
$path = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"
if (!(Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
}
Set-ItemProperty -Path $path -Name "Enabled" -Value 0 -Type DWord -Force

# Optional: Disable convenience PIN sign-in
$pinPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (!(Test-Path $pinPath)) {
    New-Item -Path $pinPath -Force | Out-Null
}
Set-ItemProperty -Path $pinPath -Name "AllowDomainPINLogon" -Value 0 -Type DWord -Force

Write-Host "Windows Hello and biometric authentication have been disabled." -ForegroundColor Green
Write-Host

# Force Windows 11 to auto-lock after 900 seconds of inactivity
# using screen-saver policy settings that Windows 11 honors.

# Enable the screen saver and set the timeout to 900 seconds
Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive -Value '1'
Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name ScreenSaveTimeOut -Value '900'

# Require password on resume (lock workstation)
Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure -Value '1'

# Use the blank screen saver (ships with Windows)
Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name SCRNSAVE.EXE -Value 'C:\Windows\System32\scrnsave.scr'

# Also configure the same via Group Policy registry keys (Windows 11 respects these)
$polPath = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
If (-not (Test-Path $polPath)) { New-Item -Path $polPath -Force | Out-Null }
Set-ItemProperty $polPath -Name ScreenSaveActive -Value '1'
Set-ItemProperty $polPath -Name ScreenSaverIsSecure -Value '1'
Set-ItemProperty $polPath -Name ScreenSaveTimeOut -Value '900'
Set-ItemProperty $polPath -Name SCRNSAVE.EXE -Value 'C:\Windows\System32\scrnsave.scr'

# Force policy reload
RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
Write-Host "Auto-lock after 900 seconds configured. Please sign out/in or run 'gpupdate /target:user /force' to apply."



    Stop-Transcript


# -------------------------------
# Final Reboot
# -------------------------------
Restart-Computer -Force
``