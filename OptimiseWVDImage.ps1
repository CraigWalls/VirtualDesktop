#region Introduction
<#
    Script Name:    OptimiseWVDImage.ps1
    Version:        0.02
    Date:           01 Jun 2021
    Author:         Craig Walls
    Email:          craig.walls@syntax.co.uk

    Parameters:
        None

    References:
        - https://github.com/The-Virtual-Desktop-Team/Virtual-Desktop-Optimization-Tool/blob/main/Win10_VirtualDesktop_Optimize.ps1
        - https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004

    Revision History:
        v0.01 - 25 May 2021 Craig Walls - First version
        v0.02 - 01 Jun 2021 Craig Walls - Updated default user section

.SYNOPSIS
This script will apply WVD optimisations in preparation for capturing a 'golden image' for production deployment.

.DESCRIPTION
This script optimises WVD by:
- removing unneeded UWP ('modern') applications
- remoing unwanted OS features
- removing unnecessary scheduled tasks
- disabling unneeded services
- disabling automatic updates
#>
#endregion

#region ScriptValues
<#
    Values that are used throughout the script
#>
$StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ScriptName = $MyInvocation.MyCommand.Name
$ScriptInfo = "$ScriptName - v0.02 - 01 Jun 2021"
$LogBreak = "+------------------------------------------------------------------------------+"
$LogDir = Join-Path -Path $env:ProgramData -ChildPath "CAF"
$LogFile = "$($ScriptName.SubString(0, $ScriptName.LastIndexOf('.'))).log"
$AppXPackages = @(
    "Microsoft.BingWeather",
    "Microsoft.GetHelp",
    "Microsoft.GetStarted",
    "Microsoft.Messaging",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MicrosoftStickyNotes",
    "Microsoft.MixedReality.Portal",
    "Microsoft.MSPaint",
    "Microsoft.Office.OneNote"
    "Microsoft.OneConnect",
    "Microsoft.People",
    "Microsoft.Print3D",
    "Microsoft.ScreenSketch",
    "Microsoft.SkypeApp",
    "Microsoft.Wallet",
    "Microsoft.Windows.Photos",
    "Microsoft.WindowsAlarms",
    "Microsoft.WindowsCalculator",
    "Microsoft.WindowsCamera",
    "Microsoft.WindowsCommunicationsApps",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxApp",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.YourPhone",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo"
)
$LogConfigs = @(
    ("HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Cellcore\", "Start", "DWord", 0),
    ("HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOOBE\", "Start", "DWord", 0),
    ("HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog\", "Start", "DWord", 0),
    ("HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ReadyBoot\", "Start", "DWord", 0),
    ("HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WDIContextLog\", "Start", "DWord", 0),
    ("HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession\", "Start", "DWord", 0),
    ("HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\", "Start", "DWord", 0),
    ("HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WinPhoneCritical\", "Start", "DWord", 0)
)
$NetworkConfigs = @(
    ("HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\", "DirectoryCacheEntriesMax", "DWord", 1024),
    ("HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\", "DisableBandwidthThrottling", "DWord", 1),
    ("HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\", "DormantFileLimit", "DWord", 256),
    ("HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\", "FileInfoCacheEntriesMax", "DWord", 1024),
    ("HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\", "FileNotFoundCacheEntriesMax", "DWord", 1024)    
)
$ScheduledTasks = @(
    "AnalyzeSystem",
    "Cellular",
    "Consolidator",
    "Diagnostics",
    "FamilySafetyMonitor",
    "FamilySafetyRefreshTask",
    "MapsToastTask",
    "*Compatibility*",
    "Microsoft-Windows-DiskDiagnosticDataCollector",
    "*MNO*",
    "NotificationTask",
    "ProcessMemoryDiagnosticEvents",
    "Proxy",
    "QueueReporting",
    "RecommendedTroubleshootingScanner",
    "RegIdleBackup",
    "RunFullMemoryDiagnostic",
    "Scheduled",
    "ScheduledDefrag",
    "SilentCleanup",
    "SpeechModelDownloadTask",
    "Sqm-Tasks",
    "SR",
    "StartComponentCleanup",
    "StartupAppTask",
    "WindowsActionDialog",
    "WinSAT",
    "XblGameSaveTask"
)
$Services = @(
    "autotimesvc",
    "BcastDVRUserService",
    "defragsvc",
    "DiagSvc",
    "DiagTrack",
    "DPS",
    "DusmSvc",
    "icssvc",
    "lfsvc",
    "MapsBroker",
    "MessagingService",
    "OneSyncSvc",
    "PimIndexMaintenanceSvc",
    "Power",
    "SEMgrSvc",
    "SmsRouter",
    "SysMain",
    "TabletInputService",
    "VSS",
    "WdiSystemHost",
    "WerSvc",
    "XblAuthManager",
    "XblGameSave",
    "XboxGipSvc",
    "XboxNetApiSvc"
)
$UserConfigs = @(
    ("HKLM:\DefUser\Control Panel\Desktop", "DragFullWindows", "String","0"),
    ("HKLM:\DefUser\Control Panel\Desktop", "FontSmoothing", "String","2"),
    ("HKLM:\DefUser\Control Panel\Desktop", "UserPreferencesMask", "Binary",[byte[]]0x90,0x32,0x07,0x80,0x10,0x00,0x00,0x00),
    ("HKLM:\DefUser\Control Panel\Desktop\WindowMetrics", "MinAnimate", "String","0"),
    ("HKLM:\DefUser\Control Panel\International\User Profile", "httpAcceptLanguageOutput", "DWord",1),
    ("HKLM:\DefUser\Software\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", "DWord",1),
    ("HKLM:\DefUser\Software\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", "DWord",1),
    ("HKLM:\DefUser\Software\Microsoft\InputPersonalization\TrainedDataStore", "HarvestContacts", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Personalization\Settings", "AcceptedPrivacyPolicy", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.549981C3F5F10_8wekyb3d8bbwe", "Disabled", "DWord",1),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.549981C3F5F10_8wekyb3d8bbwe", "DisabledByUser", "DWord",1),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftEdge_8wekyb3d8bbwe", "Disabled", "DWord",1),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftEdge_8wekyb3d8bbwe", "DisabledByUser", "DWord",1),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.SkypeApp_kzf8qxf38zg5c", "Disabled", "DWord",1),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.SkypeApp_kzf8qxf38zg5c", "DisabledByUser", "DWord",1),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe", "Disabled", "DWord",1),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe", "DisabledByUser", "DWord",1),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_8wekyb3d8bbwe", "Disabled", "DWord",1),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_8wekyb3d8bbwe", "DisabledByUser", "DWord",1),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338388Enabled", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338389Enabled", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338393Enabled", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-353696Enabled", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SystemPaneSuggestionsEnabled", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\Explorer", "ShellState", "Binary",[byte[]]0x24,0x00,0x00,0x00,0x3C,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "IconsOnly", "DWord",1),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ListViewAlphaSelect", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ListViewShadow", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowCompColor", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowInfoTip", "DWord",1),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskBarAnimation", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", "VisualFXSetting", "DWord",3),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\SearchSettings", "IsAADCloudSearchEnabled", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\SearchSettings", "IsDeviceSearchHistoryEnabled", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\SearchSettings", "IsMSACloudSearchEnabled", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement", "ScoobeSystemSettingEnabled", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\DWM", "EnableAeroPeek", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\DWM", "AlwaysHibernateThumbnails", "DWord",0),
    ("HKLM:\DefUser\Software\Microsoft\Windows\StorageSense\Parameters\StoragePolicy", "01", "DWord",0)
)
#endregion

#region Functions
<#
    Functions

        Log-Event   - logs script actions
        Write-Reg   - writes a value to the registry

#>

# Log-Event Function
Function Log-Event {
    <#
        References:
            Uses $LogLevel to determine where to write data
                "Low"    - "Info" and "Warning" to log, "Success" and "Error" to log and screen 
                "Normal" - "Info" to log, "Warning", "Success" and "Error" to log and screen
                "High"   - All output to log and screen
            Note: "Critical" EventType always goes to a modal dialog box as well as log and screen

        Usage examples:
            Log-Event -EventType "Info" -LogText "Script started!"
    #>

    Param(
        # Valid values "Info", "Success", "Warning", "Error", "Critical" - will use "Info" if not specified
        [validateSet("Info", "Success", "Warning", "Error", "Critical")]
        [String]$EventType="Info",
        # Log file folder - will use $LogDir if not specified
        [String]$LogFolder=$LogDir,
        # Log file name - will use $LogFile if not specified
        [String]$LogName=$LogFile,
        # Text to log
        [String]$LogText
    )

    $LogFullPath = Join-Path -Path $LogFolder -ChildPath $LogName 

    # All events are logged to the file
    Add-Content -Path $LogFullPath -Value "$([DateTime]::Now.ToString("u"))`t$EventType`t$LogText"

    # Display on screen unless:
        # EventType is Info and LogLevel is Low or Normal
        # EventType is Warning and LogLevel is Low
    If (!(($EventType -eq "Info") -and (($LogLevel -eq "Low") -or ($LogLevel -eq "Normal"))) -or !(($EventType -eq "Warning") -and ($LogLevel -eq "Low"))) {
        # Set output colour to match EventType
        Switch ($EventType) {
            "Info" {
                $OutputColour = "White"
            }
            "Success" {
                $OutputColour = "Green"
            }
            "Warning" {
                $OutputColour = "Yellow"
            }
            default {
                $OutputColour = "Red"
            }
        }
        Write-Host $LogText -ForegroundColor $OutputColour
        Write-Debug $LogText
    }

    # Finally, if the error is critical we need a modal dialog box to stop everything
    If ($EventType -eq "Critical") {
        $oShell = New-Object -ComObject Wscript.Shell
        $oShell.Popup($LogText,0,"Critical Error",16)
    }
}

# Write-Reg Function
function Write-Reg {
    <#
        Usage example:
            Write-Reg -RegPath "HKLM:\Software\MyCompany" -RegName "Software" -RegType "String" -RegData "Hello"
    #>

    Param(
        # The Name of the registry key - use HKLM:\ HKCU:\ etc
        [String]$RegPath,
        # The name of the value - will use default value if not specified
        [String]$RegName='(Default)',
        # The data type - will use 'String' if not specified
        [ValidateSet("Binary","DWord","ExpandString","MultiString","QWord","String")]
        [String]$RegType="String",
        # The actual value to set
        [String]$RegData
    )

     # Check if registry path exists
     If (!(Test-Path $RegPath)) {
        # It doesn't so we'll make it
        New-Item -Path $RegPath -Force | Out-Null
    }

    # Now write the value
    New-ItemProperty -Path $RegPath -Name $RegName -Value $RegData -PropertyType $RegType -Force | Out-Null
}


#endregion

#region MainScript
<# 
    Main Script Body
        "This is where the magic happens!"
#>

# Create $LogDir folder if it doesn't exist
if (!(Test-Path $LogDir)) {
    try {
        New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    } catch {
        # We can't create this folder so log to the TEMP folder instead!
        $LogDir = $env:TEMP
    }
}

Log-Event -LogText $LogBreak
Log-Event -LogText $ScriptInfo
Log-Event -LogText "$LogBreak`r`n"

# Remove Windows Media Player
Log-Event -LogText $LogBreak
Log-Event -LogText "Remove Windows Media Player`r`n"
try {
    Disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -NoRestart | Out-Null
    $WMPackages = Get-WindowsPackage -Online -PackageName "*Windows-mediaplayer*"
    foreach ($WMPackage in $WMPackages) {
        Log-Event -LogText "Removing $($WMPackage.PackageName)"
        Remove-WindowsPackage -PackageName $WMPackage.PackageName -Online -ErrorAction SilentlyContinue -NoRestart | Out-Null
        Log-Event -EventType Success -LogText "Removed $($WMPackage.PackageName)"
    }
} catch {
    Log-Event -EventType "Error" -LogText "Error removing Windows Media Player - $($_.Exception.Message)"
}
Log-Event -LogText "$LogBreak`r`n"

# Remove AppX Packages
Log-Event -LogText $LogBreak
Log-Event -LogText "Remove AppX Packages`r`n"
foreach ($App in $AppXPackages) {
    try {
        Log-Event -LogText "Removing $($App) Provisioned Package"
        Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -like ("*{0}*" -f $App)} | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
        Log-Event -EventType Success -LogText "Removed $($App) Provisioned Package"
        Log-Event -LogText "Removing $($App) Package (All Users)"
        Get-AppxPackage -AllUsers -Name ("*{0}*" -f $App) | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Log-Event -EventType Success -LogText "Removed $($App) Package (All Users)"
        Log-Event -LogText "Removing $($App) Package"
        Get-AppxPackage -Name ("*{0}*" -f $App) | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
        Log-Event -EventType Success -LogText "Removed $($App) Package"
    } catch {
    Log-Event -EventType Error -LogText "Error removing package $($App) - $($_.Exception.Message)"
    }
}
Log-Event -LogText "$LogBreak`r`n"

# Disable Scheduled Tasks
Log-Event -LogText $LogBreak
Log-Event -LogText "Disable Scheduled Tasks`r`n"
foreach ($Task in $ScheduledTasks) {
    Log-Event -LogText "Checking $($Task) Scheduled Task"
    $TaskObject = Get-ScheduledTask $Task
    if ($TaskObject) {
        if ($TaskObject.State -ne 'Disabled') {
            Log-Event -LogText "Attempting to disable $($TaskObject.TaskName)"
            try {
                Disable-ScheduledTask -InputObject $TaskObject | Out-Null
                Log-Event -EventType Success -LogText "Disabled task: $($TaskObject.TaskName)"
            } catch {
                Log-Event -EventType Error -LogText "Failed to disable task: $($TaskObject.TaskName)"
            }
        } else {
            Log-Event -LogText "Task already disabled: $($TaskObject.TaskName)"
        }
    } else {
        Log-Event -EventType Warning -LogText "Unable to find task: $($TaskObject.TaskName)"
    }
}        
Log-Event -LogText "$LogBreak`r`n"

# Disable Services
Log-Event -LogText $LogBreak
Log-Event -LogText "Disable Services`r`n"
foreach ($Service in $Services) {
    Log-Event -LogText "Attempting to stop service $($Service)"
    try {
        Stop-Service $Service -Force -ErrorAction SilentlyContinue
        Log-Event -EventType Success -LogText "Stopped service $($Service)"
    } catch {
        Log-Event -EventType Error -LogText "Failed to stop service: $($Service)"
    }
    Log-Event -LogText "Attempting to disable service $($Service)"
    try {
        Set-Service $Service -StartupType Disabled -ErrorAction SilentlyContinue
        Log-Event -EventType Success -LogText "Disabled service $($Service)"
    } catch {
        Log-Event -EventType Error -LogText "Failed to disable service: $($Service)"
    }
}
Log-Event -LogText "$LogBreak`r`n"

# Configure Network Optimisation
Log-Event -LogText $LogBreak
Log-Event -LogText "Configure Network Settings`r`n"
foreach ($NetworkConfig in $NetworkConfigs) {
    Log-Event -LogText "Setting network config for $($NetworkConfig[1])"
    try {
        Write-Reg -RegPath $NetworkConfig[0] -RegName $NetworkConfig[1] -RegType $NetworkConfig[2] -RegData $NetworkConfig[3]
        Log-Event -EventType Success -LogText "Set config for $($NetworkConfig[1])"
    } catch {
        Log-Event -EventType Error -LogText "Error setting config for $($NetworkConfig[1]) - $($_.Exception.Message)"
    }
}
Log-Event -LogText "$LogBreak`r`n"

# Configure Windows Logging
Log-Event -LogText $LogBreak
Log-Event -LogText "Configure Windows Logging`r`n"
foreach ($LogConfig in $LogConfigs) {
    Log-Event -LogText "Setting log config for $($LogConfig[0].Split("\")[-2])"
    try {
        Write-Reg -RegPath $LogConfig[0] -RegName $LogConfig[1] -RegType $LogConfig[2] -RegData $LogConfig[3]
        Log-Event -EventType Success -LogText "Set config for $($LogConfig[0].Split("\")[-2])"
    } catch {
        Log-Event -EventType Error -LogText "Error setting config for $($LogConfig[0].Split("\")[-2]) - $($_.Exception.Message)"
    }
}
Log-Event -LogText "$LogBreak`r`n"

# Configure Default User Settings
Log-Event -LogText $LogBreak
Log-Event -LogText "Configure Default User Settings`r`n"
# Load default user hive as HKLM:\DefUser
Log-Event -LogText "Loading default user hive"
try {
    & REG LOAD HKLM\DefUser C:\Users\Default\NTUSER.DAT | Out-Null
    Log-Event -EventType Success -LogText "Loaded default user hive"
} catch {
    Log-Event -EventType Error -LogText "Error loading default user hive"
}

foreach ($UserConfig in $UserConfigs) {
    Log-Event -LogText "Setting config item for $($UserConfig[0].Split("\")[-1])"
    try {
        Write-Reg -RegPath $UserConfig[0] -RegName $UserConfig[1] -RegType $UserConfig[2] -RegData $UserConfig[3]
        Log-Event -EventType Success -LogText "Set config for $($UserConfig[0].Split("\")[-1])"
    } catch {
        Log-Event -EventType Error -LogText "Error setting config for $($UserConfig[0].Split("\")[-1]) - $($_.Exception.Message)"
    }
}
# Unload default user hive
Log-Event -LogText "Waiting five seconds for reg writes to complete"
Start-Sleep -Seconds 5
Log-Event -LogText "Unloading default user hive"
try {
    & REG UNLOAD HKLM\DefUser | Out-Null
    Log-Event -EventType Success -LogText "Unloaded default user hive"
} catch {
    Log-Event -EventType Error -LogText "Error unloading default user hive"
}
Log-Event -LogText "$LogBreak`r`n"

# Finish and tidy up
Log-Event -LogText $LogBreak
$StopWatch.Stop()
Log-Event -LogText "Configuration Script Complete"
Log-Event -LogText "Total run time $($StopWatch.Elapsed.TotalSeconds) seconds"
Log-Event -LogText $LogBreak

#endregion