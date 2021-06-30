#region Introduction
<#
    Script Name:    SecureWVDImage.ps1
    Version:        0.02
    Date:           28 Jun 2021
    Author:         Craig Walls
    Email:          craig.walls@syntax.co.uk

    Parameters:
        None

    References:
        None

    Revision History:
        v0.01 - 28 Jun 2021 Craig Walls - First version
        v0.02 - 28 Jun 2021 Craig Walls - Updated file location

.SYNOPSIS
This script will apply security baselines to the WVD build in preparation for capturing a 'golden image' for production deployment.

.DESCRIPTION
This script secures WVD by applying any security baselines configured in the file share described in the ScriptValues section
#>
#endregion

#region ScriptValues
<#
    Values that are used throughout the script
#>
$StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ScriptName = $MyInvocation.MyCommand.Name
$ScriptInfo = "$ScriptName - v0.02 - 28 Jun 2021"
$LogBreak = "+------------------------------------------------------------------------------+"
$LogDir = Join-Path -Path $env:ProgramData -ChildPath "CAF"
$LogFile = "$($ScriptName.SubString(0, $ScriptName.LastIndexOf('.'))).log"
$FSAccount = "craigwvdscripts"
$FSShare = "securitybaselines"
$FSKey = 'vjd2QsbZvLXEbhKMBsE7W9We8/yiDEBeFD88d0YVmavT82jPp4XH3XquAKiWfcTtXgt6jstRhlZDlUGlQVJGsg=='
$FSLetter = "X"
$FSAddress = "$($FSAccount).file.core.windows.net"
$FSUser = "localhost\$($FSAccount)"
$FSCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $FSUser, (ConvertTo-SecureString -String $FSKey -AsPlainText -Force)
$Baselines = @(
    ("$($FSLetter):\Edge\Scripts\Baseline-LocalInstall.ps1", ""),
    ("$($FSLetter):\O365\Scripts\Baseline-LocalInstall.ps1", "-NoLegacyFileBlock"),
    ("$($FSLetter):\Win10\Scripts\Baseline-LocalInstall.ps1", "-Win10NonDomainJoined")
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

# Connect to script file share
Log-Event -LogText $LogBreak
Log-Event -LogText "Connecting to shared drive $FSAddress `r`n"

# Check connectivity on port 445
if ((Test-NetConnection -ComputerName $FSAddress -Port 445).TcpTestSucceeded) {
    try {
        cmd.exe /c "Net Use $($FSLetter): \\$FSAddress\$FSShare /u:$FSUser $FSKey"
        Log-Event -EventType Success -LogText "Connected $($FSLetter): to $FSAddress"
    } catch {
        Log-Event -EventType Error -LogText "Error connecting $($FSLetter): to $FSAddress"
    }
} else {
    Log-Event -EventType Error -LogText "Unable to connect to $FSAddress on port 445!"
}
Log-Event -LogText "$LogBreak`r`n"

# Run each baseline if the location can be seen
foreach ($Baseline in $Baselines) {
    if (Test-Path $Baseline[0]) {
        # Get the folder name so that we can look for log files
        $BaseFolder = Split-Path -Parent $Baseline[0]
        Push-Location $BaseFolder
        # If a parameter is specified add it to the command
        if ($Baseline[1] -ne $null) {
            try {
                Log-Event -LogText "Calling $($Baseline[0]) $($BaseLine[1])"
                Invoke-Expression "& `"$($BaseLine[0])`" $($BaseLine[1])"
                Log-Event -EventType Success -LogText "Completed $($BaseLine[0]) $($BaseLine[1])"
                # Copy latest log file back to our log folder
                $LatestLog = Get-ChildItem $BaseFolder | Sort-Object {$_.LastWriteTime} -Descending | Select-Object -First 1
                Log-Event -LogText "Copying log file $($LatestLog.Name) to log folder"
                Copy-Item -Path $LatestLog.FullName -Destination $LogDir -Force 
            } catch {
                Log-Event -EventType Error -LogText "Error running $($BaseLine[0]) $($BaseLine[1])"
            }
        } else {
            try {
                Log-Event -LogText "Calling $($Baseline[0])"
                Invoke-Expression "& `"$($BaseLine[0])`""
                Log-Event -EventType Success -LogText "Completed $($BaseLine[0]) "
                # Copy latest log file back to our log folder
                $LatestLog = Get-ChildItem $BaseFolder | Sort-Object {$_.LastWriteTime} -Descending | Select-Object -First 1
                Log-Event -LogText "Copying log file $($LatestLog.Name) to log folder"
                Copy-Item -Path $LatestLog.FullName -Destination $LogDir -Force 
            } catch {
                Log-Event -EventType Error -LogText "Error running $($BaseLine[0]) $($BaseLine[1])"
            }
        Pop-Location
        }
    } else {
        Log-Event -EventType Warning -LogText "Couldn`t find $($BaseLine[0]) - skipping!"
    }
}
Log-Event -LogText "$LogBreak`r`n"


# Finish and tidy up
Log-Event -LogText $LogBreak
# Remove mapped drive
Log-Event -LogText "Tidying up"
try {
    Push-Location C:
    cmd.exe /c "Net Use $($FSLetter): /d"
} catch {
    Log-Event -EventType Warning -LogText "Could not remove $($FSLetter): drive - continuing"
}
$StopWatch.Stop()
Log-Event -LogText "Configuration Script Complete"
Log-Event -LogText "Total run time $($StopWatch.Elapsed.TotalSeconds) seconds"
Log-Event -LogText $LogBreak

#endregion