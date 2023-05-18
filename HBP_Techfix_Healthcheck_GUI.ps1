﻿<#
    ###########################################################################
    # Script Name: HBP_TechFix_Healthcheck_GUI.ps1
    # Author: Callum Stones & Luke Jackson
    # Company: HBP Systems
    # Date Created: 09/05/2023 
    #
    # Copyright (c) Callum Stones, HBP Systems. All rights reserved.
    # This script is provided "AS IS" without any warranties and is intended
    # for use solely by the author and HBP Systems. Unauthorized copying,
    # reproduction, modification, or distribution is strictly prohibited
    # without the express written consent of Callum Stones and HBP Systems.
    ###########################################################################
#>

# Load required assemblies
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# Load XAML file
$xamlFile = ".\HBPTechfixHealthCheckGui.xaml"
$xamlContent = Get-Content -Path $xamlFile -Raw

# Remove the Class directive from the XAML content
$xamlContent = $xamlContent -replace '(x:Class="[^"]+")', ''

$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xamlContent))
$gui = [System.Windows.Markup.XamlReader]::Load($reader)

# Get our check boxes for use in the script

$SFCCheckBox = $gui.FindName("SFCScanCheck")
$CheckDiskCheckBox = $gui.FindName("CheckDiskCheck")
$FastBootCheck = $gui.FindName("DisableFastbootCheck")
$WupdateCheck = $gui.FindName("WindowsUpdCheck")
$DISMCheck = $gui.FindName("DISMScanCheck")
$DefragCheck = $gui.FindName("DefragCheck")
$HighPerfCheck = $gui.FindName("HighPerfCheck")
$RebootCheck = $gui.FindName("RebootCheck")

# Get our text box so we can manipulate this

$OutputBox = $gui.FindName("OutputBox")
$ProgressBox = $gui.FindName("OutputBoxTask")

# Get our button

$StartBtn = $gui.FindName("StartBtn")

# Check if we're running as administrator

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    # Display message box if not running as administrator
    $msgBoxTitle = "Administrator privileges required"
    $msgBoxMessage = "This script must be run as an administrator."
    [System.Windows.MessageBox]::Show($msgBoxMessage, $msgBoxTitle, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
    exit
}

# Check if we have an SSD or a HDD

$DiskType = Get-PhysicalDisk | Select-Object MediaType 

# If we have an SSD, we want to make sure that the defrag option isn't allowed
if ($DiskType.MediaType -eq "SSD") {
    Write-Host "SSD Detected"
    $OutputBox.IsReadOnly = $false
    $OutputBox.Text = "SSD Detected, defrag option has been unchecked and disabled as an option."
    $OutputBox.IsReadOnly = $true
    $DefragCheck.IsChecked = $false
    $DefragCheck.IsEnabled = $false
}

function Invoke-WindowsUpdates {
    Write-Host "Starting Windows Update Retrieval..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    Write-Host "Running Windows Update Retrieval..." -ForegroundColor Yellow

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null

    Install-Module -Name PSWindowsUpdate -Scope CurrentUser -Force  | Out-Null

    Import-Module PSWindowsUpdate -Force  | Out-Null

    Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot | Out-Null

    Write-Host "Windows Updates Forced!" -ForegroundColor Green
}
catch {
    Write-Host "Updates Failed." -ForegroundColor Red
}

}

function Invoke-SfcScan {
    # Get the time in hours:minutes:seconds
    $startTime = Get-Date -Format "HH:mm:ss"
    Write-Host "Starting SFC Scan at $startTime..."

    # This updates the $ProgressBox in it's own thread so it can update dynamically and in realtime
    $ProgressBox.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [Action]{
        # Updates the Progress Box with the current time
        $ProgressBox.AppendText("SFC Scan started at: $startTime`r`n")
    })
    # Disables controls so the user doesn't fiddle
    Disable-Controls

    # This is our actual process so we can call it later and check it's status
    $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c sfc /scannow > output.txt" -NoNewWindow -PassThru

    # While the SFC is running we do this block, which essentially updates the $OutputBox in realtime to let us know it's not crashed
    while (!$process.HasExited) {
        Start-Sleep -Milliseconds 500
        $currentTime = Get-Date -Format "HH:mm:ss"
        $message = "$currentTime - SFC scan still running..."
        $OutputBox.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [Action]{
            $OutputBox.Text = $message
        })
    }

    # SFC doesn't exit with a proper exit code so this is the best way to grab when it's finished
    if ($process.ExitCode -ne 0) {
        $ProgressBox.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [Action]{
            $ProgressBox.Text = "SFC Scan Complete"
        })
        $endTime = Get-Date
        $logFilePath = Convert-Path "output.txt"
        $output += "$endTime - SFC Scan finished. The log file can be found here: $logFilePath`r`nOr in the usual location of C:\Windows\Log\CBS\"
        $OutputBox.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [Action]{
            $OutputBox.Text = $output
            $OutputBox.ScrollToEnd()
        })
    }
    # Enable the controls again
    Enable-Controls
}


function Invoke-Chkdsk-CDrive {
    Write-Host "Starting CHKDSK on C: drive..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    Write-Host "Running CHKDSK on C: drive..." -ForegroundColor Yellow
    $ProgressBox.Text = "Running CHKDSK..."
    Disable-Controls
    $output = ""

    # Making an object to store our process information
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    # File name of the above is set to cmd.exe
    $startInfo.FileName = "cmd.exe"
    # Our arguments to run chkdsk and any arguments
    $startInfo.Arguments = "/c chkdsk C:"
    # This ensures we can read the output
    $startInfo.RedirectStandardOutput = $true
    # This stops it running in its own shell
    $startInfo.UseShellExecute = $false
    # This stops a new window being created to avoid mess/confusion
    $startInfo.CreateNoWindow = $true

    # This makes a new object ready to start with the above info inside it
    $process = New-Object System.Diagnostics.Process
    # Throws all the info the process needs to run into it's settings
    $process.StartInfo = $startInfo

    # This ensures out output box updates with the output of the chkdsk so we know what's going on
    $outputEvent = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action {
        if ($EventArgs.Data) {
            $output += $EventArgs.Data + "`r`n"
            $OutputBox.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [Action]{
                $OutputBox.Text = $output
                $OutputBox.ScrollToEnd()
            })
        }
    }

    # This starts our process
    $process.Start() | Out-Null
    # This reads the output asynchronously with the other processes so the output can be captured for our output box in realtime 
    $process.BeginOutputReadLine()

    # Checks if the chkdsk has finished or not
    while (!$process.HasExited) {
        Start-Sleep -Milliseconds 100
    }

    # Unregisters the reading of the output so we don't have threads left
    Unregister-Event -SourceIdentifier $outputEvent.Name
    $ProgressBox.Text = "CHKDSK Complete..."
    Enable-Controls
}

function Invoke-Defragment-CDrive {
    Write-Host "Starting Defrag on C: drive..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    Write-Host "Running Defrag on C: drive..." -ForegroundColor Yellow

    $DefragOutput = Optimize-Volume -DriveLetter C -Defrag -Verbose

    Write-Host "Finished Defrag on C: drive." -ForegroundColor Green

    Return $DefragOutput
}

function Disable-FastBoot {
    Write-Host "Disabling Fastboot..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    try {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value 0 -Force
        Write-Host "Fast Boot has been disabled successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Error disabling Fast Boot!" -ForegroundColor Red
    }
}

function Enable-HighPerformance {
    Write-Host "Enabling High Performance Mode..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    try {
        powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

        Write-Host "High-Performance power plan has been activated successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Error activating High-Performance power plan!" -ForegroundColor Red
    }
}

function Disable-Controls {
    # This just disables the check boxes and button on the form so people don't fiddle while stuff is running
    $SFCCheckBox.IsEnabled = $false
    $CheckDiskCheckBox.IsEnabled = $false
    $FastBootCheck.IsEnabled = $false
    $WupdateCheck.IsEnabled = $false
    $DISMCheck.IsEnabled = $false
    $DefragCheck.IsEnabled = $false
    $HighPerfCheck.IsEnabled = $false
    $RebootCheck.IsEnabled = $false
    $StartBtn.IsEnabled = $false
}

function Enable-Controls {
    # This enables the controls again
    $SFCCheckBox.IsEnabled = $true
    $CheckDiskCheckBox.IsEnabled = $true
    $FastBootCheck.IsEnabled = $true
    $WupdateCheck.IsEnabled = $true
    $DISMCheck.IsEnabled = $true
    $DefragCheck.IsEnabled = $true
    $HighPerfCheck.IsEnabled = $true
    $RebootCheck.IsEnabled = $true
    $StartBtn.IsEnabled = $true
}

$StartBtn.Add_Click({

    if ($SFCCheckBox.IsChecked) {
        Write-Host "I'm doing an SFC check..."
        $OutputBox.Text += "`r`nI'm running an SFC check..."
        $OutputBox.ScrollToEnd()
        Invoke-SfcScan
    }

    if ($CheckDiskCheckBox.IsChecked) {
        # This just does a verification at the moment, not a full on repair (for testing)
        Write-Host "I'm doing a check disk..."
        $OutputBox.Text += "`r`nI'm doing a check disk..."
        $OutputBox.ScrollToEnd()
        Invoke-Chkdsk-CDrive
    }
    
    if ($FastBootCheck.IsChecked) {
        Write-Host "I'm disabling fast boot..."
        $OutputBox.Text += "`r`nI'm disabling fast boot..."
        $OutputBox.ScrollToEnd()
    }
    
    if ($WupdateCheck.IsChecked) {
        Write-Host "I'm checking wupdates..."
        $OutputBox.Text += "`r`nI'm checking wupdates..."
        $OutputBox.ScrollToEnd()
    }
    
    if ($DISMCheck.IsChecked) {
        Write-Host "I'm doing a DISM check..."
        $OutputBox.Text += "`r`nI'm doing a DISM check..."
        $OutputBox.ScrollToEnd()
    }
    
    if ($DefragCheck.IsChecked) {
        Write-Host "I'm running a defrag..."
        $OutputBox.Text += "`r`nI'm running a defrag..."
        $OutputBox.ScrollToEnd()
    }
    
    if ($HighPerfCheck.IsChecked) {
        Write-Host "I'm enabling high performance..."
        $OutputBox.Text += "`r`nI'm enabling high performance..."
        $OutputBox.ScrollToEnd()
    }
    
    if ($RebootCheck.IsChecked) {
        Write-Host "I'm rebooting..."
        $OutputBox.Text += "`r`nI'm rebooting..."
        $OutputBox.ScrollToEnd()
    }
    

})

$gui.ShowDialog() | Out-Null
