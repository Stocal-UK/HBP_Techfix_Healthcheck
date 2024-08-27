<#
    ###########################################################################
    # Script Name: HBP_TechFix_Healthcheck.ps1
    # Author: Callum Stones
    # Company: HBP Systems
    # Date Created: 20/04/2023 
    #
    # Copyright (c) Callum Stones, HBP Systems. All rights reserved.
    # This script is provided "AS IS" without any warranties and is intended
    # for use solely by the author and HBP Systems. Unauthorized copying,
    # reproduction, modification, or distribution is strictly prohibited
    # without the express written consent of Callum Stones and HBP Systems.
    ###########################################################################
#>

Clear-Host

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "You must run this script as an Administrator."
 
    $NewProcessInfo = New-Object System.Diagnostics.ProcessStartInfo "PowerShell"
    $NewProcessInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    $NewProcessInfo.Verb = "runas"
    try {
        [System.Diagnostics.Process]::Start($NewProcessInfo)
    } catch {
        Write-Error "Failed to run script as Administrator."
    }
    exit
}

Clear-Host

Set-ExecutionPolicy -ExecutionPolicy Bypass -Force

$logpath = "C:\HBP\Logs" | Out-Null

if (!(Test-Path $logPath)) {
    New-Item -ItemType Directory -Path $logPath | Out-Null
}

Clear-Host

Start-Transcript -Path "$logpath\Healthcheck_Result.log" | Out-Null

Write-Host "Logging Started." -ForegroundColor Green
Write-Host "Execution Policy set to Bypass." -ForegroundColor Green

Start-Sleep -Seconds 2

Write-Host""
Write-Host""
Write-Host "HBP TechFix Healthcheck Version 1.0" -ForegroundColor Green
Write-Host "Written by Callum Stones" -ForegroundColor Green
Write-Host "Initalizing..." -ForegroundColor Green
Start-Sleep -Seconds 1

do {
    $SSD = Read-Host "Does this machine have an SSD? (Y/N)"
} while ($SSD -ne 'Y' -and $SSD -ne 'N')

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
    Write-Host "Starting SFC Procedure..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    Write-Host "Running SFC Procedure..." -ForegroundColor Yellow
    
    sfc /scannow 

    Write-Host "SFC Procedure Complete." -ForegroundColor Green
}

function Invoke-DISMRepair {
    Write-Host "Starting DISM repair..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    Write-Host "Running DISM repair..." -ForegroundColor Yellow
    
    $command = "DISM.exe /Online /Cleanup-image /Restorehealth"
    Invoke-Expression $command
   
    Write-Host "DISM Repair Complete." -ForegroundColor Green
}

function Invoke-Chkdsk-CDrive {
    Write-Host "Starting CHKDSK on C: drive..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    Write-Host "Running CHKDSK on C: drive..." -ForegroundColor Yellow
    
    Write-Output Y | Chkdsk C: /F /R /X | Out-Null
    
    Write-Host "Reboot to complete CHKDSK on C: drive..." -ForegroundColor Yellow
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

Invoke-SfcScan
Invoke-DISMRepair
Invoke-Chkdsk-CDrive
if ($SSD -eq 'N') {
    Invoke-Defragment-CDrive
}
Invoke-WindowsUpdates

Write-Host "PC is ready to reboot..." -ForegroundColor Green
Write-Host "Continuing will trigger a reboot!" -ForegroundColor Yellow

Pause

Write-Host "PC will reboot in 1 minute..." -ForegroundColor Red

Start-Sleep -Seconds 4

Stop-Transcript | Out-Null

Shutdown /R /F /T 60 | Out-Null





