<#
.SYNOPSIS
    Audits local user accounts based on last sign-in date and password age.

.DESCRIPTION
    This script audits local user accounts on the computer, reporting on:
    - Last sign-in date
    - Password age
    - Password expiration status
    - Account status (enabled/disabled)
    
.PARAMETER DaysInactive
    Number of days of inactivity to flag accounts (default: 90)

.PARAMETER PasswordAgeDays
    Number of days to flag old passwords (default: 90)

.PARAMETER ExportPath
    Optional path to export results to CSV

.EXAMPLE
    .\Audit-LocalUserAccounts.ps1
    
.EXAMPLE
    .\Audit-LocalUserAccounts.ps1 -DaysInactive 60 -PasswordAgeDays 180 -ExportPath "C:\Audit\LocalUsers.csv"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [int]$DaysInactive = 90,
    
    [Parameter(Mandatory=$false)]
    [int]$PasswordAgeDays = 90,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath
)

# Requires Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

Write-Host "=== Local User Account Audit ===" -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Green
Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
Write-Host "Inactive Threshold: $DaysInactive days" -ForegroundColor Green
Write-Host "Password Age Threshold: $PasswordAgeDays days" -ForegroundColor Green
Write-Host ""

$results = @()
$currentDate = Get-Date

# Get all local user accounts
$localUsers = Get-LocalUser

foreach ($user in $localUsers) {
    Write-Host "Processing: $($user.Name)..." -ForegroundColor Yellow
    
    # Calculate password age
    $passwordAge = $null
    $passwordAgeStatus = "N/A"
    if ($user.PasswordLastSet) {
        $passwordAge = ($currentDate - $user.PasswordLastSet).Days
        if ($passwordAge -gt $PasswordAgeDays) {
            $passwordAgeStatus = "WARNING - Old Password"
        } else {
            $passwordAgeStatus = "OK"
        }
    } else {
        $passwordAgeStatus = "Never Set"
    }
    
    # Calculate last logon age
    $lastLogonAge = $null
    $activityStatus = "N/A"
    if ($user.LastLogon) {
        $lastLogonAge = ($currentDate - $user.LastLogon).Days
        if ($lastLogonAge -gt $DaysInactive) {
            $activityStatus = "WARNING - Inactive"
        } else {
            $activityStatus = "Active"
        }
    } else {
        $activityStatus = "Never Logged On"
    }
    
    # Determine password expiration
    $passwordExpires = if ($user.PasswordExpires) { 
        $user.PasswordExpires.ToString('yyyy-MM-dd') 
    } else { 
        "Never" 
    }
    
    # Create result object
    $result = [PSCustomObject]@{
        Username = $user.Name
        FullName = $user.FullName
        Enabled = $user.Enabled
        LastLogon = if ($user.LastLogon) { $user.LastLogon.ToString('yyyy-MM-dd HH:mm:ss') } else { "Never" }
        DaysSinceLastLogon = $lastLogonAge
        ActivityStatus = $activityStatus
        PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss') } else { "Never" }
        PasswordAgeDays = $passwordAge
        PasswordAgeStatus = $passwordAgeStatus
        PasswordExpires = $passwordExpires
        PasswordNeverExpires = $user.PasswordExpires -eq $null
        Description = $user.Description
    }
    
    $results += $result
}

# Display results
Write-Host "`n=== Audit Results ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize

# Summary statistics
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total Accounts: $($results.Count)" -ForegroundColor Green
Write-Host "Enabled Accounts: $($results | Where-Object {$_.Enabled -eq $true} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Green
Write-Host "Disabled Accounts: $($results | Where-Object {$_.Enabled -eq $false} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Green
Write-Host "Inactive Accounts (>$DaysInactive days): $($results | Where-Object {$_.ActivityStatus -eq 'WARNING - Inactive'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow
Write-Host "Old Passwords (>$PasswordAgeDays days): $($results | Where-Object {$_.PasswordAgeStatus -eq 'WARNING - Old Password'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow
Write-Host "Never Logged On: $($results | Where-Object {$_.ActivityStatus -eq 'Never Logged On'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow

# Export if path provided
if ($ExportPath) {
    try {
        $results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green
    } catch {
        Write-Error "Failed to export results: $_"
    }
}

Write-Host "`nAudit Complete!" -ForegroundColor Cyan