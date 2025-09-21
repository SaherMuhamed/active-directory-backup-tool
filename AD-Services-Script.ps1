#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enable and start all Active Directory services on Windows Server

.DESCRIPTION
    This script enables and starts all core Active Directory services.
    It includes error handling, logging, and service dependency management.

.NOTES
    Author: PowerShell Script
    Requires: Administrator privileges
    Compatible: Windows Server 2012 R2 and later
#>

# Set error handling
$ErrorActionPreference = "Continue"

# Define log file path
$LogPath = "C:\Logs\AD_Services_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Create logs directory if it doesn't exist
if (!(Test-Path "C:\Logs")) {
    New-Item -ItemType Directory -Path "C:\Logs" -Force | Out-Null
}

# Function to write to log and console
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry
    Add-Content -Path $LogPath -Value $LogEntry
}

# Function to check if server has AD role installed
function Test-ADRole {
    try {
        $ADRole = Get-WindowsFeature -Name "AD-Domain-Services"
        return ($ADRole.InstallState -eq "Installed")
    }
    catch {
        return $false
    }
}

# Define Active Directory services in dependency order
$ADServices = @(
    "EventLog",           # Windows Event Log (dependency for others)
    "RpcSs",             # Remote Procedure Call (RPC)
    "RpcEptMapper",      # RPC Endpoint Mapper
    "SamSs",             # Security Accounts Manager
    "LanmanServer",      # Server
    "LanmanWorkstation", # Workstation
    "Netlogon",          # Net Logon
    "NTDS",              # Active Directory Domain Services
    "ADWS",              # Active Directory Web Services
    "DFS",               # DFS Namespace (if installed)
    "DFSR",              # DFS Replication (if installed)
    "DNS",               # DNS Server (if installed)
    "KDC",               # Kerberos Key Distribution Center
    "IsmServ",           # Intersite Messaging
    "W32Time"            # Windows Time
)

# Additional services that might be present
$OptionalServices = @(
    "ADFS",              # Active Directory Federation Services
    "CertSvc",           # Active Directory Certificate Services
    "MSExchangeADTopology", # Exchange AD Topology (if Exchange is installed)
    "FRS"                # File Replication Service (legacy)
)

Write-Log "Starting Active Directory Services Management Script" "INFO"
Write-Log "Log file: $LogPath" "INFO"

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log "ERROR: This script must be run as Administrator!" "ERROR"
    exit 1
}

# Check if AD role is installed
if (-not (Test-ADRole)) {
    Write-Log "WARNING: Active Directory Domain Services role is not installed on this server" "WARN"
    Write-Log "Please install the AD DS role first using: Install-WindowsFeature AD-Domain-Services -IncludeManagementTools" "WARN"
}

Write-Log "Checking and configuring Active Directory services..." "INFO"

# Process core AD services
foreach ($ServiceName in $ADServices) {
    try {
        $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        
        if ($Service) {
            Write-Log "Processing service: $ServiceName" "INFO"
            
            # Set service to Automatic startup
            Set-Service -Name $ServiceName -StartupType Automatic -ErrorAction Stop
            Write-Log "Set $ServiceName startup type to Automatic" "INFO"
            
            # Start the service if it's not running
            if ($Service.Status -ne "Running") {
                Start-Service -Name $ServiceName -ErrorAction Stop
                Write-Log "Started service: $ServiceName" "INFO"
                
                # Wait for service to fully start
                $timeout = 30
                $timer = 0
                do {
                    Start-Sleep -Seconds 2
                    $timer += 2
                    $Service = Get-Service -Name $ServiceName
                } while ($Service.Status -ne "Running" -and $timer -lt $timeout)
                
                if ($Service.Status -eq "Running") {
                    Write-Log "Service $ServiceName is now running" "INFO"
                } else {
                    Write-Log "Service $ServiceName failed to start within timeout period" "WARN"
                }
            } else {
                Write-Log "Service $ServiceName is already running" "INFO"
            }
        } else {
            Write-Log "Service $ServiceName not found on this system" "WARN"
        }
    }
    catch {
        Write-Log "ERROR processing service $ServiceName`: $($_.Exception.Message)" "ERROR"
    }
}

# Process optional services
Write-Log "Checking optional AD-related services..." "INFO"

foreach ($ServiceName in $OptionalServices) {
    try {
        $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        
        if ($Service) {
            Write-Log "Found optional service: $ServiceName" "INFO"
            
            # Set service to Automatic startup
            Set-Service -Name $ServiceName -StartupType Automatic -ErrorAction Stop
            Write-Log "Set $ServiceName startup type to Automatic" "INFO"
            
            # Start the service if it's not running
            if ($Service.Status -ne "Running") {
                Start-Service -Name $ServiceName -ErrorAction Stop
                Write-Log "Started optional service: $ServiceName" "INFO"
            } else {
                Write-Log "Optional service $ServiceName is already running" "INFO"
            }
        }
    }
    catch {
        Write-Log "Note: Optional service $ServiceName could not be processed: $($_.Exception.Message)" "INFO"
    }
}

# Display final service status
Write-Log "Final Active Directory Services Status:" "INFO"
Write-Log "======================================" "INFO"

$AllServices = $ADServices + $OptionalServices
foreach ($ServiceName in $AllServices) {
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($Service) {
        $Status = $Service.Status
        $StartType = (Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'").StartMode
        Write-Log "$ServiceName`: Status=$Status, StartType=$StartType" "INFO"
    }
}

Write-Log "Active Directory Services configuration completed" "INFO"
Write-Log "Check the log file for detailed information: $LogPath" "INFO"

# Optional: Test AD functionality
Write-Log "Testing basic AD functionality..." "INFO"
try {
    # Test if we can query AD
    $Domain = Get-ADDomain -ErrorAction Stop
    Write-Log "Successfully connected to domain: $($Domain.Name)" "INFO"
    
    # Test DNS resolution of domain controller
    $DCName = $env:COMPUTERNAME
    $DCRecord = Resolve-DnsName -Name $DCName -ErrorAction Stop
    Write-Log "DNS resolution test successful for: $DCName" "INFO"
    
    Write-Log "Basic AD functionality tests PASSED" "INFO"
}
catch {
    Write-Log "AD functionality test failed: $($_.Exception.Message)" "WARN"
    Write-Log "This may be normal if the server is not yet promoted to a domain controller" "INFO"
}

Write-Host "`nScript execution completed. Check log file: $LogPath" -ForegroundColor Green
