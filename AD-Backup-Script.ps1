# Active Directory Complete Backup Script
# Requires: Run as Administrator on Domain Controller
# Version: 1.0

#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory

param(
    [Parameter(Mandatory=$false)]
    [string]$BackupPath = "D:\AD_Backups",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "D:\AD_Backups\Logs",
    
    [Parameter(Mandatory=$false)]
    [int]$RetentionDays = 30,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeExports = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$CompressBackup = $true
)

# Initialize logging
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path "$LogPath\AD_Backup_$(Get-Date -Format 'yyyyMMdd').log" -Value $logEntry
}

# Create backup directories
function Initialize-BackupEnvironment {
    Write-Log "Initializing backup environment..."
    
    $directories = @($BackupPath, $LogPath, "$BackupPath\SystemState", "$BackupPath\Exports", "$BackupPath\SYSVOL")
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            Write-Log "Created directory: $dir"
        }
    }
}

# Install required features
function Install-RequiredFeatures {
    Write-Log "Checking required Windows features..."
    
    $features = @("Windows-Server-Backup", "RSAT-AD-PowerShell")
    
    foreach ($feature in $features) {
        $installed = Get-WindowsFeature -Name $feature
        if ($installed.InstallState -ne "Installed") {
            Write-Log "Installing feature: $feature"
            Install-WindowsFeature -Name $feature -IncludeManagementTools
        } else {
            Write-Log "Feature already installed: $feature"
        }
    }
}

# System State Backup
function Backup-SystemState {
    Write-Log "Starting System State backup..."
    
    $dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupTarget = "$BackupPath\SystemState\SystemState_$dateStamp"
    
    try {
        # Create system state backup
        $result = Start-Process -FilePath "wbadmin.exe" -ArgumentList "start systemstatebackup -backupTarget:`"$backupTarget`" -quiet" -Wait -PassThru -NoNewWindow
        
        if ($result.ExitCode -eq 0) {
            Write-Log "System State backup completed successfully"
            Write-Log "Backup location: $backupTarget"
            return $backupTarget
        } else {
            throw "wbadmin exit code: $($result.ExitCode)"
        }
    } catch {
        Write-Log "System State backup failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# SYSVOL Backup
function Backup-SYSVOL {
    Write-Log "Starting SYSVOL backup..."
    
    $dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $sysvolPath = "$env:SystemRoot\SYSVOL"
    $backupTarget = "$BackupPath\SYSVOL\SYSVOL_$dateStamp"
    
    try {
        if (Test-Path $sysvolPath) {
            # Copy SYSVOL directory
            robocopy $sysvolPath $backupTarget /E /COPYALL /R:3 /W:10 /LOG:"$LogPath\SYSVOL_$dateStamp.log"
            
            if ($LASTEXITCODE -le 3) {  # Robocopy success codes
                Write-Log "SYSVOL backup completed successfully"
                return $backupTarget
            } else {
                throw "Robocopy failed with exit code: $LASTEXITCODE"
            }
        } else {
            Write-Log "SYSVOL path not found: $sysvolPath" "WARNING"
            return $null
        }
    } catch {
        Write-Log "SYSVOL backup failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# Export AD Objects
function Export-ADObjects {
    Write-Log "Starting AD objects export..."
    
    $dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $exportPath = "$BackupPath\Exports\AD_Export_$dateStamp"
    New-Item -Path $exportPath -ItemType Directory -Force | Out-Null
    
    try {
        # Export Users
        Write-Log "Exporting AD Users..."
        Get-ADUser -Filter * -Properties * | Export-Clixml "$exportPath\Users.xml"
        Get-ADUser -Filter * -Properties * | Export-Csv "$exportPath\Users.csv" -NoTypeInformation
        
        # Export Groups
        Write-Log "Exporting AD Groups..."
        Get-ADGroup -Filter * -Properties * | Export-Clixml "$exportPath\Groups.xml"
        Get-ADGroup -Filter * -Properties * | Export-Csv "$exportPath\Groups.csv" -NoTypeInformation
        
        # Export OUs
        Write-Log "Exporting Organizational Units..."
        Get-ADOrganizationalUnit -Filter * -Properties * | Export-Clixml "$exportPath\OUs.xml"
        Get-ADOrganizationalUnit -Filter * -Properties * | Export-Csv "$exportPath\OUs.csv" -NoTypeInformation
        
        # Export Computers
        Write-Log "Exporting AD Computers..."
        Get-ADComputer -Filter * -Properties * | Export-Clixml "$exportPath\Computers.xml"
        Get-ADComputer -Filter * -Properties * | Export-Csv "$exportPath\Computers.csv" -NoTypeInformation
        
        # Export Group Policy Objects
        Write-Log "Exporting Group Policy Objects..."
        if (Get-Module -ListAvailable -Name GroupPolicy) {
            Import-Module GroupPolicy
            Get-GPO -All | Export-Clixml "$exportPath\GPOs.xml"
            
            # Backup each GPO
            $gpoBackupPath = "$exportPath\GPO_Backups"
            New-Item -Path $gpoBackupPath -ItemType Directory -Force | Out-Null
            Get-GPO -All | ForEach-Object { Backup-GPO -Name $_.DisplayName -Path $gpoBackupPath }
        }
        
        # Export DNS Zones (if AD-integrated)
        Write-Log "Exporting DNS information..."
        if (Get-Module -ListAvailable -Name DnsServer) {
            Import-Module DnsServer
            Get-DnsServerZone | Export-Clixml "$exportPath\DNSZones.xml"
        }
        
        # Export Domain and Forest information
        Write-Log "Exporting Domain and Forest information..."
        Get-ADDomain | Export-Clixml "$exportPath\Domain.xml"
        Get-ADForest | Export-Clixml "$exportPath\Forest.xml"
        
        Write-Log "AD objects export completed successfully"
        return $exportPath
        
    } catch {
        Write-Log "AD objects export failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# Create LDIF export
function Export-LDIF {
    Write-Log "Starting LDIF export..."
    
    $dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $ldifFile = "$BackupPath\Exports\AD_Export_$dateStamp.ldif"
    
    try {
        $domain = (Get-ADDomain).DistinguishedName
        $ldifdsPath = "$env:SystemRoot\System32\ldifde.exe"
        
        if (Test-Path $ldifdsPath) {
            $arguments = @(
                "-f", "`"$ldifFile`"",
                "-d", "`"$domain`"",
                "-p", "subtree",
                "-r", "(objectClass=*)"
            )
            
            $result = Start-Process -FilePath $ldifdsPath -ArgumentList $arguments -Wait -PassThru -NoNewWindow
            
            if ($result.ExitCode -eq 0) {
                Write-Log "LDIF export completed successfully"
                return $ldifFile
            } else {
                throw "ldifde exit code: $($result.ExitCode)"
            }
        } else {
            Write-Log "ldifde.exe not found" "WARNING"
            return $null
        }
    } catch {
        Write-Log "LDIF export failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# Compress backups
function Compress-Backups {
    param([array]$BackupPaths)
    
    Write-Log "Starting backup compression..."
    
    $dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $archiveName = "$BackupPath\AD_Complete_Backup_$dateStamp.zip"
    
    try {
        $validPaths = $BackupPaths | Where-Object { $_ -and (Test-Path $_) }
        
        if ($validPaths.Count -gt 0) {
            Compress-Archive -Path $validPaths -DestinationPath $archiveName -CompressionLevel Optimal
            Write-Log "Backup compression completed: $archiveName"
            return $archiveName
        } else {
            Write-Log "No valid backup paths to compress" "WARNING"
            return $null
        }
    } catch {
        Write-Log "Backup compression failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# Cleanup old backups
function Remove-OldBackups {
    Write-Log "Cleaning up old backups (older than $RetentionDays days)..."
    
    try {
        $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
        
        # Clean up directories
        Get-ChildItem -Path "$BackupPath\SystemState", "$BackupPath\SYSVOL", "$BackupPath\Exports" -Directory | 
        Where-Object { $_.CreationTime -lt $cutoffDate } | 
        ForEach-Object {
            Remove-Item $_.FullName -Recurse -Force
            Write-Log "Removed old backup: $($_.Name)"
        }
        
        # Clean up archive files
        Get-ChildItem -Path $BackupPath -Filter "*.zip" | 
        Where-Object { $_.CreationTime -lt $cutoffDate } | 
        ForEach-Object {
            Remove-Item $_.FullName -Force
            Write-Log "Removed old archive: $($_.Name)"
        }
        
        # Clean up old logs
        Get-ChildItem -Path $LogPath -Filter "*.log" | 
        Where-Object { $_.CreationTime -lt $cutoffDate } | 
        ForEach-Object {
            Remove-Item $_.FullName -Force
            Write-Log "Removed old log: $($_.Name)"
        }
        
    } catch {
        Write-Log "Cleanup failed: $($_.Exception.Message)" "ERROR"
    }
}

# Generate backup report
function Generate-BackupReport {
    param([hashtable]$BackupResults)
    
    $dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = "$BackupPath\Backup_Report_$dateStamp.txt"
    
    $report = @"
Active Directory Backup Report
Generated: $(Get-Date)
Server: $env:COMPUTERNAME
Domain: $((Get-ADDomain).DNSRoot)

Backup Results:
===============
System State: $(if($BackupResults.SystemState) {"SUCCESS - $($BackupResults.SystemState)"} else {"FAILED"})
SYSVOL: $(if($BackupResults.SYSVOL) {"SUCCESS - $($BackupResults.SYSVOL)"} else {"FAILED"})
AD Exports: $(if($BackupResults.Exports) {"SUCCESS - $($BackupResults.Exports)"} else {"FAILED"})
LDIF Export: $(if($BackupResults.LDIF) {"SUCCESS - $($BackupResults.LDIF)"} else {"FAILED"})
Compressed Archive: $(if($BackupResults.Archive) {"SUCCESS - $($BackupResults.Archive)"} else {"FAILED"})

File Extensions Generated:
=========================
.vhd/.vhdx - System State backup virtual hard disks
.xml - Windows Backup catalog files
.csv - Comma-separated values (human readable)
.xml - PowerShell XML exports (preserves object structure)
.ldif - LDAP Data Interchange Format
.pol - Group Policy files
.zip - Compressed archive of all backups
.log - Backup operation logs
.txt - This report file

Next Steps:
==========
1. Verify backup integrity
2. Test restoration procedures
3. Store backups securely offsite
4. Document recovery procedures
"@

    $report | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Log "Backup report generated: $reportPath"
    return $reportPath
}

# Main execution
function Start-ADBackup {
    Write-Log "
  _________      .__                      _____         .__                              .___
 /   _____/____  |  |__   ___________    /     \   ____ |  |__ _____    _____   ____   __| _/
 \_____  \\__  \ |  |  \_/ __ \_  __ \  /  \ /  \ /  _ \|  |  \\__  \  /     \_/ __ \ / __ | 
 /        \/ __ \|   Y  \  ___/|  | \/ /    Y    (  <_> )   Y  \/ __ \|  Y Y  \  ___// /_/ | 
/_______  (____  /___|  /\___  >__|    \____|__  /\____/|___|  (____  /__|_|  /\___  >____ | 
        \/     \/     \/     \/                \/            \/     \/      \/     \/     \/ 
    "
    Write-Log "=== Starting Active Directory Backup By Saher Mohamed ==="
    Write-Log "Backup Path: $BackupPath"
    Write-Log "Server: $env:COMPUTERNAME"
    Write-Log "Domain: $((Get-ADDomain).DNSRoot)"
    
    # Initialize environment
    Initialize-BackupEnvironment
    Install-RequiredFeatures
    
    # Perform backups
    $backupResults = @{
        SystemState = $null
        SYSVOL = $null
        Exports = $null
        LDIF = $null
        Archive = $null
    }
    
    # System State Backup
    $backupResults.SystemState = Backup-SystemState
    
    # SYSVOL Backup
    $backupResults.SYSVOL = Backup-SYSVOL
    
    # AD Objects Export
    if ($IncludeExports) {
        $backupResults.Exports = Export-ADObjects
        $backupResults.LDIF = Export-LDIF
    }
    
    # Compress backups
    if ($CompressBackup) {
        $pathsToCompress = @($backupResults.SystemState, $backupResults.SYSVOL, $backupResults.Exports)
        $backupResults.Archive = Compress-Backups -BackupPaths $pathsToCompress
    }
    
    # Generate report
    $reportPath = Generate-BackupReport -BackupResults $backupResults
    
    # Cleanup old backups
    Remove-OldBackups
    
    Write-Log "=== Active Directory Backup Completed ==="
    Write-Log "Report available at: $reportPath"
    
    return $backupResults
}

# Execute the backup
try {
    $results = Start-ADBackup
    
    # Display summary
    Write-Host "`n=== BACKUP SUMMARY ===" -ForegroundColor Green
    Write-Host "System State: $(if($results.SystemState) {'SUCCESS'} else {'FAILED'})" -ForegroundColor $(if($results.SystemState) {'Green'} else {'Red'})
    Write-Host "SYSVOL: $(if($results.SYSVOL) {'SUCCESS'} else {'FAILED'})" -ForegroundColor $(if($results.SYSVOL) {'Green'} else {'Red'})
    Write-Host "AD Exports: $(if($results.Exports) {'SUCCESS'} else {'FAILED'})" -ForegroundColor $(if($results.Exports) {'Green'} else {'Red'})
    Write-Host "LDIF Export: $(if($results.LDIF) {'SUCCESS'} else {'FAILED'})" -ForegroundColor $(if($results.LDIF) {'Green'} else {'Red'})
    Write-Host "Archive: $(if($results.Archive) {'SUCCESS'} else {'FAILED'})" -ForegroundColor $(if($results.Archive) {'Green'} else {'Red'})
    
} catch {
    Write-Log "Script execution failed: $($_.Exception.Message)" "ERROR"
    Write-Host "Backup failed. Check logs for details." -ForegroundColor Red
}
