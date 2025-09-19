# Active Directory Backup Tool For Organizations

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Windows Server](https://img.shields.io/badge/Windows%20Server-2016%2B-orange.svg)](https://www.microsoft.com/en-us/windows-server)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A comprehensive PowerShell tool for automating Active Directory backups with multiple recovery options. This tool creates complete, restorable backups of your Active Directory environment including system state, SYSVOL, AD objects, and Group Policies, and it's completely free!

## 🚀 Features

### Complete Backup Coverage
- **System State Backup** - Full AD database (NTDS.DIT), registry, and boot files
- **SYSVOL Backup** - Group Policy Objects and login scripts  
- **AD Objects Export** - Users, groups, computers, OUs in multiple formats
- **LDIF Export** - Standard directory format for cross-platform compatibility
- **Group Policy Backup** - Complete GPO backups with restore capability
- **DNS Zones** - AD-integrated DNS zone exports
- **Automated Compression** - ZIP archives for efficient storage
- **Intelligent Cleanup** - Automatic removal of old backups based on retention policy

### Enterprise Features
- **Comprehensive Logging** - Detailed operation logs with timestamps
- **Backup Reports** - Generated reports with backup status and file locations
- **Error Handling** - Robust error handling with detailed logging
- **Parameterized Configuration** - Customizable paths, retention, and options
- **Multiple Export Formats** - CSV, XML, and LDIF for different use cases
- **Automated Scheduling** - Compatible with Task Scheduler for automated runs

## 📋 Prerequisites

### System Requirements
- **Operating System**: Windows Server 2016 or later
- **PowerShell**: Version 5.1 or higher
- **Privileges**: Must run as Administrator on a Domain Controller
- **Storage**: Sufficient disk space for backups (typically 2-5x AD database size)

### Required Windows Features
The script automatically installs these features if missing:
- Windows Server Backup
- Remote Server Administration Tools (RSAT) - AD PowerShell

### Required Modules
- ActiveDirectory (automatically loaded)
- GroupPolicy (if available)
- DnsServer (if DNS role is installed)

## 🛠️ Installation

### Option 1: Direct Download
```powershell
# Download the script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SaherMuhamed/active-directory-backup-tool/main/AD-Backup-Script.ps1" -OutFile "AD-Backup-Script.ps1"

# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

### Option 2: Git Clone
```bash
git clone https://github.com/SaherMuhamed/active-directory-backup-tool.git
cd ad-backup-tool
```

## 🎯 Quick Start

### Basic Usage
```powershell
# Run with default settings (requires Administrator privileges)
.\AD-Backup-Script.ps1
```

### Custom Configuration
```powershell
# Specify custom backup path and retention
.\AD-Backup-Script.ps1 -BackupPath "E:\AD_Backups" -RetentionDays 60

# Disable compression and exports for faster system state only backup
.\AD-Backup-Script.ps1 -CompressBackup:$false -IncludeExports:$false
```

## 🔧 Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `BackupPath` | String | `D:\AD_Backups` | Root directory for all backups |
| `LogPath` | String | `D:\AD_Backups\Logs` | Directory for log files |
| `RetentionDays` | Integer | `30` | Days to keep old backups |
| `IncludeExports` | Switch | `$true` | Include AD object exports |
| `CompressBackup` | Switch | `$true` | Create compressed archives |

### Example Configurations

#### Production Environment
```powershell
.\AD-Backup-Script.ps1 -BackupPath "\\BackupServer\AD_Backups" -RetentionDays 90 -CompressBackup
```

#### Quick System State Backup
```powershell
.\AD-Backup-Script.ps1 -IncludeExports:$false -CompressBackup:$false
```

#### Development Environment
```powershell
.\AD-Backup-Script.ps1 -BackupPath "C:\Temp\AD_Backup" -RetentionDays 7
```

## 📁 Output Structure

The script creates the following directory structure:

```
BackupPath/
├── SystemState/
│   └── SystemState_YYYYMMDD_HHMMSS/
│       ├── *.vhd(x)           # Virtual hard disk files
│       └── *.xml              # Backup catalog files
├── SYSVOL/
│   └── SYSVOL_YYYYMMDD_HHMMSS/
│       └── [SYSVOL Contents]   # Group policies and scripts
├── Exports/
│   └── AD_Export_YYYYMMDD_HHMMSS/
│       ├── Users.xml/.csv      # User accounts
│       ├── Groups.xml/.csv     # Security groups
│       ├── OUs.xml/.csv        # Organizational units
│       ├── Computers.xml/.csv  # Computer accounts
│       ├── GPOs.xml            # Group policy objects
│       ├── GPO_Backups/        # Individual GPO backups
│       ├── Domain.xml          # Domain information
│       ├── Forest.xml          # Forest information
│       └── DNSZones.xml        # DNS zone data
├── Logs/
│   ├── AD_Backup_YYYYMMDD.log  # Daily operation logs
│   └── SYSVOL_YYYYMMDD.log     # SYSVOL copy logs
├── AD_Complete_Backup_YYYYMMDD_HHMMSS.zip  # Compressed archive
└── Backup_Report_YYYYMMDD_HHMMSS.txt       # Backup report
```

## File Extensions Explained

| Extension | Content Type | Usage |
|-----------|--------------|--------|
| `.vhd/.vhdx` | System state virtual disks | Primary restoration files |
| `.xml` (Catalog) | Windows backup metadata | Backup catalog information |
| `.xml` (PowerShell) | Serialized AD objects | Complete object restoration |
| `.csv` | Comma-separated values | Human-readable reports |
| `.ldif` | LDAP Data Interchange Format | Cross-platform imports |
| `.pol` | Group Policy files | Policy configurations |
| `.zip` | Compressed archives | Storage and transport |
| `.log` | Operation logs | Troubleshooting and audit |
| `.txt` | Backup reports | Summary and documentation |

## Restoration Guide

### Complete Disaster Recovery

For complete AD forest recovery:

```powershell
# 1. Boot target server from Windows installation media
# 2. Choose "Repair your computer" > "Troubleshoot" > "Command Prompt"
# 3. Restore system state:
wbadmin start systemstaterecovery -version:MM/DD/YYYY-HH:MM -backupTarget:E:\AD_Backups\SystemState\

# 4. Restart in Directory Services Restore Mode
bcdedit /set safeboot dsrepair
shutdown /r /t 0

# 5. After restoration completes, return to normal boot
bcdedit /deletevalue safeboot
```

### New Domain Controller Setup

Create new forest and import backed up objects:

```powershell
# 1. Create new forest
Install-ADDSForest -DomainName "yourdomain.com" -SafeModeAdministratorPassword (ConvertTo-SecureString "Password!" -AsPlainText -Force)

# 2. Import AD objects from backup
$exportPath = "E:\AD_Backups\Exports\AD_Export_20241215_103000"

# Import users
$users = Import-Clixml "$exportPath\Users.xml"
foreach ($user in $users) {
    New-ADUser -Name $user.Name -SamAccountName $user.SamAccountName -UserPrincipalName $user.UserPrincipalName
}

# 3. Restore Group Policies
Import-GPO -BackupId (Get-ChildItem "$exportPath\GPO_Backups")[0].Name -Path "$exportPath\GPO_Backups" -TargetName "Default Domain Policy"
```

### Granular Object Recovery

Restore individual objects:

```powershell
# Restore specific user
$backupUsers = Import-Clixml "E:\AD_Backups\Exports\AD_Export_YYYYMMDD_HHMMSS\Users.xml"
$user = $backupUsers | Where-Object {$_.SamAccountName -eq "john.doe"}
New-ADUser -Name $user.Name -SamAccountName $user.SamAccountName # ... additional properties
```

## ⚡ Automation & Scheduling

### Task Scheduler Setup

Create scheduled task for daily backups:

```powershell
# Create scheduled task
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\AD-Backup-Script.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 2AM
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "AD Daily Backup" -Action $action -Trigger $trigger -Settings $settings -Principal $principal
```

### PowerShell Job

Run as background job:

```powershell
# Start backup as background job
Start-Job -ScriptBlock {
    & "C:\Scripts\AD-Backup-Script.ps1" -BackupPath "E:\AD_Backups" -RetentionDays 30
} -Name "AD-Backup"

# Monitor job progress
Get-Job -Name "AD-Backup" | Receive-Job -Keep
```

## 📊 Monitoring & Validation

### Backup Validation Script

```powershell
function Test-ADBackup {
    param([string]$BackupPath = "D:\AD_Backups")
    
    # Check latest system state backup
    $latestSystemState = Get-ChildItem "$BackupPath\SystemState" | Sort-Object CreationTime -Descending | Select-Object -First 1
    if ($latestSystemState -and (Test-Path $latestSystemState.FullName)) {
        Write-Host "✅ System State backup found: $($latestSystemState.Name)" -ForegroundColor Green
    } else {
        Write-Host "❌ No system state backup found" -ForegroundColor Red
    }
    
    # Check exports
    $latestExport = Get-ChildItem "$BackupPath\Exports" | Sort-Object CreationTime -Descending | Select-Object -First 1
    if ($latestExport -and (Test-Path "$($latestExport.FullName)\Users.xml")) {
        Write-Host "✅ AD exports found: $($latestExport.Name)" -ForegroundColor Green
    } else {
        Write-Host "❌ No AD exports found" -ForegroundColor Red
    }
}
```

### Log Analysis

Monitor backup operations:

```powershell
# View latest backup log
Get-Content "D:\AD_Backups\Logs\AD_Backup_$(Get-Date -Format 'yyyyMMdd').log" -Tail 20

# Search for errors
Get-ChildItem "D:\AD_Backups\Logs\*.log" | ForEach-Object {
    Select-String -Path $_.FullName -Pattern "ERROR" | Select-Object Line, Filename
}
```

## 🛡️ Security Considerations

### Backup Security
- **Encryption**: Store backups on encrypted drives
- **Access Control**: Limit access to backup files using NTFS permissions
- **Network Transfer**: Use encrypted connections for network backup locations
- **DSRM Password**: Ensure Directory Services Restore Mode password is documented securely

### Permissions Required
```powershell
# Minimum required permissions:
# - Local Administrator on Domain Controller
# - Domain Admin (for complete backup)
# - Backup Operator (for system state backup)
```

## 🐛 Troubleshooting

### Common Issues

#### Script Execution Policy Error
```powershell
# Solution: Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

#### Insufficient Disk Space
```powershell
# Check available space
Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | 
Select-Object DeviceID, @{Name="Size(GB)";Expression={[math]::Round($_.Size/1GB,2)}}, 
@{Name="FreeSpace(GB)";Expression={[math]::Round($_.FreeSpace/1GB,2)}}
```

#### System State Backup Fails
```cmd
# Check Windows Backup service
sc query VSS
sc query swprv

# Restart services if needed
net stop VSS && net start VSS
```

#### AD Module Not Available
```powershell
# Install RSAT tools
Install-WindowsFeature RSAT-AD-PowerShell -IncludeManagementTools
```

### Log Analysis Commands

```powershell
# Find backup failures
Select-String -Path "D:\AD_Backups\Logs\*.log" -Pattern "FAILED|ERROR" | 
Select-Object LineNumber, Line, Filename

# Check backup completion times
Select-String -Path "D:\AD_Backups\Logs\*.log" -Pattern "Backup Completed" | 
Select-Object Line, Filename
```

## Performance Considerations

### Backup Size Estimates
- **Small Domain** (<1000 objects): 500MB - 2GB
- **Medium Domain** (1000-10000 objects): 2GB - 10GB  
- **Large Domain** (>10000 objects): 10GB - 50GB+

### Optimization Tips
1. **Exclude unnecessary data** using `-IncludeExports:$false` for system state only
2. **Use local storage** for better performance during backup creation
3. **Schedule during off-hours** to minimize impact
4. **Monitor disk I/O** during backup operations
5. **Use compression** for storage efficiency vs. speed trade-off

### Network Backup Considerations
```powershell
# For network backup locations, consider:
$networkPath = "\\BackupServer\AD_Backups$"

# Test network connectivity first
Test-NetConnection -ComputerName "BackupServer" -Port 445

# Use robocopy for reliable network transfers
robocopy "D:\LocalBackup" $networkPath /E /COPYALL /R:3 /W:10
```

### Development Setup
```bash
git clone https://github.com/SaherMuhamed/active-directory-backup-tool.git
cd ad-backup-tool

# Create feature branch
git checkout -b feature/your-feature-name

# Make changes and test
# Submit pull request
```

### Testing
Before submitting changes:
1. Test on Windows Server 2016/2019/2022
2. Verify in lab environment
3. Check PowerShell 5.1 compatibility
4. Update documentation

## 📝 Changelog

### Version 1.0.0 (2024-12-15)
- Initial release
- Complete system state backup
- SYSVOL backup functionality
- AD object exports (CSV/XML/LDIF)
- Group Policy backup
- Automated compression
- Comprehensive logging
- Backup validation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided as-is without warranty. Always test backup and restoration procedures in a lab environment before using in production. I'm not responsible for any data loss or system damage.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/SaherMuhamed/active-directory-backup-tool/issues)
- **Documentation**: [Wiki](https://github.com/SaherMuhamed/active-directory-backup-tool/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/SaherMuhamed/active-directory-backup-tool/discussions)

## Acknowledgments

- Microsoft Active Directory team for comprehensive backup APIs
- PowerShell community for scripting best practices

---

## 🔗 Related Projects

- [AD-Restore-Tool](https://github.com/yourusername/ad-restore-tool) - Companion restoration utility
- [Group-Policy-Backup](https://github.com/yourusername/gpo-backup-tool) - Specialized GPO backup tool
- [AD-Health-Check](https://github.com/yourusername/ad-health-check) - Active Directory health monitoring

---

**Made By Saher Mohamed for the IT Community**

If this tool helps you, please consider giving it a ⭐ star on GitHub!
